//===------------------------------------------------------------*- C++ -*-===//
//
//                     由F8LEFT创建于2017/6/3。
//                   版权所有（c）2017。
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//
// 文件功能：实现ELF读取、段装载、动态段定位与程序头有效性校验。

#include "elf_reader.h"
#include "elf.h"
#include <stdio.h>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <fcntl.h>
#include <errno.h>
#include <vector>

/*
 * ELF加载技术说明：
 * 1）程序头中的PT_LOAD描述文件内容映射到进程地址空间的方式。
 * 2）每个可加载段至少包含：p_offset、p_filesz、p_memsz、p_vaddr、p_flags。
 * 3）通常要求p_filesz<=p_memsz，超出的内存部分按0填充。
 * 4）装载时并非直接把段放到p_vaddr，而是根据首段落点计算统一load_bias。
 * 5）后续虚拟地址转内存地址时统一使用：runtime_addr=load_bias+p_vaddr。
 * 6）页对齐计算依赖PAGE_START/PAGE_END/PAGE_OFFSET，保证段边界处理一致。
 */


// 将程序头权限位映射到平台保护位。
#define MAYBE_MAP_FLAG(x,from,to)    (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))
// 构造函数：仅初始化成员，实际加载在Load中完成。
ElfReader::ElfReader() = default;

// 析构函数：统一释放文件和内存资源。
ElfReader::~ElfReader() = default;

// 对外主入口：按顺序执行读取、校验、装载和程序头定位。
bool ElfReader::Load() {
    // 依次执行读取、校验、装载和程序头定位。
    return ReadElfHeader() &&
           VerifyElfHeader() &&
           ReadProgramHeader() &&
           // 后续可补充从节头读取动态段的路径（适配更高版本场景）。
           ReserveAddressSpace() &&
           LoadSegments() &&
           FindPhdr();
}

// 读取ELF头到header_缓存。
bool ElfReader::ReadElfHeader() {
    auto rc = source_->read(&header_, sizeof(header_));
    if (rc != sizeof(header_)) {
        FLOGE("\"%s\"文件过小，无法识别为ELF", name_);
        return false;
    }
    return true;
}

// 校验ELF基础合法性，避免后续解析在非法输入上继续执行。
bool ElfReader::VerifyElfHeader() {
    if (header_.e_ident[EI_MAG0] != ELFMAG0 ||
        header_.e_ident[EI_MAG1] != ELFMAG1 ||
        header_.e_ident[EI_MAG2] != ELFMAG2 ||
        header_.e_ident[EI_MAG3] != ELFMAG3) {
        FLOGE("\"%s\"的ELF魔数错误", name_);
        return false;
    }
#ifndef __SO64__
    if (header_.e_ident[EI_CLASS] != ELFCLASS32) {
        FLOGE("\"%s\"不是32位ELF：%d", name_, header_.e_ident[EI_CLASS]);
        return false;
    }
#else
    if (header_.e_ident[EI_CLASS] != ELFCLASS64) {
        FLOGE("\"%s\"不是64位ELF：%d", name_, header_.e_ident[EI_CLASS]);
        return false;
    }
#endif

    if (header_.e_ident[EI_DATA] != ELFDATA2LSB) {
        FLOGE("\"%s\"不是小端字节序：%d", name_, header_.e_ident[EI_DATA]);
        return false;
    }

//    if (header_.e_type != ET_DYN) {
//        FLOGE("\"%s\"的e_type异常：%d", name_, header_.e_type);
//        return false;
//    }

    if (header_.e_version != EV_CURRENT) {
        FLOGE("\"%s\"的e_version不受支持：%d", name_, header_.e_version);
        return false;
    }

    return true;
}

// 读取程序头表并保存到本地缓冲，后续逻辑都基于此缓冲。
bool ElfReader::ReadProgramHeader() {
    phdr_num_ = header_.e_phnum;

    // 与内核一致：程序头表最大限制为64KiB。
    if (phdr_num_ < 1 || phdr_num_ > 65536/sizeof(Elf_Phdr)) {
        FLOGE("\"%s\"的e_phnum无效：%zu", name_, phdr_num_);
        return false;
    }

    phdr_size_ = phdr_num_ * sizeof(Elf_Phdr);
    auto mmap_holder = std::unique_ptr<uint8_t[]>(new (std::nothrow) uint8_t[phdr_size_]);
    if (mmap_holder == nullptr) {
        FLOGE("\"%s\"程序头内存分配失败", name_);
        return false;
    }
    void* mmap_result = mmap_holder.get();
    auto rc = source_->read(mmap_result, phdr_size_, header_.e_phoff);
    if (rc != phdr_size_) {
        FLOGE("\"%s\"缺少有效程序头数据", name_);
        return false;
    }

    phdr_mmap_holder_ = std::move(mmap_holder);
    phdr_mmap_ = phdr_mmap_holder_.get();
    phdr_table_ = reinterpret_cast<Elf_Phdr*>(reinterpret_cast<char*>(mmap_result));

    return true;
}

/*
 * 计算所有可加载段覆盖的页对齐区间长度。
 * 返回值为需要预留的总字节数；若不存在可加载段则返回0。
 * 若out_min_vaddr/out_max_vaddr非空，会输出页对齐后的最小／最大地址。
 */
size_t phdr_table_get_load_size(const Elf_Phdr* phdr_table,
                                size_t phdr_count,
                                Elf_Addr* out_min_vaddr,
                                Elf_Addr* out_max_vaddr)
{
    // 计算所有PT_LOAD段的页对齐覆盖范围，返回总映射长度。
    // 安全加法：统一处理地址运算溢出。
    auto safe_add = [](Elf_Addr lhs, Elf_Addr rhs, Elf_Addr* out) -> bool {
        if (lhs > std::numeric_limits<Elf_Addr>::max() - rhs) {
            return false;
        }
        *out = lhs + rhs;
        return true;
    };
#ifdef __SO64__
    Elf_Addr min_vaddr = 0xFFFFFFFFFFFFFFFFU;
#else
    Elf_Addr min_vaddr = 0xFFFFFFFFU;
#endif
    Elf_Addr max_vaddr = 0x00000000U;

    bool found_pt_load = false;
    for (size_t i = 0; i < phdr_count; ++i) {
        const Elf_Phdr* phdr = &phdr_table[i];

        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        found_pt_load = true;
        if (phdr->p_filesz > phdr->p_memsz) {
            return 0;
        }

        if (phdr->p_vaddr < min_vaddr) {
            min_vaddr = phdr->p_vaddr;
        }

        Elf_Addr seg_end = 0;
        if (!safe_add(phdr->p_vaddr, phdr->p_memsz, &seg_end)) {
            return 0;
        }
        if (seg_end > max_vaddr) {
            max_vaddr = seg_end;
        }
    }
    if (!found_pt_load) {
        min_vaddr = 0x00000000U;
    }

    min_vaddr = PAGE_START(min_vaddr);
    if (!safe_add(max_vaddr, PAGE_SIZE - 1, &max_vaddr)) {
        return 0;
    }
    max_vaddr = PAGE_START(max_vaddr);
    if (max_vaddr < min_vaddr) {
        return 0;
    }

    if (out_min_vaddr != NULL) {
        *out_min_vaddr = min_vaddr;
    }
    if (out_max_vaddr != NULL) {
        *out_max_vaddr = max_vaddr;
    }
    return max_vaddr - min_vaddr;
}

// 预留一块连续缓冲用于承载所有加载段和可选padding。
bool ElfReader::ReserveAddressSpace(uint32_t padding_size) {
    Elf_Addr min_vaddr;
    load_size_ = phdr_table_get_load_size(phdr_table_, phdr_num_, &min_vaddr);
    if (load_size_ == 0) {
        FLOGE("\"%s\"不存在可加载段", name_);
        return false;
    }
    pad_size_ = padding_size;

    Elf_Addr alloc_size = load_size_;
    if (alloc_size > std::numeric_limits<Elf_Addr>::max() - pad_size_) {
        FLOGE("\"%s\"加载尺寸溢出", name_);
        return false;
    }
    alloc_size += pad_size_;
    if (alloc_size > static_cast<Elf_Addr>(std::numeric_limits<size_t>::max())) {
        FLOGE("\"%s\"加载尺寸过大", name_);
        return false;
    }

    uint8_t* addr = reinterpret_cast<uint8_t*>(min_vaddr);
    // 分配加载缓冲并整体清零。
    auto start_holder = std::unique_ptr<uint8_t[]>(new (std::nothrow) uint8_t[static_cast<size_t>(alloc_size)]);
    if (start_holder == nullptr) {
        FLOGE("\"%s\"预留内存失败", name_);
        return false;
    }
    memset(start_holder.get(), 0, static_cast<size_t>(alloc_size));

    load_start_holder_ = std::move(start_holder);
    load_start_ = load_start_holder_.get();
    // 将“页对齐后的最小虚拟地址”映射到加载起始地址，据此计算统一偏移基址。
    load_bias_ = reinterpret_cast<uint8_t *>(reinterpret_cast<uintptr_t >(load_start_)
                                             - reinterpret_cast<uintptr_t >(addr));
    return true;
}

// 将每个PT_LOAD段复制到预留缓冲对应偏移处。
bool ElfReader::LoadSegments() {
    // 后续可完善：当前按段独立拷贝，可再补齐段间文件空洞数据策略。
    for (size_t i = 0; i < phdr_num_; ++i) {
        const Elf_Phdr* phdr = &phdr_table_[i];

        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        // 计算段在虚拟地址空间中的范围。
        Elf_Addr seg_start = phdr->p_vaddr;
        Elf_Addr seg_end = seg_start + phdr->p_memsz;
        if (seg_end < seg_start) {
            FLOGE("\"%s\" invalid segment range at phdr %zu", name_, i);
            return false;
        }

//        Elf_Addr seg_page_start = PAGE_START(seg_start);
//        Elf_Addr seg_page_end   = PAGE_END(seg_end);

        Elf_Addr seg_file_end = seg_start + phdr->p_filesz;
        if (seg_file_end < seg_start) {
            FLOGE("\"%s\" invalid segment file range at phdr %zu", name_, i);
            return false;
        }
        if (phdr->p_filesz > phdr->p_memsz) {
            FLOGE("\"%s\" p_filesz > p_memsz at phdr %zu", name_, i);
            return false;
        }

        // 校验文件偏移区间，避免偏移回绕。
        Elf_Addr file_start = phdr->p_offset;
        Elf_Addr file_end = file_start + phdr->p_filesz;
        if (file_end < file_start) {
            FLOGE("\"%s\" invalid file range at phdr %zu", name_, i);
            return false;
        }

//        Elf_Addr file_page_start = PAGE_START(file_start);
        Elf_Addr file_length = file_end - file_start;


        if (file_length != 0) {
            // 按文件偏移把段内容读入加载缓冲。
            void* load_point = seg_start + reinterpret_cast<uint8_t *>(load_bias_);
            auto read_size = source_->read(load_point, file_length, file_start);
            if (read_size != file_length) {
                FLOGE("couldn't map \"%s\" segment %zu: %s", name_, i, strerror(errno));
                return false;
            }

        }

        // 若开启严格装载，可对可写段末页做零填充。
//        if ((phdr->p_flags & PF_W) != 0 && PAGE_OFFSET(seg_file_end) > 0) {
//            memset(seg_file_end + reinterpret_cast<uint8_t *>(load_bias_), 0, PAGE_SIZE - PAGE_OFFSET(seg_file_end));
//        }

//        seg_file_end = PAGE_END(seg_file_end);

        // 如果段内存长度大于文件长度，额外区域理论上需要补零。
        // 当前缓冲已预清零，因此这里可直接跳过。
//        if (seg_page_end > seg_file_end) {
//            void* load_point = (uint8_t*)load_bias_ + seg_file_end;
//            memset(load_point, 0, seg_page_end - seg_file_end);
//        }
    }
    return true;
}

/*
 * 内部函数：遍历可加载段并设置保护属性。
 * 目前保留遍历框架，未真正调用mprotect。
 */
static int
_phdr_table_set_load_prot(const Elf_Phdr* phdr_table,
                          int               phdr_count,
                          uint8_t *load_bias,
                          int               extra_prot_flags)
{
    // 当前项目不实际调用mprotect，此处保留接口和段遍历逻辑。
    const Elf_Phdr* phdr = phdr_table;
    const Elf_Phdr* phdr_limit = phdr + phdr_count;

    for (; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_LOAD || (phdr->p_flags & PF_W) != 0)
            continue;

        auto seg_page_start = PAGE_START(phdr->p_vaddr) + load_bias;
        auto seg_page_end   = PAGE_END(phdr->p_vaddr + phdr->p_memsz) + load_bias;

        auto ret = 0;

//        int ret = mprotect((void*)seg_page_start,
//                           seg_page_end - seg_page_start,
//                           PFLAGS_TO_PROT(phdr->p_flags) | extra_prot_flags);
//        if (ret < 0) {
//            return -1;
//        }
    }
    return 0;
}

/*
 * 对外接口：恢复可加载段原有保护属性。
 * 当前实现仅保留接口与遍历逻辑。
 */
int
phdr_table_protect_segments(const Elf_Phdr* phdr_table,
                            int               phdr_count,
                            uint8_t *load_bias)
{
    // 对外接口：恢复段保护（当前为保留实现）。
    // 当前实现等价于遍历检查，便于后续扩展真实保护逻辑。
    return _phdr_table_set_load_prot(phdr_table, phdr_count,
                                     load_bias, 0);
}

/*
 * 对外接口：临时放宽段保护属性，便于后续做重定位修补。
 * 当前实现仅保留框架，未实际调用mprotect。
 */
int
phdr_table_unprotect_segments(const Elf_Phdr* phdr_table,
                              int               phdr_count,
                              uint8_t *load_bias)
{
    // 对外接口：放宽段保护（当前为保留实现）。
    // 预留可写保护接口，当前未启用真实mprotect。
    return _phdr_table_set_load_prot(phdr_table, phdr_count,
                                     load_bias, /*PROT_WRITE*/0);
}

/* 内部函数：处理GNU RELRO段的保护逻辑。 */
static int
_phdr_table_set_gnu_relro_prot(const Elf_Phdr* phdr_table,
                               int               phdr_count,
                               uint8_t *load_bias,
                               int               prot_flags)
{
    // 当前只保留遍历框架，便于后续补齐RELRO真实保护。
    // 注意：PT_GNU_RELRO筛选与mprotect调用均处于关闭状态。
    const Elf_Phdr* phdr = phdr_table;
    const Elf_Phdr* phdr_limit = phdr + phdr_count;

    for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
//        if (phdr->p_type != PT_GNU_RELRO)
//            continue;

        /*
         * RELRO段若未严格按页边界对齐，保护粒度会扩展到整页。
         * 因此实际处理时通常以“段覆盖到的整页”作为最小保护单位。
         */
        auto seg_page_start = PAGE_START(phdr->p_vaddr) + load_bias;
        auto seg_page_end   = PAGE_END(phdr->p_vaddr + phdr->p_memsz) + load_bias;

        auto ret = 0;
//        int ret = mprotect((void*)seg_page_start,
//                           seg_page_end - seg_page_start,
//                           prot_flags);
//        if (ret < 0) {
//            return -1;
//        }
    }
    return 0;
}

/*
 * 对外接口：应用GNU RELRO保护。
 * 典型场景是把.got等重定位完成后的区域改为只读。
 */
int
phdr_table_protect_gnu_relro(const Elf_Phdr* phdr_table,
                             int               phdr_count,
                             uint8_t *load_bias)
{
    // 对外接口：处理GNU RELRO保护（当前为保留实现）。
    // 对外RELRO保护入口。
    return _phdr_table_set_gnu_relro_prot(phdr_table,
                                          phdr_count,
                                          load_bias,
            /*PROT_READ*/0);
}


#  ifndef PT_ARM_EXIDX
#    define PT_ARM_EXIDX    0x70000001      /* .ARM.exidx段 */
#  endif

/*
 * 返回.ARM.exidx在内存中的地址和条目数量。
 * 找到则返回0，未找到返回-1。
 */
int
phdr_table_get_arm_exidx(const Elf_Phdr* phdr_table,
                         int               phdr_count,
                         uint8_t * load_bias,
                         Elf_Addr**      arm_exidx,
                         unsigned*         arm_exidx_count)
{
    // 对外接口：返回ARM异常回溯段地址及条目数量。
    // 从程序头中查找ARM异常回溯表。
    const Elf_Phdr* phdr = phdr_table;
    const Elf_Phdr* phdr_limit = phdr + phdr_count;

    for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_ARM_EXIDX)
            continue;

        *arm_exidx = (Elf_Addr*)((uint8_t *)load_bias + phdr->p_vaddr);
        *arm_exidx_count = (unsigned)(phdr->p_memsz / sizeof(Elf_Addr));
        return 0;
    }
    *arm_exidx = NULL;
    *arm_exidx_count = 0;
    return -1;
}

/*
 * 从程序头中提取.dynamic段地址、项数和权限标记。
 * 若未找到有效动态段，则dynamic输出为NULL。
 */
void
phdr_table_get_dynamic_section(const Elf_Phdr* phdr_table,
                               int               phdr_count,
                               uint8_t *load_bias,
                               Elf_Dyn**       dynamic,
                               size_t*           dynamic_count,
                               Elf_Word*       dynamic_flags)
{
    // 对外接口：从程序头中提取动态段信息。
    // 动态段必须完全落在某个PT_LOAD范围内。
    auto range_in_load = [phdr_table, phdr_count](Elf_Addr start, Elf_Addr size) -> bool {
        if (size == 0) {
            return false;
        }
        Elf_Addr end = start + size;
        if (end < start) {
            return false;
        }
        for (int i = 0; i < phdr_count; ++i) {
            const Elf_Phdr* load = &phdr_table[i];
            if (load->p_type != PT_LOAD) {
                continue;
            }
            Elf_Addr load_end = load->p_vaddr + load->p_memsz;
            if (load_end < load->p_vaddr) {
                continue;
            }
            if (start >= load->p_vaddr && end <= load_end) {
                return true;
            }
        }
        return false;
    };
    const Elf_Phdr* phdr = phdr_table;
    const Elf_Phdr* phdr_limit = phdr + phdr_count;

    for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_DYNAMIC) {
            continue;
        }

        Elf_Addr dyn_size = phdr->p_memsz;
        if (phdr->p_filesz != 0 && phdr->p_filesz < dyn_size) {
            dyn_size = phdr->p_filesz;
        }
        if (dyn_size < sizeof(Elf_Dyn) ||
            !range_in_load(phdr->p_vaddr, dyn_size)) {
            continue;
        }
        *dynamic = reinterpret_cast<Elf_Dyn*>(load_bias + phdr->p_vaddr);
        if (dynamic_count) {
            *dynamic_count = static_cast<size_t>(dyn_size / sizeof(Elf_Dyn));
        }
        if (dynamic_flags) {
            *dynamic_flags = phdr->p_flags;
        }
        return;
    }
    *dynamic = NULL;
    if (dynamic_count) {
        *dynamic_count = 0;
    }
}

// 在已加载镜像中定位程序头表入口，优先PT_PHDR，兜底首个PT_LOAD＋e_phoff。
bool ElfReader::FindPhdr() {
    const Elf_Phdr* phdr_limit = phdr_table_ + phdr_num_;

    // 优先使用PT_PHDR直接定位。
    for (const Elf_Phdr* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_PHDR) {
            return CheckPhdr((uint8_t*)load_bias_ + phdr->p_vaddr);
        }
    }

    // 若无PT_PHDR，则尝试从首个偏移为0的PT_LOAD反推出程序头地址。
    for (const Elf_Phdr* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_LOAD) {
            if (phdr->p_offset == 0) {
                // 常见场景：首个可加载段偏移为0，可直接通过e_phoff定位程序头。
                uint8_t *elf_addr = (uint8_t*)load_bias_ + phdr->p_vaddr;
                const Elf_Ehdr* ehdr = (const Elf_Ehdr*)(void*)elf_addr;
                Elf_Addr  offset = ehdr->e_phoff;
                return CheckPhdr((uint8_t*)ehdr + offset);
            }
            break;
        }
    }

    FLOGE("无法在\"%s\"中定位已加载程序头", name_);
    return false;
}

// 校验程序头表指针范围是否落在可加载段内，避免后续越界访问。
bool ElfReader::CheckPhdr(uint8_t * loaded) {
    const Elf_Phdr* phdr_limit = phdr_table_ + phdr_num_;
    auto loaded_end = loaded + (phdr_num_ * sizeof(Elf_Phdr));
    // 保证loaded指针覆盖区间完全落在某个可加载段内。
    for (Elf_Phdr* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        auto seg_start = phdr->p_vaddr + (uint8_t*)load_bias_;
        auto seg_size = phdr->p_memsz;
        if (phdr->p_filesz > seg_size) {
            seg_size = phdr->p_filesz;
        }
        auto seg_end = seg_size + seg_start;
        if (seg_start <= loaded && loaded_end <= seg_end) {
            loaded_phdr_ = reinterpret_cast<const Elf_Phdr*>(loaded);
            return true;
        }
    }
    FLOGE("\"%s\"的已加载程序头%p不在可加载段内", name_, loaded);
    return false;
}

// 将临时程序头表同步回已加载镜像中的程序头区域。
void ElfReader::ApplyPhdrTable() {
    // 把修正后的程序头表写回已加载镜像，保证后续重建读取到的是修正值。
    const Elf_Phdr* phdr_limit = phdr_table_ + phdr_num_;
    memcpy((void*)loaded_phdr_, (void*)phdr_table_, (uintptr_t)phdr_limit - (uintptr_t)phdr_table_ );
    return ;
}


// 绑定输入文件路径并初始化底层文件读取器。
bool ElfReader::setSource(const char *source) {
    return set_source(source == nullptr ? std::string_view() : std::string_view(source));
}

bool ElfReader::set_source(std::string_view source) {
    // 打开输入文件并缓存大小。
    if (source.empty()) {
        return false;
    }
    name_storage_ = source;
    name_ = name_storage_.c_str();
    auto fr = std::make_unique<FileReader>(source);
    if (!fr->open()) {
        return false;
    }
    file_size = static_cast<size_t>(fr->file_size());
    source_holder_ = std::move(fr);
    source_ = source_holder_.get();
    return true;
}

// 读取当前实例中的动态段信息，供重建阶段提取DT_*元数据。
void ElfReader::GetDynamicSection(Elf_Dyn **dynamic, size_t *dynamic_count, Elf_Word *dynamic_flags) {
    // 与全局版本同逻辑，读取当前实例中的动态段。
    auto range_in_load = [this](Elf_Addr start, Elf_Addr size) -> bool {
        if (size == 0) {
            return false;
        }
        Elf_Addr end = start + size;
        if (end < start) {
            return false;
        }
        const Elf_Phdr* load = phdr_table_;
        const Elf_Phdr* limit = phdr_table_ + phdr_num_;
        for (; load < limit; ++load) {
            if (load->p_type != PT_LOAD) {
                continue;
            }
            Elf_Addr load_end = load->p_vaddr + load->p_memsz;
            if (load_end < load->p_vaddr) {
                continue;
            }
            if (start >= load->p_vaddr && end <= load_end) {
                return true;
            }
        }
        return false;
    };
    const Elf_Phdr* phdr = phdr_table_;
    const Elf_Phdr* phdr_limit = phdr + phdr_num_;

    for (phdr = phdr_table_; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_DYNAMIC) {
            continue;
        }

        Elf_Addr dyn_size = phdr->p_memsz;
        if (phdr->p_filesz != 0 && phdr->p_filesz < dyn_size) {
            dyn_size = phdr->p_filesz;
        }
        if (dyn_size < sizeof(Elf_Dyn) ||
            !range_in_load(phdr->p_vaddr, dyn_size)) {
            continue;
        }
        *dynamic = reinterpret_cast<Elf_Dyn*>(load_bias_ + phdr->p_vaddr);
        if (dynamic_count) {
            *dynamic_count = static_cast<size_t>(dyn_size / sizeof(Elf_Dyn));
        }
        if (dynamic_flags) {
            *dynamic_flags = phdr->p_flags;
        }
        return;
    }
    *dynamic = NULL;
    if (dynamic_count) {
        *dynamic_count = 0;
    }
}
