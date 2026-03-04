//===------------------------------------------------------------*- C++ -*-===//
//
//                     由F8LEFT创建于2021/1/5。
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//
// 文件功能：实现ObElfReader扩展逻辑，处理转储SO程序头修复和原始SO动态段补齐。
// 核心策略：优先使用转储SO自身动态段；缺失时再从原始SO提取并回填。
#include "ob_elf_reader.h"

#include <vector>
#include <algorithm>
#include <cstring>
#include <new>

// 修正内存转储场景下可能失真的程序头信息。
void ObElfReader::FixDumpSoPhdr() {
    // 部分壳会丢失可加载段之间的数据，按内存镜像方式重算段大小。
    if (dump_so_base_ != 0) {
        std::vector<Elf_Phdr*> loaded_phdrs;
        // 收集全部可加载段。
        for (auto i = 0; i < phdr_num_; i++) {
            auto phdr = &phdr_table_[i];
            if(phdr->p_type != PT_LOAD) continue;
            loaded_phdrs.push_back(phdr);
        }
        // 按虚拟地址排序，便于推导每段大小。
        std::sort(loaded_phdrs.begin(), loaded_phdrs.end(),
                  [](Elf_Phdr * first, Elf_Phdr * second) {
                      return first->p_vaddr < second->p_vaddr;
                  });
        if (!loaded_phdrs.empty()) {
            // 通过“到下一段起始地址”的方式重算p_memsz/p_filesz。
            for (unsigned long i = 0, total = loaded_phdrs.size(); i < total; i++) {
                auto phdr = loaded_phdrs[i];
                if (i != total - 1) {
                    // 以“下一可加载段起点”作为当前段结尾。
                    auto nphdr = loaded_phdrs[i+1];
                    if (nphdr->p_vaddr > phdr->p_vaddr) {
                        phdr->p_memsz = nphdr->p_vaddr - phdr->p_vaddr;
                    } else {
                        phdr->p_memsz = 0;
                    }
                } else {
                    // 最后一段以文件末尾作为结尾。
                    if (file_size > phdr->p_vaddr) {
                        phdr->p_memsz = file_size - phdr->p_vaddr;
                    } else {
                        phdr->p_memsz = 0;
                    }
                }
                phdr->p_filesz = phdr->p_memsz;
            }
        }
    }

    auto phdr = phdr_table_;
    for(auto i = 0; i < phdr_num_; i++) {
        // 输出文件按内存镜像布局，偏移与虚拟地址保持一致。
        phdr->p_paddr = phdr->p_vaddr;
        phdr->p_filesz = phdr->p_memsz;     // 扩展文件大小与内存大小一致。
        phdr->p_offset = phdr->p_vaddr;     // 已按内存镜像加载，文件偏移直接对齐虚拟地址。
//            phdr->p_flags = 0                 // 后续可按段类型补齐默认权限
        phdr++;
    }
}

// 转储SO加载主流程：必要时从原始SO补动态段。
bool ObElfReader::Load() {
    // 按基础读取流程读取ELF头和程序头。
    if (!read_elf_header() || !verify_elf_header() || !read_program_header())
        return false;
    FixDumpSoPhdr();

    bool has_base_dynamic_info = false;
    // 需要额外预留给回填动态段的空间大小。
    uint32_t base_dynamic_size = 0;
    if (!haveDynamicSectionInLoadableSegment()) {
        // 尝试从原始SO读取可用动态段。
        // 后续可完善：动态段重建仍有边界场景待处理。
        LoadDynamicSectionFromBaseSource();
        has_base_dynamic_info = dynamic_sections_ != nullptr;
        if (has_base_dynamic_info) {
            base_dynamic_size = dynamic_count_ * sizeof(Elf_Dyn);
        }
    } else {
        FLOGI("动态段已位于可加载段内，将忽略baseso参数。");
    }

    if (!reserve_address_space(base_dynamic_size) ||
        !load_segments() ||
        !find_phdr()) {
        return false;
    }
    if (has_base_dynamic_info) {
        // 把动态段附加到load区尾部并修正动态段程序头。
        ApplyDynamicSection();
    }

    apply_phdr_table();

    return true;
}

//void ObElfReader::GetDynamicSection(Elf_Dyn **dynamic, size_t *dynamic_count, Elf_Word *dynamic_flags) {
//    if (dynamic_sections_ == nullptr) {
//        ElfReader::GetDynamicSection(dynamic, dynamic_count, dynamic_flags);
//        return;
//    }
//    *dynamic = reinterpret_cast<Elf_Dyn*>(dynamic_sections_);
//    if (dynamic_count) {
//        *dynamic_count = dynamic_count_;
//    }
//    if (dynamic_flags) {
//        *dynamic_flags = dynamic_flags_;
//    }
//    return;
//}

// 析构函数：释放从原始SO复制的动态段缓冲。
ObElfReader::~ObElfReader() = default;

// 从原始SO读取动态段，供转储SO缺失动态段时回填。
bool ObElfReader::LoadDynamicSectionFromBaseSource() {
    dynamic_sections_holder_.reset();
    dynamic_sections_ = nullptr;
    dynamic_count_ = 0;
    dynamic_flags_ = 0;

    if (base_so_name_.empty()) {
        return false;
    }
    ElfReader base_reader;

    // 已提供原始SO时，从中读取动态段。
    if (!base_reader.set_source(base_so_name_) ||
        !base_reader.read_elf_header() ||
        !base_reader.verify_elf_header() ||
        !base_reader.read_program_header()) {
        FLOGE("无法解析原始SO文件，请检查路径或文件内容");
        return false;
    }
    const Elf_Phdr * phdr_table_ = base_reader.phdr_table_;
    const Elf_Phdr * phdr_limit = phdr_table_ + base_reader.phdr_num_;
    const Elf_Phdr * phdr;

    for (phdr = phdr_table_; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_DYNAMIC) {
            continue;
        }

        // 复制动态段原始字节到本地缓存。
        if (phdr->p_memsz == 0) {
            return false;
        }
        dynamic_sections_holder_ = std::unique_ptr<uint8_t[]>(new (std::nothrow) uint8_t[phdr->p_memsz]);
        if (dynamic_sections_holder_ == nullptr) {
            return false;
        }
        dynamic_sections_ = dynamic_sections_holder_.get();
        memset(dynamic_sections_, 0, phdr->p_memsz);
        size_t load_size = phdr->p_filesz;
        if (load_size > phdr->p_memsz) {
            load_size = phdr->p_memsz;
        }
        auto read_size = base_reader.source_->read(dynamic_sections_, load_size, phdr->p_offset);
        if (read_size != load_size) {
            dynamic_sections_holder_.reset();
            dynamic_sections_ = nullptr;
            return false;
        }

        dynamic_count_ = (unsigned)(phdr->p_memsz / sizeof(Elf_Dyn));
        dynamic_flags_ = phdr->p_flags;
        return true;
    }

    return false;
}

// 将补充的动态段写入当前镜像末尾并更新动态段程序头。
void ObElfReader::ApplyDynamicSection() {
    if (dynamic_sections_ == nullptr)
        return;
    uint8_t * wbuf_start = load_start_ + load_size_;
    uint32_t dynamic_size = dynamic_count_ * sizeof(Elf_Dyn);
    // 保护校验：仅当预留空间足够时才执行回填，避免越界写入。
    if (pad_size_ < dynamic_size)
        return;
    // 直接把动态段原始字节复制到补齐区。
    memcpy(wbuf_start, dynamic_sections_, dynamic_size);
    // 修正动态段程序头。
    for (auto p = phdr_table_, pend = phdr_table_+ phdr_num_; p < pend; p++) {
        if (p->p_type == PT_DYNAMIC) {
            p->p_vaddr = wbuf_start - load_bias_;
            p->p_paddr = p->p_vaddr;
            p->p_offset = p->p_vaddr;

            p->p_memsz = dynamic_size;
            p->p_filesz = p->p_memsz;
            break;
        }
    }
}

// 判断PT_DYNAMIC是否完全落在某个PT_LOAD段中。
bool ObElfReader::haveDynamicSectionInLoadableSegment() {
    const Elf_Phdr* phdr = phdr_table_;
    const Elf_Phdr* phdr_limit = phdr + phdr_num_;

    for (phdr = phdr_table_; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_DYNAMIC) {
            continue;
        }
        Elf_Addr dyn_start = phdr->p_vaddr;
        Elf_Addr dyn_end = dyn_start + phdr->p_memsz;
        if (dyn_end < dyn_start) {
            break;
        }

        for (const Elf_Phdr* load = phdr_table_; load < phdr_limit; load++) {
            if (load->p_type != PT_LOAD) {
                continue;
            }
            Elf_Addr load_start = load->p_vaddr;
            Elf_Addr load_end = load_start + load->p_memsz;
            if (load_end < load_start) {
                continue;
            }
            if (dyn_start >= load_start && dyn_end <= load_end) {
                return true;
            }
        }
        break;
    }
    return false;
}
