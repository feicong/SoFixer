//===------------------------------------------------------------*- C++ -*-===//
//
//                     由F8LEFT创建于2017/6/3。
//                   版权所有（c）2017。
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//
// 文件功能：实现ELF读取、段装载、动态段定位与程序头有效性校验。

#include "elf_reader.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <vector>

#include "elf.h"

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
#define MAYBE_MAP_FLAG(x, from, to) (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)                                                          \
	(MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
	 MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))
// 构造函数：仅初始化成员，实际加载在Load中完成。
ElfReader::ElfReader() = default;

// 析构函数：统一释放文件和内存资源。
ElfReader::~ElfReader() = default;

// 对外主入口：按顺序执行读取、校验、装载和程序头定位。
bool ElfReader::Load() {
	// 前置条件：必须先通过set_source绑定输入文件。
	// 若source_为空直接进入读取流程，会在ReadElfHeader里解引用空指针并崩溃。
	// 这里先做统一兜底，保证异常路径可观测且可诊断。
	if (source_ == nullptr || !source_->is_open() || name_ == nullptr) {
		FLOGE("读取器未初始化：source=%p opened=%d name=%p", source_,
			  (source_ != nullptr && source_->is_open()) ? 1 : 0, name_);
		return false;
	}
	// 依次执行读取、校验、装载和程序头定位。
	return ReadElfHeader() && VerifyElfHeader() && ReadProgramHeader() &&
		   // 后续可补充从节头读取动态段的路径（适配更高版本场景）。
		   ReserveAddressSpace() && LoadSegments() && FindPhdr();
}

// 读取ELF头到header_缓存。
bool ElfReader::ReadElfHeader() {
	if (source_ == nullptr || !source_->is_open()) {
		FLOGE("读取ELF头失败：输入源未就绪，source=%p opened=%d", source_,
			  (source_ != nullptr && source_->is_open()) ? 1 : 0);
		return false;
	}
	auto rc = source_->read(&header_, sizeof(header_));
	if (rc != sizeof(header_)) {
		FLOGE("\"%s\"文件过小，无法识别为ELF", name_);
		return false;
	}
	return true;
}

// 校验ELF基础合法性，避免后续解析在非法输入上继续执行。
bool ElfReader::VerifyElfHeader() {
	if (header_.e_ident[EI_MAG0] != ELFMAG0 || header_.e_ident[EI_MAG1] != ELFMAG1 ||
		header_.e_ident[EI_MAG2] != ELFMAG2 || header_.e_ident[EI_MAG3] != ELFMAG3) {
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
	if (source_ == nullptr || !source_->is_open()) {
		FLOGE("读取程序头失败：输入源未就绪，source=%p opened=%d", source_,
			  (source_ != nullptr && source_->is_open()) ? 1 : 0);
		return false;
	}
	phdr_num_ = header_.e_phnum;
	// 程序头步长必须与当前构建使用的Elf_Phdr大小一致。
	// 若e_phentsize与sizeof(Elf_Phdr)不一致，说明输入ELF和当前解析口径不匹配：
	// 1）可能是位宽不匹配（32位文件被64位解析，或反之）；
	// 2）也可能是损坏输入导致步长字段异常。
	// 继续按sizeof(Elf_Phdr)线性读取会把每条程序头错位解释，后续所有段边界计算都会失真。
	if (header_.e_phentsize != static_cast<decltype(header_.e_phentsize)>(sizeof(Elf_Phdr))) {
		FLOGE("\"%s\"程序头步长异常：e_phentsize=%u expected=%zu", name_, static_cast<unsigned>(header_.e_phentsize),
			  sizeof(Elf_Phdr));
		return false;
	}

	// 与内核一致：程序头表最大限制为64KiB。
	if (phdr_num_ < 1 || phdr_num_ > 65536 / sizeof(Elf_Phdr)) {
		FLOGE("\"%s\"的e_phnum无效：%zu", name_, phdr_num_);
		return false;
	}
	// 这里不能把file_size窄化成Elf_Addr后再比较。
	// 在32位构建中，Elf_Addr只有32位；当输入文件大于4GB时，窄化会截断高位，
	// 导致“本应判越界”的e_phoff被误判为合法。
	// 因此统一提升到uint64_t口径比较，避免位宽相关的边界遗漏。
	const auto file_size_u64 = static_cast<uint64_t>(file_size);
	const auto e_phoff_u64 = static_cast<uint64_t>(header_.e_phoff);
	if (e_phoff_u64 > file_size_u64) {
		FLOGE("\"%s\"程序头偏移越界：e_phoff=0x%llx file_size=0x%llx", name_,
			  static_cast<unsigned long long>(header_.e_phoff), static_cast<unsigned long long>(file_size_u64));
		return false;
	}
	if (phdr_num_ > std::numeric_limits<uint64_t>::max() / static_cast<uint64_t>(header_.e_phentsize)) {
		FLOGE("\"%s\"程序头表大小溢出：phnum=%zu phentsize=%u", name_, phdr_num_,
			  static_cast<unsigned>(header_.e_phentsize));
		return false;
	}
	const auto phdr_bytes_in_file = static_cast<uint64_t>(phdr_num_) * static_cast<uint64_t>(header_.e_phentsize);
	if (e_phoff_u64 > std::numeric_limits<uint64_t>::max() - phdr_bytes_in_file ||
		e_phoff_u64 + phdr_bytes_in_file > file_size_u64) {
		FLOGE("\"%s\"程序头区间越界：e_phoff=0x%llx phdr_bytes=0x%llx file_size=0x%llx", name_,
			  static_cast<unsigned long long>(header_.e_phoff), static_cast<unsigned long long>(phdr_bytes_in_file),
			  static_cast<unsigned long long>(file_size_u64));
		return false;
	}

	const size_t phdr_size_bytes = phdr_num_ * sizeof(Elf_Phdr);
	if (phdr_size_bytes > static_cast<size_t>(std::numeric_limits<Elf_Addr>::max())) {
		FLOGE("\"%s\"程序头总大小超出范围：size=%zu", name_, phdr_size_bytes);
		return false;
	}
	phdr_size_ = static_cast<Elf_Addr>(phdr_size_bytes);
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
 * 返回值为需要预留的总字节数。
 * 返回0表示两类情况：
 * 1）不存在任何PT_LOAD段；
 * 2）段范围非法或发生地址溢出（例如p_filesz>p_memsz、地址回绕）。
 * 若out_min_vaddr/out_max_vaddr非空，会输出页对齐后的最小／最大地址。
 */
size_t phdr_table_get_load_size(const Elf_Phdr* phdr_table, size_t phdr_count, Elf_Addr* out_min_vaddr,
								Elf_Addr* out_max_vaddr) {
	// 这里是多个读取流程共享的基础工具函数。
	// 先做参数兜底，避免调用方在异常路径传入空表或0个程序头后继续解引用。
	if (phdr_table == nullptr) {
		FLOGE("程序头表为空，无法计算可加载段范围");
		return 0;
	}
	if (phdr_count == 0) {
		FLOGE("程序头数量为0，无法计算可加载段范围");
		return 0;
	}
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
			// ELF装载语义要求文件内数据不能超过段内存大小。
			// 若该约束不成立，后续映射区间计算失去意义，直接判失败。
			FLOGE("PT_LOAD段文件大小超过内存大小：index=%zu p_filesz=0x%llx p_memsz=0x%llx", i,
				  static_cast<unsigned long long>(phdr->p_filesz), static_cast<unsigned long long>(phdr->p_memsz));
			return 0;
		}

		if (phdr->p_vaddr < min_vaddr) {
			min_vaddr = phdr->p_vaddr;
		}

		Elf_Addr seg_end = 0;
		if (!safe_add(phdr->p_vaddr, phdr->p_memsz, &seg_end)) {
			FLOGE("PT_LOAD段结束地址溢出：index=%zu p_vaddr=0x%llx p_memsz=0x%llx", i,
				  static_cast<unsigned long long>(phdr->p_vaddr), static_cast<unsigned long long>(phdr->p_memsz));
			return 0;
		}
		if (seg_end > max_vaddr) {
			max_vaddr = seg_end;
		}
	}
	if (!found_pt_load) {
		FLOGE("程序头中不存在PT_LOAD段，无法计算可加载区间");
		return 0;
	}

	min_vaddr = PAGE_START(min_vaddr);
	if (!safe_add(max_vaddr, PAGE_SIZE - 1, &max_vaddr)) {
		FLOGE("可加载段页对齐上界溢出：max_vaddr=0x%llx page_size=0x%llx", static_cast<unsigned long long>(max_vaddr),
			  static_cast<unsigned long long>(PAGE_SIZE));
		return 0;
	}
	max_vaddr = PAGE_START(max_vaddr);
	if (max_vaddr < min_vaddr) {
		FLOGE("可加载段区间异常：min_vaddr=0x%llx max_vaddr=0x%llx", static_cast<unsigned long long>(min_vaddr),
			  static_cast<unsigned long long>(max_vaddr));
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
bool ElfReader::ReserveAddressSpace(Elf_Addr padding_size) {
	Elf_Addr min_vaddr;
	const size_t load_size = phdr_table_get_load_size(phdr_table_, phdr_num_, &min_vaddr);
	if (load_size == 0) {
		FLOGE("\"%s\"不存在有效可加载段或段范围非法", name_);
		return false;
	}
	if (load_size > static_cast<size_t>(std::numeric_limits<Elf_Addr>::max())) {
		FLOGE("\"%s\"可加载段总大小超出范围：size=%zu", name_, load_size);
		return false;
	}
	load_size_ = static_cast<Elf_Addr>(load_size);
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
	// 约束关系：runtime_addr=load_bias_+vaddr。
	// 后续所有“虚拟地址->缓冲区地址”的换算都依赖这个偏移。
	load_bias_ =
		reinterpret_cast<uint8_t*>(reinterpret_cast<uintptr_t>(load_start_) - reinterpret_cast<uintptr_t>(addr));
	return true;
}

// 将每个PT_LOAD段复制到预留缓冲对应偏移处。
bool ElfReader::LoadSegments() {
	if (load_start_ == nullptr || load_bias_ == nullptr) {
		FLOGE("\"%s\"加载缓冲未初始化", name_);
		return false;
	}
	const uintptr_t load_begin = reinterpret_cast<uintptr_t>(load_start_);
	const uintptr_t load_size_bytes = static_cast<uintptr_t>(load_size_);
	if (load_size_bytes > std::numeric_limits<uintptr_t>::max() - load_begin) {
		FLOGE("\"%s\"加载缓冲边界异常", name_);
		return false;
	}
	const uintptr_t load_end = load_begin + load_size_bytes;
	auto safe_add = [](uintptr_t lhs, uintptr_t rhs, uintptr_t* out) -> bool {
		if (lhs > std::numeric_limits<uintptr_t>::max() - rhs) {
			return false;
		}
		*out = lhs + rhs;
		return true;
	};

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
			FLOGE("\"%s\"段地址区间回绕：phdr=%zu vaddr=0x%llx memsz=0x%llx", name_, i,
				  static_cast<unsigned long long>(seg_start), static_cast<unsigned long long>(phdr->p_memsz));
			return false;
		}

		//        Elf_Addr seg_page_start = PAGE_START(seg_start);
		//        Elf_Addr seg_page_end   = PAGE_END(seg_end);

		Elf_Addr seg_file_end = seg_start + phdr->p_filesz;
		if (seg_file_end < seg_start) {
			FLOGE("\"%s\"段文件区间回绕：phdr=%zu vaddr=0x%llx filesz=0x%llx", name_, i,
				  static_cast<unsigned long long>(seg_start), static_cast<unsigned long long>(phdr->p_filesz));
			return false;
		}
		if (phdr->p_filesz > phdr->p_memsz) {
			FLOGE("\"%s\"段大小非法：phdr=%zu filesz=0x%llx memsz=0x%llx（要求filesz<=memsz）", name_, i,
				  static_cast<unsigned long long>(phdr->p_filesz), static_cast<unsigned long long>(phdr->p_memsz));
			return false;
		}

		// 校验文件偏移区间，避免偏移回绕。
		Elf_Addr file_start = phdr->p_offset;
		Elf_Addr file_end = file_start + phdr->p_filesz;
		if (file_end < file_start) {
			FLOGE("\"%s\"文件偏移区间回绕：phdr=%zu offset=0x%llx filesz=0x%llx", name_, i,
				  static_cast<unsigned long long>(file_start), static_cast<unsigned long long>(phdr->p_filesz));
			return false;
		}
		if (static_cast<uint64_t>(file_end) > static_cast<uint64_t>(file_size)) {
			FLOGE("\"%s\"段文件区间越界：phdr=%zu file_end=0x%llx file_size=0x%llx", name_, i,
				  static_cast<unsigned long long>(file_end), static_cast<unsigned long long>(file_size));
			return false;
		}
		if (phdr->p_filesz > static_cast<Elf_Addr>(std::numeric_limits<size_t>::max())) {
			FLOGE("\"%s\"段文件大小超出当前平台size_t范围：phdr=%zu filesz=0x%llx max_size_t=0x%llx", name_, i,
				  static_cast<unsigned long long>(phdr->p_filesz),
				  static_cast<unsigned long long>(std::numeric_limits<size_t>::max()));
			return false;
		}

		uintptr_t seg_runtime_start = 0;
		if (!safe_add(reinterpret_cast<uintptr_t>(load_bias_), static_cast<uintptr_t>(seg_start), &seg_runtime_start)) {
			FLOGE("\"%s\"运行时段起始地址溢出：phdr=%zu load_bias=0x%llx seg_start=0x%llx", name_, i,
				  static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(load_bias_)),
				  static_cast<unsigned long long>(seg_start));
			return false;
		}
		uintptr_t seg_runtime_end = 0;
		if (!safe_add(seg_runtime_start, static_cast<uintptr_t>(phdr->p_memsz), &seg_runtime_end)) {
			FLOGE("\"%s\"运行时段结束地址溢出：phdr=%zu runtime_start=0x%llx memsz=0x%llx", name_, i,
				  static_cast<unsigned long long>(seg_runtime_start), static_cast<unsigned long long>(phdr->p_memsz));
			return false;
		}
		if (seg_runtime_start < load_begin || seg_runtime_end > load_end) {
			FLOGE("\"%s\"运行时段越过加载缓冲：phdr=%zu runtime=[0x%llx,0x%llx) load=[0x%llx,0x%llx)", name_, i,
				  static_cast<unsigned long long>(seg_runtime_start), static_cast<unsigned long long>(seg_runtime_end),
				  static_cast<unsigned long long>(load_begin), static_cast<unsigned long long>(load_end));
			return false;
		}

		//        Elf_Addr file_page_start = PAGE_START(file_start);
		size_t file_length = static_cast<size_t>(phdr->p_filesz);

		if (file_length != 0) {
			uintptr_t seg_file_runtime_end = 0;
			if (!safe_add(seg_runtime_start, static_cast<uintptr_t>(phdr->p_filesz), &seg_file_runtime_end)) {
				FLOGE("\"%s\"运行时文件段结束地址溢出：phdr=%zu runtime_start=0x%llx filesz=0x%llx", name_, i,
					  static_cast<unsigned long long>(seg_runtime_start),
					  static_cast<unsigned long long>(phdr->p_filesz));
				return false;
			}
			if (seg_file_runtime_end > load_end || seg_file_runtime_end > seg_runtime_end) {
				FLOGE("\"%s\"运行时文件段越界：phdr=%zu file_runtime_end=0x%llx seg_runtime_end=0x%llx load_end=0x%llx",
					  name_, i, static_cast<unsigned long long>(seg_file_runtime_end),
					  static_cast<unsigned long long>(seg_runtime_end), static_cast<unsigned long long>(load_end));
				return false;
			}
			// 按文件偏移把段内容读入加载缓冲。
			void* load_point = reinterpret_cast<void*>(seg_runtime_start);
			auto read_size = source_->read(load_point, file_length, file_start);
			if (read_size != file_length) {
				FLOGE("读取段数据失败：file=%s phdr=%zu offset=0x%llx expect=%zu actual=%zu errno=%d(%s)", name_, i,
					  static_cast<unsigned long long>(file_start), file_length, read_size, errno, strerror(errno));
				return false;
			}
		}

		// 若开启严格装载，可对可写段末页做零填充。
		//        if ((phdr->p_flags & PF_W) != 0 && PAGE_OFFSET(seg_file_end) > 0)
		//        {
		//            memset(seg_file_end + reinterpret_cast<uint8_t *>(load_bias_),
		//            0, PAGE_SIZE - PAGE_OFFSET(seg_file_end));
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
static int _phdr_table_set_load_prot(const Elf_Phdr* phdr_table, int phdr_count, uint8_t* load_bias,
									 int extra_prot_flags) {
	// 当前项目不实际调用mprotect，此处保留接口和段遍历逻辑。
	(void)load_bias;
	(void)extra_prot_flags;
	const Elf_Phdr* phdr = phdr_table;
	const Elf_Phdr* phdr_limit = phdr + phdr_count;

	for (; phdr < phdr_limit; phdr++) {
		if (phdr->p_type != PT_LOAD || (phdr->p_flags & PF_W) != 0) continue;

		//        int ret = mprotect((void*)seg_page_start,
		//                           seg_page_end - seg_page_start,
		//                           PFLAGS_TO_PROT(phdr->p_flags) |
		//                           extra_prot_flags);
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
int phdr_table_protect_segments(const Elf_Phdr* phdr_table, int phdr_count, uint8_t* load_bias) {
	// 对外接口：恢复段保护（当前为保留实现）。
	// 当前实现等价于遍历检查，便于后续扩展真实保护逻辑。
	return _phdr_table_set_load_prot(phdr_table, phdr_count, load_bias, 0);
}

/*
 * 对外接口：临时放宽段保护属性，便于后续做重定位修补。
 * 当前实现仅保留框架，未实际调用mprotect。
 */
int phdr_table_unprotect_segments(const Elf_Phdr* phdr_table, int phdr_count, uint8_t* load_bias) {
	// 对外接口：放宽段保护（当前为保留实现）。
	// 预留可写保护接口，当前未启用真实mprotect。
	return _phdr_table_set_load_prot(phdr_table, phdr_count, load_bias,
									 /*PROT_WRITE*/ 0);
}

/* 内部函数：处理GNU RELRO段的保护逻辑。 */
static int _phdr_table_set_gnu_relro_prot(const Elf_Phdr* phdr_table, int phdr_count, uint8_t* load_bias,
										  int prot_flags) {
	// 当前只保留遍历框架，便于后续补齐RELRO真实保护。
	// 注意：PT_GNU_RELRO筛选与mprotect调用均处于关闭状态。
	(void)load_bias;
	(void)prot_flags;
	const Elf_Phdr* phdr = phdr_table;
	const Elf_Phdr* phdr_limit = phdr + phdr_count;

	for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
		//        if (phdr->p_type != PT_GNU_RELRO)
		//            continue;

		/*
		 * RELRO段若未严格按页边界对齐，保护粒度会扩展到整页。
		 * 因此实际处理时通常以“段覆盖到的整页”作为最小保护单位。
		 */
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
int phdr_table_protect_gnu_relro(const Elf_Phdr* phdr_table, int phdr_count, uint8_t* load_bias) {
	// 对外接口：处理GNU RELRO保护（当前为保留实现）。
	// 对外RELRO保护入口。
	return _phdr_table_set_gnu_relro_prot(phdr_table, phdr_count, load_bias,
										  /*PROT_READ*/ 0);
}

#ifndef PT_ARM_EXIDX
#define PT_ARM_EXIDX 0x70000001 /* .ARM.exidx段 */
#endif

/*
 * 返回.ARM.exidx在内存中的地址和条目数量。
 * 找到则返回0，未找到返回-1。
 */
int phdr_table_get_arm_exidx(const Elf_Phdr* phdr_table, int phdr_count, uint8_t* load_bias, Elf_Addr** arm_exidx,
							 size_t* arm_exidx_count) {
	if (arm_exidx == NULL || arm_exidx_count == NULL) {
		FLOGE("无效输出指针：arm_exidx=%p arm_exidx_count=%p", arm_exidx, arm_exidx_count);
		return -1;
	}
	*arm_exidx = NULL;
	*arm_exidx_count = 0;
	if (phdr_table == NULL) {
		FLOGE("无效程序头表指针：phdr_table为空");
		return -1;
	}
	if (phdr_count <= 0) {
		FLOGE("无效程序头数量：phdr_count=%d", phdr_count);
		return -1;
	}
	if (load_bias == NULL) {
		FLOGE("无效加载基址：load_bias为空");
		return -1;
	}
	// 对外接口：返回ARM异常回溯段地址及条目数量。
	// 从程序头中查找ARM异常回溯表。
	const Elf_Phdr* phdr = phdr_table;
	const Elf_Phdr* phdr_limit = phdr + phdr_count;

	for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
		if (phdr->p_type != PT_ARM_EXIDX) continue;

		*arm_exidx = (Elf_Addr*)((uint8_t*)load_bias + phdr->p_vaddr);
		Elf_Addr entry_count = phdr->p_memsz / sizeof(Elf_Addr);
		if (entry_count > static_cast<Elf_Addr>(std::numeric_limits<size_t>::max())) {
			FLOGE("ARM.exidx条目数量溢出：p_memsz=0x%llx entry_count=0x%llx",
				  static_cast<unsigned long long>(phdr->p_memsz), static_cast<unsigned long long>(entry_count));
			*arm_exidx = NULL;
			*arm_exidx_count = 0;
			return -1;
		}
		*arm_exidx_count = static_cast<size_t>(entry_count);
		return 0;
	}
	return -1;
}

/*
 * 从程序头中提取.dynamic段地址、项数和权限标记。
 * 若未找到有效动态段，则dynamic输出为NULL。
 * 调用约定：函数入口会先把输出参数归零，调用方可只检查dynamic是否为空。
 * 判定规则：仅接受“至少1个Elf_Dyn且完整落入某个PT_LOAD”的PT_DYNAMIC。
 * 计数规则：dynamic_count按dyn_size/sizeof(Elf_Dyn)下取整，尾部残缺字节会被忽略。
 * 多段规则：若存在多个PT_DYNAMIC候选，返回第一个通过完整性校验的段。
 */
void phdr_table_get_dynamic_section(const Elf_Phdr* phdr_table, int phdr_count, uint8_t* load_bias, Elf_Dyn** dynamic,
									size_t* dynamic_count, Elf_Word* dynamic_flags) {
	if (dynamic == NULL) {
		FLOGE("无效输出指针：dynamic为空");
		return;
	}
	*dynamic = NULL;
	if (dynamic_count) {
		*dynamic_count = 0;
	}
	if (dynamic_flags) {
		*dynamic_flags = 0;
	}
	if (phdr_table == NULL) {
		FLOGE("无效程序头表指针：phdr_table为空");
		return;
	}
	if (phdr_count <= 0) {
		FLOGE("无效程序头数量：phdr_count=%d", phdr_count);
		return;
	}
	if (load_bias == NULL) {
		FLOGE("无效加载基址：load_bias为空");
		return;
	}
	// 对外接口：从程序头中提取动态段信息。
	// 动态段必须完全落在某个PT_LOAD范围内。
	auto range_in_load = [phdr_table, phdr_count](Elf_Addr start, Elf_Addr size) -> bool {
		// 使用[start,end)半开区间做范围比较，避免边界重复计数。
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

		// 动态段在文件中的有效字节通常不超过映射内存大小。
		// 对转储样本优先取更保守的最小值，避免把文件缺失区域当成可用动态表解析。
		Elf_Addr dyn_size = phdr->p_memsz;
		if (phdr->p_filesz != 0 && phdr->p_filesz < dyn_size) {
			dyn_size = phdr->p_filesz;
		}
		// 至少要容纳一个Elf_Dyn条目，并且区间必须完整落在任一PT_LOAD段内。
		if (dyn_size < sizeof(Elf_Dyn) || !range_in_load(phdr->p_vaddr, dyn_size)) {
			continue;
		}
		*dynamic = reinterpret_cast<Elf_Dyn*>(load_bias + phdr->p_vaddr);
		if (dynamic_count) {
			// dyn_size可能不是条目大小整数倍，按完整条目数量向下取整。
			*dynamic_count = static_cast<size_t>(dyn_size / sizeof(Elf_Dyn));
		}
		if (dynamic_flags) {
			*dynamic_flags = phdr->p_flags;
		}
		return;
	}
	FLOGE("未找到有效PT_DYNAMIC段：phdr_count=%d", phdr_count);
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

	// 若无PT_PHDR，则尝试从“任意offset为0的PT_LOAD”反推出程序头地址。
	// 不能只检查第一个PT_LOAD，原因如下：
	// 1）部分转储样本的程序头顺序可能被打乱；
	// 2）第一个出现的PT_LOAD未必对应ELF文件起始映射；
	// 3）若只看第一个就break，会把后续本可恢复的样本误判为失败。
	for (const Elf_Phdr* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
		if (phdr->p_type == PT_LOAD) {
			if (phdr->p_offset == 0) {
				// 常见场景：某个可加载段映射了ELF起始页，可通过e_phoff定位程序头。
				// 这里优先使用已校验过的header_.e_phoff，不直接信任内存里ehdr副本，
				// 避免转储脏数据覆盖后导致偏移异常。
				const auto base_addr = reinterpret_cast<uintptr_t>(load_bias_);
				const auto seg_vaddr = static_cast<uintptr_t>(phdr->p_vaddr);
				if (base_addr > std::numeric_limits<uintptr_t>::max() - seg_vaddr) {
					FLOGW("PT_LOAD基址溢出，跳过该候选：vaddr=0x%llx", static_cast<unsigned long long>(phdr->p_vaddr));
					continue;
				}
				const auto elf_addr = base_addr + seg_vaddr;
				const auto phoff_addr = static_cast<uintptr_t>(header_.e_phoff);
				if (elf_addr > std::numeric_limits<uintptr_t>::max() - phoff_addr) {
					FLOGW("程序头地址溢出，跳过该候选：elf_addr=0x%llx e_phoff=0x%llx",
						  static_cast<unsigned long long>(elf_addr), static_cast<unsigned long long>(header_.e_phoff));
					continue;
				}
				const auto phdr_addr = elf_addr + phoff_addr;
				if (CheckPhdr(reinterpret_cast<uint8_t*>(phdr_addr))) {
					return true;
				}
			}
		}
	}

	FLOGE("无法在\"%s\"中定位已加载程序头", name_);
	return false;
}

// 校验程序头表指针范围是否落在可加载段内，避免后续越界访问。
bool ElfReader::CheckPhdr(uint8_t* loaded) {
	if (loaded == nullptr || load_start_ == nullptr) {
		FLOGE("\"%s\"程序头地址为空", name_);
		return false;
	}
	const uintptr_t load_begin = reinterpret_cast<uintptr_t>(load_start_);
	const uintptr_t load_size_bytes = static_cast<uintptr_t>(load_size_);
	if (load_size_bytes > std::numeric_limits<uintptr_t>::max() - load_begin) {
		FLOGE("\"%s\"加载缓冲边界异常", name_);
		return false;
	}
	const uintptr_t load_end = load_begin + load_size_bytes;
	const uintptr_t loaded_begin = reinterpret_cast<uintptr_t>(loaded);
	const uintptr_t phdr_bytes = static_cast<uintptr_t>(phdr_num_ * sizeof(Elf_Phdr));
	if (phdr_bytes > std::numeric_limits<uintptr_t>::max() - loaded_begin) {
		FLOGE("\"%s\"程序头范围溢出", name_);
		return false;
	}
	const uintptr_t loaded_end_value = loaded_begin + phdr_bytes;
	if (loaded_begin < load_begin || loaded_end_value > load_end) {
		FLOGE("\"%s\"的已加载程序头%p越过加载缓冲范围", name_, loaded);
		return false;
	}
	auto safe_add = [](uintptr_t lhs, uintptr_t rhs, uintptr_t* out) -> bool {
		if (lhs > std::numeric_limits<uintptr_t>::max() - rhs) {
			return false;
		}
		*out = lhs + rhs;
		return true;
	};
	const Elf_Phdr* phdr_limit = phdr_table_ + phdr_num_;
	auto loaded_end = reinterpret_cast<uint8_t*>(loaded_end_value);
	// 保证loaded指针覆盖区间完全落在某个可加载段内。
	for (Elf_Phdr* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
		if (phdr->p_type != PT_LOAD) {
			continue;
		}
		uintptr_t seg_start_value = 0;
		if (!safe_add(reinterpret_cast<uintptr_t>(load_bias_), static_cast<uintptr_t>(phdr->p_vaddr),
					  &seg_start_value)) {
			continue;
		}
		auto seg_start = reinterpret_cast<uint8_t*>(seg_start_value);
		auto seg_size = phdr->p_memsz;
		if (phdr->p_filesz > seg_size) {
			seg_size = phdr->p_filesz;
		}
		uintptr_t seg_end_value = 0;
		if (!safe_add(seg_start_value, static_cast<uintptr_t>(seg_size), &seg_end_value)) {
			continue;
		}
		auto seg_end = reinterpret_cast<uint8_t*>(seg_end_value);
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
	// 回写前必须保证“源表/目标表/条目数量”三者都有效。
	// 这里是修复流程的收口点，如果静默写坏程序头会导致后续重建结果不可用且难排查。
	if (loaded_phdr_ == nullptr || phdr_table_ == nullptr) {
		FLOGE("程序头回写失败：loaded_phdr=%p phdr_table=%p", loaded_phdr_, phdr_table_);
		return;
	}
	if (phdr_num_ == 0) {
		FLOGE("程序头回写失败：phdr_num为0");
		return;
	}
	if (phdr_num_ > std::numeric_limits<size_t>::max() / sizeof(Elf_Phdr)) {
		FLOGE("程序头回写失败：复制大小溢出，phdr_num=%zu", phdr_num_);
		return;
	}
	// 使用“条目数*条目大小”明确计算复制长度，避免指针差值在跨位宽场景出现歧义。
	// 把修正后的程序头表写回已加载镜像，保证后续重建读取到的是修正值。
	const size_t phdr_copy_bytes = phdr_num_ * sizeof(Elf_Phdr);
	memcpy((void*)loaded_phdr_, (void*)phdr_table_, phdr_copy_bytes);
	return;
}

// 绑定输入文件路径并初始化底层文件读取器。
bool ElfReader::setSource(const char* source) {
	return set_source(source == nullptr ? std::string_view() : std::string_view(source));
}

bool ElfReader::set_source(std::string_view source) {
	// 打开输入文件并缓存大小。
	if (source.empty()) {
		FLOGE("输入文件路径为空");
		return false;
	}
	name_storage_ = source;
	name_ = name_storage_.c_str();
	auto fr = std::make_unique<FileReader>(source);
	if (!fr->open()) {
		FLOGE("\"%s\"打开失败", name_);
		return false;
	}
	auto source_size = fr->file_size();
	if (source_size > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
		FLOGE("\"%s\"文件过大，当前构建无法处理", name_);
		return false;
	}
	file_size = static_cast<size_t>(source_size);
	source_holder_ = std::move(fr);
	source_ = source_holder_.get();
	return true;
}

// 读取当前实例中的动态段信息，供重建阶段提取DT_*元数据。
void ElfReader::GetDynamicSection(Elf_Dyn** dynamic, size_t* dynamic_count, Elf_Word* dynamic_flags) {
	// 统一失败输出语义：函数返回前先把输出初始化为空状态。
	// 这样调用方即使忽略日志，也能通过“空指针＋0计数”判断当前没有可用动态段。
	// 该行为与phdr_table_get_dynamic_section保持一致，便于两种调用路径统一处理。
	if (dynamic == nullptr) {
		FLOGE("无效输出指针：dynamic为空");
		return;
	}
	*dynamic = nullptr;
	if (dynamic_count) {
		*dynamic_count = 0;
	}
	if (dynamic_flags) {
		*dynamic_flags = 0;
	}
	if (phdr_table_ == nullptr) {
		FLOGE("程序头表未初始化");
		return;
	}
	if (phdr_num_ == 0) {
		FLOGE("程序头数量为0，无法读取动态段");
		return;
	}
	if (load_bias_ == nullptr) {
		FLOGE("加载偏移基址未初始化");
		return;
	}
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

		// 与全局辅助函数保持一致：动态段可解析长度取min(p_memsz,p_filesz)。
		// 这样可兼容“内存段存在但文件段不完整”的转储输入。
		Elf_Addr dyn_size = phdr->p_memsz;
		if (phdr->p_filesz != 0 && phdr->p_filesz < dyn_size) {
			dyn_size = phdr->p_filesz;
		}
		// 动态段必须可容纳至少一个条目，且地址区间必须位于已加载PT_LOAD覆盖范围。
		if (dyn_size < sizeof(Elf_Dyn) || !range_in_load(phdr->p_vaddr, dyn_size)) {
			continue;
		}
		*dynamic = reinterpret_cast<Elf_Dyn*>(load_bias_ + phdr->p_vaddr);
		if (dynamic_count) {
			// 与全局函数一致：仅返回完整条目数量，避免残缺条目进入后续DT_*扫描。
			*dynamic_count = static_cast<size_t>(dyn_size / sizeof(Elf_Dyn));
		}
		if (dynamic_flags) {
			*dynamic_flags = phdr->p_flags;
		}
		return;
	}
	FLOGE("未找到有效PT_DYNAMIC段：phdr_count=%zu", phdr_num_);
}
