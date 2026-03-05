//===------------------------------------------------------------*- C++ -*-===//
//
//                     由F8LEFT创建于2017/6/4。
//                   版权所有（c）2017。
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//
// 文件功能：实现ELF修复重建流程，包括动态信息提取、节表生成与重定位修正。
#include "elf_rebuilder.h"

#include <cstdio>
#include <cstring>
#include <limits>
#include <new>

#include "elf.h"

#ifdef __SO64__
#define ADDRESS_FORMAT "ll"
#else
#define ADDRESS_FORMAT ""
#endif

#ifndef R_AARCH64_GLOB_DAT
#define R_AARCH64_GLOB_DAT 1025
#endif
#ifndef R_AARCH64_JUMP_SLOT
#define R_AARCH64_JUMP_SLOT 1026
#endif
#ifndef R_AARCH64_RELATIVE
#define R_AARCH64_RELATIVE 1027
#endif

namespace {
// 安全地址加法；发生溢出时返回失败状态。
bool AddElfAddr(Elf_Addr lhs, Elf_Addr rhs, Elf_Addr* out) {
	if (lhs > std::numeric_limits<Elf_Addr>::max() - rhs) {
		return false;
	}
	*out = lhs + rhs;
	return true;
}

// 安全size_t加法；用于处理动态表中由外部输入驱动的计数运算。
bool AddSizeT(size_t lhs, size_t rhs, size_t* out) {
	if (out == nullptr) {
		return false;
	}
	if (lhs > std::numeric_limits<size_t>::max() - rhs) {
		return false;
	}
	*out = lhs + rhs;
	return true;
}

// 基于程序头逐段校验［start,start+size）是否位于某个PT_LOAD内。
// 该函数按每个PT_LOAD独立校验，可拦截“位于段间空洞”的伪合法地址。
bool RangeInLoadSegments(Elf_Addr start, Elf_Addr size, const Elf_Phdr* phdr_table, size_t phdr_count) {
	if (phdr_table == nullptr || phdr_count == 0) {
		return false;
	}
	Elf_Addr end = start;
	if (size != 0 && !AddElfAddr(start, size, &end)) {
		return false;
	}
	for (size_t i = 0; i < phdr_count; ++i) {
		const Elf_Phdr* load = &phdr_table[i];
		if (load->p_type != PT_LOAD) {
			continue;
		}
		Elf_Addr load_end = 0;
		if (!AddElfAddr(load->p_vaddr, load->p_memsz, &load_end)) {
			continue;
		}
		if (size == 0) {
			if (start >= load->p_vaddr && start <= load_end) {
				return true;
			}
		} else if (start >= load->p_vaddr && end <= load_end) {
			return true;
		}
	}
	return false;
}

// 与PointerInLoad类似，但边界判断改为“逐个PT_LOAD段覆盖”。
// 这样可以避免指针落在[min_load,max_load)连续区间内却实际处于段间空洞的误判。
bool PointerInLoadSegments(const uint8_t* base, const void* ptr, size_t size, const Elf_Phdr* phdr_table,
						   size_t phdr_count) {
	if (base == nullptr || ptr == nullptr) {
		return false;
	}
	const auto base_addr = reinterpret_cast<uintptr_t>(base);
	const auto ptr_addr = reinterpret_cast<uintptr_t>(ptr);
	if (ptr_addr < base_addr) {
		return false;
	}
	const auto offset = ptr_addr - base_addr;
	if (offset > std::numeric_limits<Elf_Addr>::max()) {
		return false;
	}
	if (size > static_cast<size_t>(std::numeric_limits<Elf_Addr>::max())) {
		return false;
	}
	return RangeInLoadSegments(static_cast<Elf_Addr>(offset), static_cast<Elf_Addr>(size), phdr_table, phdr_count);
}

// 将运行时指针转换为相对load_bias的Elf_Addr偏移，带范围检查。
bool PointerToElfAddrOffset(const uint8_t* base, const void* ptr, const char* field, Elf_Addr* out) {
	if (field == nullptr) {
		field = "unknown";
	}
	if (out == nullptr) {
		FLOGE("%s偏移写入目标为空", field);
		return false;
	}
	if (base == nullptr || ptr == nullptr) {
		FLOGE("%s偏移计算参数无效：base=%p ptr=%p", field, base, ptr);
		return false;
	}
	const auto base_addr = reinterpret_cast<uintptr_t>(base);
	const auto ptr_addr = reinterpret_cast<uintptr_t>(ptr);
	if (ptr_addr < base_addr) {
		FLOGE("%s偏移计算失败：ptr小于base，base=0x%llx ptr=0x%llx", field, static_cast<unsigned long long>(base_addr),
			  static_cast<unsigned long long>(ptr_addr));
		return false;
	}
	const auto offset = ptr_addr - base_addr;
	if (offset > static_cast<uintptr_t>(std::numeric_limits<Elf_Addr>::max())) {
		FLOGE("%s偏移超出Elf_Addr范围：offset=0x%llx max=0x%" ADDRESS_FORMAT "x", field,
			  static_cast<unsigned long long>(offset), std::numeric_limits<Elf_Addr>::max());
		return false;
	}
	*out = static_cast<Elf_Addr>(offset);
	return true;
}

// 将size_t安全转换为Elf_Addr，便于写入sh_size等字段。
bool SizeToElfAddr(size_t value, const char* field, Elf_Addr* out) {
	if (field == nullptr) {
		field = "unknown";
	}
	if (out == nullptr) {
		FLOGE("%s写入目标为空", field);
		return false;
	}
	if (value > static_cast<size_t>(std::numeric_limits<Elf_Addr>::max())) {
		FLOGE("%s超出Elf_Addr范围：value=%zu max=0x%" ADDRESS_FORMAT "x", field, value,
			  std::numeric_limits<Elf_Addr>::max());
		return false;
	}
	*out = static_cast<Elf_Addr>(value);
	return true;
}

// 校验字符串偏移是否在strtab内且能找到结尾'\0'。
bool StringOffsetValid(const char* strtab, size_t strtab_size, Elf_Word name_off) {
	if (strtab == nullptr || strtab_size == 0) {
		return false;
	}
	const auto name_index = static_cast<size_t>(name_off);
	if (name_index >= strtab_size) {
		return false;
	}
	const void* terminator = memchr(strtab + name_index, '\0', strtab_size - name_index);
	return terminator != nullptr;
}

// count*elem_size转换为Elf_Addr字节数，带溢出校验。
bool CountToBytes(size_t count, size_t elem_size, Elf_Addr* out_bytes) {
	if (elem_size == 0) {
		return false;
	}
	if (count > std::numeric_limits<size_t>::max() / elem_size) {
		return false;
	}
	const size_t bytes = count * elem_size;
	if (bytes > static_cast<size_t>(std::numeric_limits<Elf_Addr>::max())) {
		return false;
	}
	*out_bytes = static_cast<Elf_Addr>(bytes);
	return true;
}

// bytes/elem_size转换为数量，要求整除。
bool BytesToCount(Elf_Addr bytes, size_t elem_size, size_t* out_count) {
	if (elem_size == 0) {
		return false;
	}
	const auto elem = static_cast<Elf_Addr>(elem_size);
	if (bytes % elem != 0) {
		return false;
	}
	const auto count = bytes / elem;
	if (count > static_cast<Elf_Addr>(std::numeric_limits<size_t>::max())) {
		return false;
	}
	*out_count = static_cast<size_t>(count);
	return true;
}

// 判断是否为相对重定位类型。
bool IsRelativeRelocType(Elf_Addr type) {
	return type == R_386_RELATIVE || type == R_ARM_RELATIVE || type == R_X86_64_RELATIVE || type == R_AARCH64_RELATIVE;
}

// 判断是否为导入符号相关重定位类型。
bool IsImportRelocType(Elf_Addr type) {
	return type == R_386_GLOB_DAT || type == R_386_JMP_SLOT || type == R_ARM_GLOB_DAT || type == R_ARM_JUMP_SLOT ||
		   type == R_X86_64_GLOB_DAT || type == R_X86_64_JUMP_SLOT || type == R_AARCH64_GLOB_DAT ||
		   type == R_AARCH64_JUMP_SLOT || type == 0x401 || type == 0x402;
}
}  // namespace

// 绑定读取器实例。
ElfRebuilder::ElfRebuilder(ObElfReader* elf_reader) { elf_reader_ = elf_reader; }

// 重写程序头：输出文件偏移按已加载内存地址布局。
bool ElfRebuilder::RebuildPhdr() {
	FLOGD("=====================RebuildPhdr======================");

	auto phdr = (Elf_Phdr*)elf_reader_->loaded_phdr();
	for (size_t i = 0; i < elf_reader_->phdr_count(); ++i) {
		phdr->p_filesz = phdr->p_memsz;	 // 输出文件大小与内存段大小保持一致。
		// p_paddr和p_align在当前重建路径不参与装载决策。
		// 输出文件偏移按内存镜像布局修正。
		phdr->p_paddr = phdr->p_vaddr;
		phdr->p_offset = phdr->p_vaddr;	 // 当前已按内存地址布局加载。
		phdr++;
	}
	FLOGD("===================RebuildPhdr End====================");
	return true;
}

// 重建节头表和节名表。
bool ElfRebuilder::RebuildShdr() {
	FLOGD("=======================RebuildShdr=========================");
	shdrs.clear();
	shstrtab.clear();
	sDYNSYM = 0;
	sDYNSTR = 0;
	sHASH = 0;
	sRELDYN = 0;
	sRELADYN = 0;
	sRELPLT = 0;
	sPLT = 0;
	sTEXTTAB = 0;
	sARMEXIDX = 0;
	sFINIARRAY = 0;
	sINITARRAY = 0;
	sDYNAMIC = 0;
	sGOT = 0;
	sDATA = 0;
	sBSS = 0;
	sSHSTRTAB = 0;
	// 重建节头表和节索引关联信息。
	auto base = si.load_bias;
	auto checked_count_bytes = [](size_t count, size_t elem_size, const char* section, Elf_Addr* out) -> bool {
		if (!CountToBytes(count, elem_size, out)) {
			FLOGE("节%s大小计算失败：count=%zu elem_size=%zu", section, count, elem_size);
			return false;
		}
		return true;
	};
	auto assign_word_checked = [](size_t value, const char* field, Elf_Word* out) -> bool {
		if (out == nullptr) {
			FLOGE("%s写入目标为空", field);
			return false;
		}
		if (value > static_cast<size_t>(std::numeric_limits<Elf_Word>::max())) {
			FLOGE("%s超出Elf_Word范围：value=%zu max=%u", field, value,
				  static_cast<unsigned>(std::numeric_limits<Elf_Word>::max()));
			return false;
		}
		*out = static_cast<Elf_Word>(value);
		return true;
	};
	auto assign_section_index = [&](Elf_Word* out, const char* section) -> bool {
		return assign_word_checked(shdrs.size(), section, out);
	};
	auto append_section_name = [&](Elf_Shdr* shdr, const char* name) -> bool {
		if (shdr == nullptr || name == nullptr) {
			FLOGE("节名写入参数无效：shdr=%p name=%p", shdr, name);
			return false;
		}
		if (!assign_word_checked(shstrtab.length(), name, &shdr->sh_name)) {
			return false;
		}
		shstrtab.append(name);
		shstrtab.push_back('\0');
		return true;
	};
	shstrtab.push_back('\0');

	// 0号节：空节。
	if (true) {
		Elf_Shdr shdr = {};
		shdrs.push_back(shdr);
	}

	// 生成.dynsym节。
	if (si.symtab != nullptr) {
		if (!assign_section_index(&sDYNSYM, ".dynsym索引")) {
			return false;
		}

		Elf_Shdr shdr = {};
		if (!append_section_name(&shdr, ".dynsym")) {
			return false;
		}

		shdr.sh_type = SHT_DYNSYM;
		shdr.sh_flags = SHF_ALLOC;
		if (!PointerToElfAddrOffset(base, si.symtab, ".dynsym地址", &shdr.sh_addr)) {
			return false;
		}
		shdr.sh_offset = shdr.sh_addr;
		shdr.sh_size = 0;  // 后续根据下一节地址回填大小。
		shdr.sh_link = 0;  // 后续回填到.dynstr。
						   //        shdr.sh_info = 1;
		shdr.sh_info = 0;
#ifdef __SO64__
		shdr.sh_addralign = 8;
		shdr.sh_entsize = 0x18;
#else
		shdr.sh_addralign = 4;
		shdr.sh_entsize = 0x10;
#endif

		shdrs.push_back(shdr);
	}

	// 生成.dynstr节。
	if (si.strtab != nullptr) {
		if (!assign_section_index(&sDYNSTR, ".dynstr索引")) {
			return false;
		}

		Elf_Shdr shdr = {};
		if (!append_section_name(&shdr, ".dynstr")) {
			return false;
		}

		shdr.sh_type = SHT_STRTAB;
		shdr.sh_flags = SHF_ALLOC;
		if (!PointerToElfAddrOffset(base, si.strtab, ".dynstr地址", &shdr.sh_addr)) {
			return false;
		}
		shdr.sh_offset = shdr.sh_addr;
		if (!SizeToElfAddr(si.strtabsize, ".dynstr大小", &shdr.sh_size)) {
			return false;
		}
		shdr.sh_link = 0;
		shdr.sh_info = 0;
		shdr.sh_addralign = 1;
		shdr.sh_entsize = 0x0;

		shdrs.push_back(shdr);
	}

	// 生成.hash节。
	if (si.hash != nullptr) {
		if (!assign_section_index(&sHASH, ".hash索引")) {
			return false;
		}

		Elf_Shdr shdr = {};
		if (!append_section_name(&shdr, ".hash")) {
			return false;
		}

		shdr.sh_type = SHT_HASH;
		shdr.sh_flags = SHF_ALLOC;

		if (!PointerToElfAddrOffset(base, si.hash, ".hash地址", &shdr.sh_addr)) {
			return false;
		}
		shdr.sh_offset = shdr.sh_addr;
		Elf_Addr hash_word_count = 0;
		if (!AddElfAddr(static_cast<Elf_Addr>(si.nbucket), static_cast<Elf_Addr>(si.nchain), &hash_word_count) ||
			!AddElfAddr(hash_word_count, 2, &hash_word_count)) {
			FLOGE(".hash条目数计算失败：nbucket=%zu nchain=%zu", si.nbucket, si.nchain);
			return false;
		}
		Elf_Addr hash_size = 0;
		if (!CountToBytes(static_cast<size_t>(hash_word_count), sizeof(Elf_Word), &hash_size)) {
			FLOGE(".hash字节大小计算失败：word_count=0x%" ADDRESS_FORMAT "x word_size=%zu",
				  static_cast<Elf_Addr>(hash_word_count), sizeof(Elf_Word));
			return false;
		}
		shdr.sh_size = hash_size;
		shdr.sh_link = sDYNSYM;
		shdr.sh_info = 0;
		shdr.sh_addralign = 4;
		shdr.sh_entsize = 0x4;

		shdrs.push_back(shdr);
	}

	// 生成.rel.dyn节。
	if (si.rel != nullptr) {
		if (!assign_section_index(&sRELDYN, ".rel.dyn索引")) {
			return false;
		}

		Elf_Shdr shdr = {};
		if (!append_section_name(&shdr, ".rel.dyn")) {
			return false;
		}

		shdr.sh_type = SHT_REL;
		shdr.sh_flags = SHF_ALLOC;
		if (!PointerToElfAddrOffset(base, si.rel, ".rel.dyn地址", &shdr.sh_addr)) {
			return false;
		}
		shdr.sh_offset = shdr.sh_addr;
		if (!checked_count_bytes(si.rel_count, sizeof(Elf_Rel), ".rel.dyn", &shdr.sh_size)) {
			return false;
		}
		shdr.sh_link = sDYNSYM;
		shdr.sh_info = 0;
#ifdef __SO64__
		shdr.sh_addralign = 8;
		shdr.sh_entsize = sizeof(Elf_Rel);
#else
		shdr.sh_addralign = 4;
		shdr.sh_entsize = 0x8;
#endif

		shdrs.push_back(shdr);
	}

	// 生成.rela.dyn节（常见于RELA格式的主重定位表）。
	if (si.plt_rela != nullptr) {
		if (!assign_section_index(&sRELADYN, ".rela.dyn索引")) {
			return false;
		}
		Elf_Shdr shdr = {};
		if (!append_section_name(&shdr, ".rela.dyn")) {
			return false;
		}
		shdr.sh_type = SHT_RELA;
		shdr.sh_flags = SHF_ALLOC;
		if (!PointerToElfAddrOffset(base, si.plt_rela, ".rela.dyn地址", &shdr.sh_addr)) {
			return false;
		}
		shdr.sh_offset = shdr.sh_addr;
		if (!checked_count_bytes(si.plt_rela_count, sizeof(Elf_Rela), ".rela.dyn", &shdr.sh_size)) {
			return false;
		}
		shdr.sh_link = sDYNSYM;
		shdr.sh_info = 0;
#ifdef __SO64__
		shdr.sh_addralign = 8;
#else
		shdr.sh_addralign = 4;
#endif
		shdr.sh_entsize = sizeof(Elf_Rela);
		shdrs.push_back(shdr);
	}
	// 生成.rel.plt/.rela.plt节。
	if (si.plt_rel != nullptr) {
		if (si.plt_type != DT_REL && si.plt_type != DT_RELA) {
			FLOGE(".plt重定位类型不受支持：plt_type=0x%" ADDRESS_FORMAT "x（仅支持DT_REL/DT_RELA）",
				  static_cast<Elf_Addr>(si.plt_type));
			return false;
		}
		if (!assign_section_index(&sRELPLT, ".rel.plt/.rela.plt索引")) {
			return false;
		}

		Elf_Shdr shdr = {};
		if (si.plt_type == DT_REL) {
			if (!append_section_name(&shdr, ".rel.plt")) {
				return false;
			}
		} else {
			if (!append_section_name(&shdr, ".rela.plt")) {
				return false;
			}
		}

		if (si.plt_type == DT_REL) {
			shdr.sh_type = SHT_REL;
		} else {
			shdr.sh_type = SHT_RELA;
		}
		shdr.sh_flags = SHF_ALLOC;
		if (!PointerToElfAddrOffset(base, si.plt_rel, ".rel.plt/.rela.plt地址", &shdr.sh_addr)) {
			return false;
		}
		shdr.sh_offset = shdr.sh_addr;
		if (si.plt_type == DT_REL) {
			if (!checked_count_bytes(si.plt_rel_count, sizeof(Elf_Rel), ".rel.plt", &shdr.sh_size)) {
				return false;
			}
		} else {
			if (!checked_count_bytes(si.plt_rel_count, sizeof(Elf_Rela), ".rela.plt", &shdr.sh_size)) {
				return false;
			}
		}
		shdr.sh_link = sDYNSYM;
		shdr.sh_info = 0;
		if (si.plt_type == DT_REL) {
			shdr.sh_entsize = sizeof(Elf_Rel);
		} else {
			shdr.sh_entsize = sizeof(Elf_Rela);
		}
#ifdef __SO64__
		shdr.sh_addralign = 8;
#else
		shdr.sh_addralign = 4;
#endif

		shdrs.push_back(shdr);
	}

	// 基于plt重定位区间推导.plt节。
	if (si.plt_rel != nullptr) {
		if (!assign_section_index(&sPLT, ".plt索引")) {
			return false;
		}

		Elf_Shdr shdr = {};
		if (!append_section_name(&shdr, ".plt")) {
			return false;
		}

		shdr.sh_type = SHT_PROGBITS;
		shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
		if (!AddElfAddr(shdrs[sRELPLT].sh_addr, shdrs[sRELPLT].sh_size, &shdr.sh_addr)) {
			FLOGE("无效.plt节起始地址：relplt_addr=0x%" ADDRESS_FORMAT "x relplt_size=0x%" ADDRESS_FORMAT "x",
				  shdrs[sRELPLT].sh_addr, shdrs[sRELPLT].sh_size);
			return false;
		}
		shdr.sh_offset = shdr.sh_addr;
		// 后续可按架构重新校准.plt模板长度。
		Elf_Addr plt_tail_size = 0;
		if (!checked_count_bytes(si.plt_rel_count, 12, ".plt", &plt_tail_size) ||
			!AddElfAddr(static_cast<Elf_Addr>(20), plt_tail_size, &shdr.sh_size)) {
			FLOGE("无效.plt节大小：plt_rel_count=%zu plt_tail_size=0x%" ADDRESS_FORMAT "x", si.plt_rel_count,
				  plt_tail_size);
			return false;
		}
		shdr.sh_link = 0;
		shdr.sh_info = 0;
		shdr.sh_addralign = 4;
		shdr.sh_entsize = 0x0;

		shdrs.push_back(shdr);
	}

	// 生成.text&ARM.extab过渡节。
	if (si.plt_rel != nullptr) {
		if (!assign_section_index(&sTEXTTAB, ".text&ARM.extab索引")) {
			return false;
		}

		Elf_Shdr shdr = {};
		if (!append_section_name(&shdr, ".text&ARM.extab")) {
			return false;
		}

		shdr.sh_type = SHT_PROGBITS;
		shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
		if (!AddElfAddr(shdrs[sPLT].sh_addr, shdrs[sPLT].sh_size, &shdr.sh_addr)) {
			FLOGE("无效.text&ARM.extab起始地址：plt_addr=0x%" ADDRESS_FORMAT "x plt_size=0x%" ADDRESS_FORMAT "x",
				  shdrs[sPLT].sh_addr, shdrs[sPLT].sh_size);
			return false;
		}
		// 按8字节对齐。
		while (shdr.sh_addr & 0x7) {
			if (shdr.sh_addr == std::numeric_limits<Elf_Addr>::max()) {
				FLOGE("无效.text&ARM.extab对齐地址：addr=0x%" ADDRESS_FORMAT "x", shdr.sh_addr);
				return false;
			}
			shdr.sh_addr++;
		}

		shdr.sh_offset = shdr.sh_addr;
		shdr.sh_size = 0;  // 后续回填。
		shdr.sh_link = 0;
		shdr.sh_info = 0;
		shdr.sh_addralign = 8;
		shdr.sh_entsize = 0x0;

		shdrs.push_back(shdr);
	}

	// 生成.ARM.exidx节。
	if (si.ARM_exidx != nullptr) {
		if (!assign_section_index(&sARMEXIDX, ".ARM.exidx索引")) {
			return false;
		}

		Elf_Shdr shdr = {};
		if (!append_section_name(&shdr, ".ARM.exidx")) {
			return false;
		}

		shdr.sh_type = SHT_ARMEXIDX;
		shdr.sh_flags = SHF_ALLOC | SHF_LINK_ORDER;
		if (!PointerToElfAddrOffset(base, si.ARM_exidx, ".ARM.exidx地址", &shdr.sh_addr)) {
			return false;
		}
		shdr.sh_offset = shdr.sh_addr;
		if (!checked_count_bytes(si.ARM_exidx_count, sizeof(Elf_Addr), ".ARM.exidx", &shdr.sh_size)) {
			return false;
		}
		shdr.sh_link = sTEXTTAB;
		shdr.sh_info = 0;
		shdr.sh_addralign = 4;
		shdr.sh_entsize = 0x8;

		shdrs.push_back(shdr);
	}
	// 生成.fini_array节。
	if (si.fini_array != nullptr) {
		if (!assign_section_index(&sFINIARRAY, ".fini_array索引")) {
			return false;
		}

		Elf_Shdr shdr = {};
		if (!append_section_name(&shdr, ".fini_array")) {
			return false;
		}

		shdr.sh_type = SHT_FINI_ARRAY;
		shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
		if (!PointerToElfAddrOffset(base, si.fini_array, ".fini_array地址", &shdr.sh_addr)) {
			return false;
		}
		shdr.sh_offset = shdr.sh_addr;
		if (!checked_count_bytes(si.fini_array_count, sizeof(Elf_Addr), ".fini_array", &shdr.sh_size)) {
			return false;
		}
		shdr.sh_link = 0;
		shdr.sh_info = 0;
#ifdef __SO64__
		shdr.sh_addralign = 8;
#else
		shdr.sh_addralign = 4;
#endif
		shdr.sh_entsize = 0x0;

		shdrs.push_back(shdr);
	}

	// 生成.init_array节。
	if (si.init_array != nullptr) {
		if (!assign_section_index(&sINITARRAY, ".init_array索引")) {
			return false;
		}

		Elf_Shdr shdr = {};
		if (!append_section_name(&shdr, ".init_array")) {
			return false;
		}

		shdr.sh_type = SHT_INIT_ARRAY;
		shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
		if (!PointerToElfAddrOffset(base, si.init_array, ".init_array地址", &shdr.sh_addr)) {
			return false;
		}
		shdr.sh_offset = shdr.sh_addr;
		if (!checked_count_bytes(si.init_array_count, sizeof(Elf_Addr), ".init_array", &shdr.sh_size)) {
			return false;
		}
		shdr.sh_link = 0;
		shdr.sh_info = 0;
#ifdef __SO64__
		shdr.sh_addralign = 8;
#else
		shdr.sh_addralign = 4;
#endif
		shdr.sh_entsize = 0x0;

		shdrs.push_back(shdr);
	}

	// 生成.dynamic节。
	if (si.dynamic != nullptr) {
		if (!assign_section_index(&sDYNAMIC, ".dynamic索引")) {
			return false;
		}

		Elf_Shdr shdr = {};
		if (!append_section_name(&shdr, ".dynamic")) {
			return false;
		}

		shdr.sh_type = SHT_DYNAMIC;
		shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
		if (!PointerToElfAddrOffset(base, si.dynamic, ".dynamic地址", &shdr.sh_addr)) {
			return false;
		}
		shdr.sh_offset = shdr.sh_addr;
		if (!checked_count_bytes(si.dynamic_count, sizeof(Elf_Dyn), ".dynamic", &shdr.sh_size)) {
			return false;
		}
		shdr.sh_link = sDYNSTR;
		shdr.sh_info = 0;
#ifdef __SO64__
		shdr.sh_addralign = 8;
		shdr.sh_entsize = 0x10;
#else
		shdr.sh_addralign = 4;
		shdr.sh_entsize = 0x8;
#endif

		shdrs.push_back(shdr);
	}

	// 预留.got重建逻辑（当前关闭）。
	//    if(si.plt_got != nullptr) {
	//        // 全局偏移表
	//        sGOT = shdrs.size();
	//        auto sLast = sGOT - 1;
	//
	//        Elf_Shdr shdr;
	//        shdr.sh_name = shstrtab.length();
	//        shstrtab.append(".got");
	//        shstrtab.push_back('\0');
	//
	//        shdr.sh_type = SHT_PROGBITS;
	//        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
	//        shdr.sh_addr = shdrs[sLast].sh_addr + shdrs[sLast].sh_size;
	//        // 按8字节对齐
	//        while (shdr.sh_addr & 0x7) {
	//            shdr.sh_addr ++;
	//        }
	//
	//        shdr.sh_offset = shdr.sh_addr;
	//        shdr.sh_size = (uintptr_t)(si.plt_got + si.plt_rel_count) -
	//        shdr.sh_addr - (uintptr_t)base + 3 * sizeof(Elf_Addr); shdr.sh_link
	//        = 0; shdr.sh_info = 0;
	// #ifdef __SO64__
	//        shdr.sh_addralign = 8;
	// #else
	//        shdr.sh_addralign = 4;
	// #endif
	//        shdr.sh_entsize = 0x0;
	//
	//        shdrs.push_back(shdr);
	//    }

	// 生成.data节。
	if (true) {
		if (!assign_section_index(&sDATA, ".data索引")) {
			return false;
		}

		Elf_Shdr shdr = {};
		if (!append_section_name(&shdr, ".data")) {
			return false;
		}

		shdr.sh_type = SHT_PROGBITS;
		shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
		// 这里不能再使用“上一条已生成节”作为.data起点。
		// 原因如下：
		// 1）节的生成顺序是按“信息来源是否存在”拼接，不保证地址单调递增；
		// 2）如果上一条节地址较低，而更高地址的ALLOC节在更前面生成，
		//    旧算法会把.data起点放得过低，导致与高地址节重叠，再依赖后续裁剪兜底；
		// 3）重建应以“当前所有ALLOC节的最大结束地址”作为.data起点，避免顺序耦合。
		Elf_Addr data_start = 0;
		for (size_t idx = 1; idx < shdrs.size(); ++idx) {
			const Elf_Shdr& prev = shdrs[idx];
			if ((prev.sh_flags & SHF_ALLOC) == 0) {
				continue;
			}
			Elf_Addr prev_end = 0;
			if (!AddElfAddr(prev.sh_addr, prev.sh_size, &prev_end)) {
				FLOGE("无效ALLOC节区间：index=%zu addr=0x%" ADDRESS_FORMAT "x size=0x%" ADDRESS_FORMAT "x", idx,
					  prev.sh_addr, prev.sh_size);
				return false;
			}
			if (prev_end > data_start) {
				data_start = prev_end;
			}
		}
		shdr.sh_addr = data_start;
		shdr.sh_offset = shdr.sh_addr;
		// .data必须位于已加载镜像范围内。
		// 若data_start已经超过max_load，说明前面节边界推导出现矛盾：
		// 1）要么某个ALLOC节地址异常偏大；
		// 2）要么max_load被错误收缩。
		// 继续输出会得到“节头看似合法但区间越界”的结果，因此这里直接失败。
		if (shdr.sh_addr > si.max_load) {
			FLOGE("无效.data节区间：data_start=0x%" ADDRESS_FORMAT "x max_load=0x%" ADDRESS_FORMAT "x", shdr.sh_addr,
				  si.max_load);
			return false;
		}
		shdr.sh_size = si.max_load - shdr.sh_addr;
		shdr.sh_link = 0;
		shdr.sh_info = 0;
		shdr.sh_addralign = sizeof(Elf_Addr);
		shdr.sh_entsize = 0x0;

		shdrs.push_back(shdr);
	}

	// 预留.bss重建逻辑（当前关闭）。
	//    if(true) {
	//        sBSS = shdrs.size();
	//
	//        Elf_Shdr shdr;
	//        shdr.sh_name = shstrtab.length();
	//        shstrtab.append(".bss");
	//        shstrtab.push_back('\0');
	//
	//        shdr.sh_type = SHT_NOBITS;
	//        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
	//        shdr.sh_addr = si.max_load;
	//        shdr.sh_offset = shdr.sh_addr;
	//        shdr.sh_size = 0;   // 当前路径不使用
	//        shdr.sh_link = 0;
	//        shdr.sh_info = 0;
	//        shdr.sh_addralign = 8;
	//        shdr.sh_entsize = 0x0;
	//
	//        shdrs.push_back(shdr);
	//    }

	// 生成.shstrtab节并拼接到load区尾部。
	if (true) {
		if (!assign_section_index(&sSHSTRTAB, ".shstrtab索引")) {
			return false;
		}

		Elf_Shdr shdr = {};
		if (!append_section_name(&shdr, ".shstrtab")) {
			return false;
		}

		shdr.sh_type = SHT_STRTAB;
		shdr.sh_flags = 0;
		shdr.sh_addr = si.max_load;
		shdr.sh_offset = shdr.sh_addr;
		if (!SizeToElfAddr(shstrtab.length(), ".shstrtab大小", &shdr.sh_size)) {
			return false;
		}
		shdr.sh_link = 0;
		shdr.sh_info = 0;
		shdr.sh_addralign = 1;
		shdr.sh_entsize = 0x0;

		shdrs.push_back(shdr);
	}

	// 修复节之间的链接关系。

	// 按地址排序节头并同步修正内部索引。
	for (size_t i = 1; i < shdrs.size(); ++i) {
		for (size_t j = i + 1; j < shdrs.size(); ++j) {
			if (shdrs[i].sh_addr > shdrs[j].sh_addr) {
				// 交换两个节头条目。
				auto tmp = shdrs[i];
				shdrs[i] = shdrs[j];
				shdrs[j] = tmp;

				// 同步交换关联索引。
				auto chgIdx = [i, j](Elf_Word& t) {
					if (t == static_cast<Elf_Word>(i)) {
						t = static_cast<Elf_Word>(j);
					} else if (t == static_cast<Elf_Word>(j)) {
						t = static_cast<Elf_Word>(i);
					}
				};
				chgIdx(sDYNSYM);
				chgIdx(sDYNSTR);
				chgIdx(sHASH);
				chgIdx(sRELDYN);
				chgIdx(sRELADYN);
				chgIdx(sRELPLT);
				chgIdx(sPLT);
				chgIdx(sTEXTTAB);
				chgIdx(sARMEXIDX);
				chgIdx(sFINIARRAY);
				chgIdx(sINITARRAY);
				chgIdx(sDYNAMIC);
				chgIdx(sGOT);
				chgIdx(sDATA);
				chgIdx(sBSS);
				chgIdx(sSHSTRTAB);
			}
		}
	}
	if (sHASH != 0) {
		shdrs[sHASH].sh_link = sDYNSYM;
	}
	if (sRELDYN != 0) {
		shdrs[sRELDYN].sh_link = sDYNSYM;
	}
	if (sRELADYN != 0) {
		shdrs[sRELADYN].sh_link = sDYNSYM;
	}
	if (sRELPLT != 0) {
		shdrs[sRELPLT].sh_link = sDYNSYM;
	}
	if (sARMEXIDX != 0) {
		shdrs[sARMEXIDX].sh_link = sTEXTTAB;
	}
	if (sDYNAMIC != 0) {
		shdrs[sDYNAMIC].sh_link = sDYNSTR;
	}
	if (sDYNSYM != 0) {
		shdrs[sDYNSYM].sh_link = sDYNSTR;
	}

	if (sDYNSYM != 0) {
		auto sNext = sDYNSYM + 1;
		// .dynsym的节大小依赖“后一个节地址-当前节地址”推导。
		// 若排序被破坏或越界，继续计算会得到负跨度（在无符号下回绕成超大值），
		// 最终导致节表写入异常，必须在这里硬性拦截。
		if (sNext >= shdrs.size() || shdrs[sNext].sh_addr < shdrs[sDYNSYM].sh_addr) {
			FLOGE(".dynsym节顺序异常：dynsym_idx=%zu next_idx=%zu shdr_count=%zu dynsym_addr=0x%" ADDRESS_FORMAT
				  "x next_addr=0x%" ADDRESS_FORMAT "x",
				  static_cast<size_t>(sDYNSYM), static_cast<size_t>(sNext), shdrs.size(), shdrs[sDYNSYM].sh_addr,
				  sNext < shdrs.size() ? shdrs[sNext].sh_addr : static_cast<Elf_Addr>(0));
			return false;
		}
		shdrs[sDYNSYM].sh_size = shdrs[sNext].sh_addr - shdrs[sDYNSYM].sh_addr;
	}

	if (sTEXTTAB != 0) {
		auto sNext = sTEXTTAB + 1;
		// .text&ARM.extab同样依赖“下一个节地址”推导本节大小。
		// 这里与.dynsym保持同一防御口径，避免节大小被错误放大。
		if (sNext >= shdrs.size() || shdrs[sNext].sh_addr < shdrs[sTEXTTAB].sh_addr) {
			FLOGE(".text&ARM.extab节顺序异常：text_idx=%zu next_idx=%zu shdr_count=%zu text_addr=0x%" ADDRESS_FORMAT
				  "x next_addr=0x%" ADDRESS_FORMAT "x",
				  static_cast<size_t>(sTEXTTAB), static_cast<size_t>(sNext), shdrs.size(), shdrs[sTEXTTAB].sh_addr,
				  sNext < shdrs.size() ? shdrs[sNext].sh_addr : static_cast<Elf_Addr>(0));
			return false;
		}
		shdrs[sTEXTTAB].sh_size = shdrs[sNext].sh_addr - shdrs[sTEXTTAB].sh_addr;
	}

	// 纠正可能的节大小重叠
	for (size_t i = 2; i < shdrs.size(); ++i) {
		if (shdrs[i].sh_offset < shdrs[i - 1].sh_offset) {
			FLOGE("节偏移顺序错误：index=%zu prev_off=0x%" ADDRESS_FORMAT "x cur_off=0x%" ADDRESS_FORMAT "x", i,
				  shdrs[i - 1].sh_offset, shdrs[i].sh_offset);
			return false;
		}
		if (shdrs[i].sh_offset - shdrs[i - 1].sh_offset < shdrs[i - 1].sh_size) {
			shdrs[i - 1].sh_size = shdrs[i].sh_offset - shdrs[i - 1].sh_offset;
		}
	}

	FLOGD("=====================RebuildShdr End======================");
	return true;
}

// 重建主流程：先修程序头，再读SO信息，最后构造节表、重定位和输出。
bool ElfRebuilder::Rebuild() {
	// Rebuild被设计为“一次性流水线”入口。
	// 如果读取器尚未完成Load阶段，后续任何地址计算都可能落在未初始化内存上。
	// 因此这里把关键前置条件集中校验并尽早失败。
	if (elf_reader_ == nullptr) {
		FLOGE("重建器未绑定有效读取器实例：elf_reader=%p", elf_reader_);
		return false;
	}
	if (elf_reader_->load_bias() == nullptr) {
		FLOGE("读取器尚未完成加载：load_bias=%p loaded_phdr=%p phdr_count=%zu", elf_reader_->load_bias(),
			  elf_reader_->loaded_phdr(), elf_reader_->phdr_count());
		return false;
	}
	if (elf_reader_->loaded_phdr() == nullptr || elf_reader_->phdr_count() == 0) {
		FLOGE("读取器程序头状态无效：loaded_phdr=%p phdr_count=%zu", elf_reader_->loaded_phdr(),
			  elf_reader_->phdr_count());
		return false;
	}

	// 每次重建前都重置内部状态，避免复用同一实例时把上一次中间结果带入本次输出。
	// 这里重置的成员会在RebuildShdr/ReadSoInfo/RebuildFin中逐步回填。
	rebuild_size = 0;
	rebuild_data_.reset();
	shdrs.clear();
	shstrtab.clear();
	sDYNSYM = 0;
	sDYNSTR = 0;
	sHASH = 0;
	sRELDYN = 0;
	sRELADYN = 0;
	sRELPLT = 0;
	sPLT = 0;
	sTEXTTAB = 0;
	sARMEXIDX = 0;
	sFINIARRAY = 0;
	sINITARRAY = 0;
	sDYNAMIC = 0;
	sGOT = 0;
	sDATA = 0;
	sBSS = 0;
	sSHSTRTAB = 0;
	external_pointer = 0;
	return RebuildPhdr() && ReadSoInfo() && RebuildShdr() && RebuildRelocs() && RebuildFin();
}

// 从动态段提取重建所需信息，并做完整边界与一致性校验。
bool ElfRebuilder::ReadSoInfo() {
	FLOGD("=======================ReadSoInfo=========================");
	// 先清零soinfo，确保本轮解析仅依赖当前输入，不继承历史字段。
	si = soinfo{};
	si.base = si.load_bias = elf_reader_->load_bias();
	si.phdr = elf_reader_->loaded_phdr();
	si.phnum = elf_reader_->phdr_count();
	auto base = si.load_bias;
	// soinfo是后续节重建与重定位修复的唯一数据来源。
	// 这里先验证load_bias与phdr快照有效，避免在动态段扫描阶段出现空指针解引用。
	if (base == nullptr) {
		FLOGE("load_bias为空，无法解析soinfo：load_bias=%p phdr=%p phnum=%zu", base, si.phdr, si.phnum);
		return false;
	}
	if (si.phdr == nullptr || si.phnum == 0) {
		FLOGE("程序头信息无效：phdr=%p phnum=%zu", si.phdr, si.phnum);
		return false;
	}
	if (phdr_table_get_load_size(si.phdr, si.phnum, &si.min_load, &si.max_load) == 0) {
		FLOGE("可加载段范围无效：phdr=%p phnum=%zu", si.phdr, si.phnum);
		return false;
	}
	// 指针类校验同样采用“按PT_LOAD逐段覆盖”语义。
	// 这能避免符号表指针、动态段指针在段间空洞时被连续区间误判通过。
	auto pointer_in_load_segments = [this](const void* ptr, size_t size) -> bool {
		return PointerInLoadSegments(si.load_bias, ptr, size, si.phdr, si.phnum);
	};
	// 这里必须只使用“程序头推导出的可加载区间”作为地址合法性边界。
	// 读取器预留的pad_size仅用于内存缓冲写入，不代表ELF语义上的可加载区域。
	// 若把pad_size并入si.max_load，会在“-b预取但未实际回填”场景下放宽RangeInLoad，
	// 导致本应判越界的DT_*地址被错误接受。
	// 动态段真正回填成功时，ApplyDynamicSection会扩展末尾PT_LOAD，随后这里自然会反映到新边界。

	/* 提取动态段信息 */
	elf_reader_->get_dynamic_section(&si.dynamic, &si.dynamic_count, &si.dynamic_flags);
	if (si.dynamic == nullptr || si.dynamic_count == 0) {
		FLOGE("动态段程序头数据无效：dynamic=%p dynamic_count=%zu dynamic_flags=0x%x", si.dynamic, si.dynamic_count,
			  si.dynamic_flags);
		return false;
	}
	if (!pointer_in_load_segments(si.dynamic, sizeof(Elf_Dyn))) {
		// 这里只检查首个条目即可，因为后续扫描会再按dynamic_count做逐项边界约束。
		// 若首条已越界，说明动态段基址本身不可用，后续任何DT_*读取都没有意义。
		FLOGE("动态段指针越过可加载范围：dynamic=%p dynamic_count=%zu min_load=0x%" ADDRESS_FORMAT
			  "x max_load=0x%" ADDRESS_FORMAT "x phdr=%p phnum=%zu",
			  si.dynamic, si.dynamic_count, si.min_load, si.max_load, si.phdr, si.phnum);
		return false;
	}

	if (si.phnum > static_cast<size_t>(std::numeric_limits<int>::max())) {
		FLOGE("程序头数量超过接口上限：phnum=%zu", si.phnum);
		return false;
	}
	phdr_table_get_arm_exidx(si.phdr, static_cast<int>(si.phnum), si.base, &si.ARM_exidx, &si.ARM_exidx_count);

	// DT_*地址必须落在“某个PT_LOAD”中，而不是仅落在[min_load,max_load)连续区间。
	// 这可以阻断“段间空洞地址”被误判为合法的情况。
	auto range_in_load_segments = [this](Elf_Addr start, Elf_Addr size) -> bool {
		return RangeInLoadSegments(start, size, si.phdr, si.phnum);
	};

	// 从动态段收集关键元数据，先记录地址和值，后续统一做范围校验后再转指针。
	uint32_t needed_count = 0;
	Elf_Addr plt_rel_size_bytes = 0;
	Elf_Addr strtab_addr = 0;
	bool has_strtab = false;
	Elf_Addr symtab_addr = 0;
	bool has_symtab = false;
	Elf_Addr rel_addr = 0;
	bool has_rel = false;
	Elf_Addr rela_addr = 0;
	bool has_rela = false;
	Elf_Addr jmprel_addr = 0;
	bool has_jmprel = false;
	Elf_Addr pltgot_addr = 0;
	bool has_pltgot = false;
	Elf_Addr init_addr = 0;
	bool has_init = false;
	Elf_Addr fini_addr = 0;
	bool has_fini = false;
	Elf_Addr init_array_addr = 0;
	bool has_init_array = false;
	Elf_Addr fini_array_addr = 0;
	bool has_fini_array = false;
	Elf_Addr preinit_array_addr = 0;
	bool has_preinit_array = false;
	Elf_Addr syment = 0;
	bool has_syment = false;
	Elf_Addr relent = 0;
	bool has_relent = false;
	Elf_Addr relaent = 0;
	bool has_relaent = false;
	Elf_Word soname_off = 0;
	bool has_soname = false;
	for (size_t dyn_idx = 0; dyn_idx < si.dynamic_count; ++dyn_idx) {
		Elf_Dyn* d = si.dynamic + dyn_idx;
		if (d->d_tag == DT_NULL) {
			break;
		}
		// 第一阶段：只解析动态条目的原始值。
		switch (d->d_tag) {
			case DT_HASH: {
				// DT_HASH采用两阶段校验：
				// 阶段1：校验固定头部（nbucket/nchain）可访问；
				// 阶段2：基于头部值计算整表字节数，再校验整表范围。
				// 这样能同时拦截“表头越界”和“头部合法但尺寸字段被篡改”的两类输入。
				Elf_Addr hash_addr = d->d_un.d_ptr;
				Elf_Addr hash_head_size = static_cast<Elf_Addr>(2 * sizeof(Elf_Word));
				if (!range_in_load_segments(hash_addr, hash_head_size)) {
					FLOGE("DT_HASH表头越界：hash_addr=0x%" ADDRESS_FORMAT "x head_size=0x%" ADDRESS_FORMAT
						  "x（未被任何PT_LOAD覆盖）",
						  hash_addr, hash_head_size);
					return false;
				}
				// 动态段里的地址不保证按主机字长对齐，不能直接转成unsigned*解引用。
				// 这里按ELF定义读取两个Elf_Word头字段，避免在严格对齐架构上触发未定义行为。
				Elf_Word hash_meta[2] = {0, 0};
				memcpy(hash_meta, base + hash_addr, sizeof(hash_meta));
				const size_t nbucket = static_cast<size_t>(hash_meta[0]);
				const size_t nchain = static_cast<size_t>(hash_meta[1]);
				size_t total_words = 0;
				if (!AddSizeT(nbucket, nchain, &total_words) || !AddSizeT(total_words, 2, &total_words)) {
					FLOGE("DT_HASH表项数量溢出：nbucket=%zu nchain=%zu", nbucket, nchain);
					return false;
				}
				Elf_Addr hash_table_bytes = 0;
				if (!CountToBytes(total_words, sizeof(Elf_Word), &hash_table_bytes) ||
					!range_in_load_segments(hash_addr, hash_table_bytes)) {
					FLOGE("DT_HASH表大小无效或越界：hash_addr=0x%" ADDRESS_FORMAT
						  "x total_words=%zu bytes=0x%" ADDRESS_FORMAT "x（未被单个PT_LOAD完整覆盖）",
						  hash_addr, total_words, hash_table_bytes);
					return false;
				}
				Elf_Addr bucket_addr = 0;
				if (!AddElfAddr(hash_addr, static_cast<Elf_Addr>(2 * sizeof(Elf_Word)), &bucket_addr)) {
					FLOGE("DT_HASH桶表地址溢出：hash_addr=0x%" ADDRESS_FORMAT "x", hash_addr);
					return false;
				}
				si.hash = base + hash_addr;
				si.nbucket = nbucket;
				si.nchain = nchain;
				si.bucket = reinterpret_cast<unsigned*>(base + bucket_addr);
				si.chain = si.bucket + si.nbucket;
				break;
			}
			case DT_STRTAB:
				strtab_addr = d->d_un.d_ptr;
				has_strtab = true;
				FLOGD("string table found at %" ADDRESS_FORMAT "x", d->d_un.d_ptr);
				break;
			case DT_SYMTAB:
				symtab_addr = d->d_un.d_ptr;
				has_symtab = true;
				FLOGD("symbol table found at %" ADDRESS_FORMAT "x", d->d_un.d_ptr);
				break;
			case DT_PLTREL:
				if (d->d_un.d_val > static_cast<Elf_Addr>(std::numeric_limits<uint32_t>::max())) {
					FLOGE("DT_PLTREL值过大：value=0x%" ADDRESS_FORMAT "x", d->d_un.d_val);
					return false;
				}
				si.plt_type = static_cast<uint32_t>(d->d_un.d_val);
				break;
			case DT_JMPREL:
				jmprel_addr = d->d_un.d_ptr;
				has_jmprel = true;
				FLOGD("%s plt_rel (DT_JMPREL) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
				break;
			case DT_PLTRELSZ:
				plt_rel_size_bytes = d->d_un.d_val;
				break;
			case DT_REL:
				rel_addr = d->d_un.d_ptr;
				has_rel = true;
				FLOGD("%s rel (DT_REL) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
				break;
			case DT_RELSZ:
				if (!BytesToCount(d->d_un.d_val, sizeof(Elf_Rel), &si.rel_count)) {
					FLOGE("DT_RELSZ与Elf_Rel大小不对齐：relsz=0x%" ADDRESS_FORMAT "x rel_size=%zu", d->d_un.d_val,
						  sizeof(Elf_Rel));
					return false;
				}
				FLOGD("%s rel_size (DT_RELSZ) %zu", si.name, si.rel_count);
				break;
			case DT_PLTGOT:
				/* 预留给延迟绑定路径，当前仅记录地址，不启用。 */
				pltgot_addr = d->d_un.d_ptr;
				has_pltgot = true;
				break;
			case DT_DEBUG:
				// 预留：若动态段可写，可在此回填调试器所需地址。
				break;
			case DT_RELA:
				rela_addr = d->d_un.d_ptr;
				has_rela = true;
				break;
			case DT_RELASZ:
				// 历史命名沿用plt_rela_count，实际承载的是DT_RELA表项数量。
				if (!BytesToCount(d->d_un.d_val, sizeof(Elf_Rela), &si.plt_rela_count)) {
					FLOGE("DT_RELASZ与Elf_Rela大小不对齐：relasz=0x%" ADDRESS_FORMAT "x rela_size=%zu", d->d_un.d_val,
						  sizeof(Elf_Rela));
					return false;
				}
				break;
			case DT_INIT:
				init_addr = d->d_un.d_ptr;
				has_init = true;
				FLOGD("%s constructors (DT_INIT) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
				break;
			case DT_FINI:
				fini_addr = d->d_un.d_ptr;
				has_fini = true;
				FLOGD("%s destructors (DT_FINI) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
				break;
			case DT_INIT_ARRAY:
				init_array_addr = d->d_un.d_ptr;
				has_init_array = true;
				FLOGD("%s constructors (DT_INIT_ARRAY) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
				break;
			case DT_INIT_ARRAYSZ:
				if (!BytesToCount(d->d_un.d_val, sizeof(Elf_Addr), &si.init_array_count)) {
					FLOGE("DT_INIT_ARRAYSZ与Elf_Addr大小不对齐：init_arraysz=0x%" ADDRESS_FORMAT "x addr_size=%zu",
						  d->d_un.d_val, sizeof(Elf_Addr));
					return false;
				}
				FLOGD("%s constructors (DT_INIT_ARRAYSZ) %zu", si.name, si.init_array_count);
				break;
			case DT_FINI_ARRAY:
				fini_array_addr = d->d_un.d_ptr;
				has_fini_array = true;
				FLOGD("%s destructors (DT_FINI_ARRAY) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
				break;
			case DT_FINI_ARRAYSZ:
				if (!BytesToCount(d->d_un.d_val, sizeof(Elf_Addr), &si.fini_array_count)) {
					FLOGE("DT_FINI_ARRAYSZ与Elf_Addr大小不对齐：fini_arraysz=0x%" ADDRESS_FORMAT "x addr_size=%zu",
						  d->d_un.d_val, sizeof(Elf_Addr));
					return false;
				}
				FLOGD("%s destructors (DT_FINI_ARRAYSZ) %zu", si.name, si.fini_array_count);
				break;
			case DT_PREINIT_ARRAY:
				preinit_array_addr = d->d_un.d_ptr;
				has_preinit_array = true;
				FLOGD("%s constructors (DT_PREINIT_ARRAY) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
				break;
			case DT_PREINIT_ARRAYSZ:
				if (!BytesToCount(d->d_un.d_val, sizeof(Elf_Addr), &si.preinit_array_count)) {
					FLOGE("DT_PREINIT_ARRAYSZ与Elf_Addr大小不对齐：preinit_arraysz=0x%" ADDRESS_FORMAT
						  "x addr_size=%zu",
						  d->d_un.d_val, sizeof(Elf_Addr));
					return false;
				}
				FLOGD("%s constructors (DT_PREINIT_ARRAYSZ) %zu", si.name, si.preinit_array_count);
				break;
			case DT_TEXTREL:
				si.has_text_relocations = true;
				break;
			case DT_SYMBOLIC:
				si.has_DT_SYMBOLIC = true;
				break;
			case DT_NEEDED:
				++needed_count;
				break;
			case DT_FLAGS:
				if (d->d_un.d_val & DF_TEXTREL) {
					si.has_text_relocations = true;
				}
				if (d->d_un.d_val & DF_SYMBOLIC) {
					si.has_DT_SYMBOLIC = true;
				}
				break;
			case DT_STRSZ:
				si.strtabsize = d->d_un.d_val;
				break;
			case DT_SYMENT:
				syment = d->d_un.d_val;
				has_syment = true;
				break;
			case DT_RELENT:
				relent = d->d_un.d_val;
				has_relent = true;
				break;
			case DT_RELAENT:
				relaent = d->d_un.d_val;
				has_relaent = true;
				break;
			case DT_MIPS_RLD_MAP:
				// 预留：MIPS调试映射项处理。
				break;
			case DT_MIPS_RLD_VERSION:
			case DT_MIPS_FLAGS:
			case DT_MIPS_BASE_ADDRESS:
			case DT_MIPS_UNREFEXTNO:
				break;

			case DT_MIPS_SYMTABNO:
				if (d->d_un.d_val > static_cast<Elf_Addr>(std::numeric_limits<unsigned>::max())) {
					FLOGE("DT_MIPS_SYMTABNO值过大：value=0x%" ADDRESS_FORMAT "x", d->d_un.d_val);
					return false;
				}
				si.mips_symtabno = static_cast<unsigned>(d->d_un.d_val);
				break;

			case DT_MIPS_LOCAL_GOTNO:
				if (d->d_un.d_val > static_cast<Elf_Addr>(std::numeric_limits<unsigned>::max())) {
					FLOGE("DT_MIPS_LOCAL_GOTNO值过大：value=0x%" ADDRESS_FORMAT "x", d->d_un.d_val);
					return false;
				}
				si.mips_local_gotno = static_cast<unsigned>(d->d_un.d_val);
				break;

			case DT_MIPS_GOTSYM:
				if (d->d_un.d_val > static_cast<Elf_Addr>(std::numeric_limits<unsigned>::max())) {
					FLOGE("DT_MIPS_GOTSYM值过大：value=0x%" ADDRESS_FORMAT "x", d->d_un.d_val);
					return false;
				}
				si.mips_gotsym = static_cast<unsigned>(d->d_un.d_val);
				break;
			case DT_SONAME:
				if (d->d_un.d_val > static_cast<Elf_Addr>(std::numeric_limits<Elf_Word>::max())) {
					FLOGE("DT_SONAME偏移值过大：value=0x%" ADDRESS_FORMAT "x", d->d_un.d_val);
					return false;
				}
				soname_off = static_cast<Elf_Word>(d->d_un.d_val);
				has_soname = true;
				break;
			default:
				FLOGD("Unused DT entry: type 0x%08" ADDRESS_FORMAT "x arg 0x%08" ADDRESS_FORMAT "x", d->d_tag,
					  d->d_un.d_val);
				break;
		}
	}
	if (has_strtab) {
		// 第二阶段：统一做范围校验后再转成可访问指针。
		if (si.strtabsize == 0 || si.strtabsize > static_cast<size_t>(std::numeric_limits<Elf_Addr>::max()) ||
			!range_in_load_segments(strtab_addr, static_cast<Elf_Addr>(si.strtabsize))) {
			FLOGE("DT_STRTAB范围无效：strtab_addr=0x%" ADDRESS_FORMAT "x strtab_size=%zu min_load=0x%" ADDRESS_FORMAT
				  "x max_load=0x%" ADDRESS_FORMAT "x",
				  strtab_addr, si.strtabsize, si.min_load, si.max_load);
			return false;
		}
		si.strtab = reinterpret_cast<const char*>(base + strtab_addr);
	}
	if (has_symtab) {
		if (!range_in_load_segments(symtab_addr, static_cast<Elf_Addr>(sizeof(Elf_Sym)))) {
			FLOGE("DT_SYMTAB地址无效：symtab_addr=0x%" ADDRESS_FORMAT "x sym_size=%zu min_load=0x%" ADDRESS_FORMAT
				  "x max_load=0x%" ADDRESS_FORMAT "x",
				  symtab_addr, sizeof(Elf_Sym), si.min_load, si.max_load);
			return false;
		}
		si.symtab = reinterpret_cast<Elf_Sym*>(base + symtab_addr);
	}
	if (has_pltgot) {
		if (!range_in_load_segments(pltgot_addr, static_cast<Elf_Addr>(sizeof(Elf_Addr)))) {
			FLOGE("DT_PLTGOT地址无效：pltgot_addr=0x%" ADDRESS_FORMAT "x addr_size=%zu min_load=0x%"
				  ADDRESS_FORMAT "x max_load=0x%" ADDRESS_FORMAT "x",
				  pltgot_addr, sizeof(Elf_Addr), si.min_load, si.max_load);
			return false;
		}
		si.plt_got = reinterpret_cast<Elf_Addr*>(base + pltgot_addr);
	}
	if (has_init) {
		if (!range_in_load_segments(init_addr, 1)) {
			FLOGE("DT_INIT地址无效：init_addr=0x%" ADDRESS_FORMAT "x min_load=0x%" ADDRESS_FORMAT
				  "x max_load=0x%" ADDRESS_FORMAT "x",
				  init_addr, si.min_load, si.max_load);
			return false;
		}
		si.init_func = reinterpret_cast<void*>(base + init_addr);
	}
	if (has_fini) {
		if (!range_in_load_segments(fini_addr, 1)) {
			FLOGE("DT_FINI地址无效：fini_addr=0x%" ADDRESS_FORMAT "x min_load=0x%" ADDRESS_FORMAT
				  "x max_load=0x%" ADDRESS_FORMAT "x",
				  fini_addr, si.min_load, si.max_load);
			return false;
		}
		si.fini_func = reinterpret_cast<void*>(base + fini_addr);
	}
	if (has_init_array) {
		Elf_Addr init_array_bytes = 0;
		if (!CountToBytes(si.init_array_count, sizeof(Elf_Addr), &init_array_bytes)) {
			FLOGE("DT_INIT_ARRAY大小无效：count=%zu elem_size=%zu", si.init_array_count, sizeof(Elf_Addr));
			return false;
		}
		if (!range_in_load_segments(init_array_addr, init_array_bytes)) {
			FLOGE("DT_INIT_ARRAY范围无效：addr=0x%" ADDRESS_FORMAT "x bytes=0x%" ADDRESS_FORMAT
				  "x min_load=0x%" ADDRESS_FORMAT "x max_load=0x%" ADDRESS_FORMAT "x",
				  init_array_addr, init_array_bytes, si.min_load, si.max_load);
			return false;
		}
		si.init_array = reinterpret_cast<void**>(base + init_array_addr);
	}
	if (has_fini_array) {
		Elf_Addr fini_array_bytes = 0;
		if (!CountToBytes(si.fini_array_count, sizeof(Elf_Addr), &fini_array_bytes)) {
			FLOGE("DT_FINI_ARRAY大小无效：count=%zu elem_size=%zu", si.fini_array_count, sizeof(Elf_Addr));
			return false;
		}
		if (!range_in_load_segments(fini_array_addr, fini_array_bytes)) {
			FLOGE("DT_FINI_ARRAY范围无效：addr=0x%" ADDRESS_FORMAT "x bytes=0x%" ADDRESS_FORMAT
				  "x min_load=0x%" ADDRESS_FORMAT "x max_load=0x%" ADDRESS_FORMAT "x",
				  fini_array_addr, fini_array_bytes, si.min_load, si.max_load);
			return false;
		}
		si.fini_array = reinterpret_cast<void**>(base + fini_array_addr);
	}
	if (has_preinit_array) {
		Elf_Addr preinit_array_bytes = 0;
		if (!CountToBytes(si.preinit_array_count, sizeof(Elf_Addr), &preinit_array_bytes)) {
			FLOGE("DT_PREINIT_ARRAY大小无效：count=%zu elem_size=%zu", si.preinit_array_count, sizeof(Elf_Addr));
			return false;
		}
		if (!range_in_load_segments(preinit_array_addr, preinit_array_bytes)) {
			FLOGE("DT_PREINIT_ARRAY范围无效：addr=0x%" ADDRESS_FORMAT "x bytes=0x%" ADDRESS_FORMAT
				  "x min_load=0x%" ADDRESS_FORMAT "x max_load=0x%" ADDRESS_FORMAT "x",
				  preinit_array_addr, preinit_array_bytes, si.min_load, si.max_load);
			return false;
		}
		si.preinit_array = reinterpret_cast<void**>(base + preinit_array_addr);
	}
	if (has_soname) {
		if (StringOffsetValid(si.strtab, si.strtabsize, soname_off)) {
			si.name = si.strtab + soname_off;
			FLOGD("soname %s", si.name);
		} else {
			FLOGW("忽略无效DT_SONAME偏移：soname_off=0x%x strtab=%p strtab_size=%zu", soname_off, si.strtab,
				  si.strtabsize);
		}
	}
	if (has_syment && syment != sizeof(Elf_Sym)) {
		FLOGE("DT_SYMENT不受支持：value=%" ADDRESS_FORMAT "u expected=%zu", syment, sizeof(Elf_Sym));
		return false;
	}
	if (has_relent && relent != sizeof(Elf_Rel)) {
		FLOGE("DT_RELENT不受支持：value=%" ADDRESS_FORMAT "u expected=%zu", relent, sizeof(Elf_Rel));
		return false;
	}
	if (has_relaent && relaent != sizeof(Elf_Rela)) {
		FLOGE("DT_RELAENT不受支持：value=%" ADDRESS_FORMAT "u expected=%zu", relaent, sizeof(Elf_Rela));
		return false;
	}
	// 关键动态元数据必须成对出现，否则后续重建会进入“地址存在但语义不完整”的状态。
	// 这里直接失败而不是继续容错，原因如下：
	// 1）.dynsym离不开.dynstr：符号名解析、导入槽映射都依赖字符串表；
	// 2）重定位/哈希离不开.symtab：没有符号表时，导入与链接关系无法稳定恢复；
	// 3）继续执行会生成“可输出但不可信”的结果，排查成本更高。
	if (has_symtab && !has_strtab) {
		FLOGE("动态段不完整：存在DT_SYMTAB但缺少DT_STRTAB/DT_STRSZ，symtab_addr=0x%" ADDRESS_FORMAT
			  "x strtab_addr=0x%" ADDRESS_FORMAT "x strtab_size=%zu",
			  symtab_addr, strtab_addr, si.strtabsize);
		return false;
	}
	if (!has_symtab && (has_rel || has_rela || has_jmprel || si.hash != nullptr)) {
		FLOGE("动态段不完整：存在重定位或哈希信息但缺少DT_SYMTAB，has_rel=%d has_rela=%d has_jmprel=%d has_hash=%d",
			  has_rel ? 1 : 0, has_rela ? 1 : 0, has_jmprel ? 1 : 0, si.hash != nullptr ? 1 : 0);
		return false;
	}
	if ((has_jmprel || plt_rel_size_bytes != 0) && si.plt_type != DT_REL && si.plt_type != DT_RELA) {
		FLOGE("Unsupported DT_PLTREL type: 0x%" ADDRESS_FORMAT "x", static_cast<Elf_Addr>(si.plt_type));
		return false;
	}
	if (plt_rel_size_bytes != 0) {
		if (si.plt_type == DT_RELA) {
			if (!BytesToCount(plt_rel_size_bytes, sizeof(Elf_Rela), &si.plt_rel_count)) {
				FLOGE("DT_PLTRELSZ与RELA项大小不对齐：pltrelsz=0x%" ADDRESS_FORMAT "x rela_size=%zu",
					  plt_rel_size_bytes, sizeof(Elf_Rela));
				return false;
			}
		} else if (si.plt_type == DT_REL) {
			if (!BytesToCount(plt_rel_size_bytes, sizeof(Elf_Rel), &si.plt_rel_count)) {
				FLOGE("DT_PLTRELSZ与REL项大小不对齐：pltrelsz=0x%" ADDRESS_FORMAT "x rel_size=%zu",
					  plt_rel_size_bytes, sizeof(Elf_Rel));
				return false;
			}
		} else {
			FLOGE("Unsupported DT_PLTREL type: 0x%" ADDRESS_FORMAT "x", static_cast<Elf_Addr>(si.plt_type));
			return false;
		}
		FLOGD("%s plt_rel_count (DT_PLTRELSZ) %zu", si.name, si.plt_rel_count);
	}
	if (si.rel_count != 0) {
		// 仅在声明了有效数量时，要求对应地址存在且范围完整。
		if (!has_rel) {
			FLOGE("动态段不完整：存在DT_RELSZ但缺少DT_REL，rel_count=%zu", si.rel_count);
			return false;
		}
		Elf_Addr rel_bytes = 0;
		if (!CountToBytes(si.rel_count, sizeof(Elf_Rel), &rel_bytes) || !range_in_load_segments(rel_addr, rel_bytes)) {
			FLOGE("DT_REL范围无效：rel_addr=0x%" ADDRESS_FORMAT "x rel_count=%zu rel_bytes=0x%" ADDRESS_FORMAT
				  "x min_load=0x%" ADDRESS_FORMAT "x max_load=0x%" ADDRESS_FORMAT "x",
				  rel_addr, si.rel_count, rel_bytes, si.min_load, si.max_load);
			return false;
		}
		si.rel = reinterpret_cast<Elf_Rel*>(base + rel_addr);
	} else if (has_rel) {
		if (!range_in_load_segments(rel_addr, static_cast<Elf_Addr>(sizeof(Elf_Rel)))) {
			FLOGE("DT_REL地址无效：rel_addr=0x%" ADDRESS_FORMAT "x rel_size=%zu min_load=0x%" ADDRESS_FORMAT
				  "x max_load=0x%" ADDRESS_FORMAT "x",
				  rel_addr, sizeof(Elf_Rel), si.min_load, si.max_load);
			return false;
		}
		si.rel = reinterpret_cast<Elf_Rel*>(base + rel_addr);
	}
	if (si.plt_rela_count != 0) {
		// 同步校验RELA主重定位表。
		if (!has_rela) {
			FLOGE("动态段不完整：存在DT_RELASZ但缺少DT_RELA，rela_count=%zu", si.plt_rela_count);
			return false;
		}
		Elf_Addr rela_bytes = 0;
		if (!CountToBytes(si.plt_rela_count, sizeof(Elf_Rela), &rela_bytes) ||
			!range_in_load_segments(rela_addr, rela_bytes)) {
			FLOGE("DT_RELA范围无效：rela_addr=0x%" ADDRESS_FORMAT "x rela_count=%zu rela_bytes=0x%" ADDRESS_FORMAT
				  "x min_load=0x%" ADDRESS_FORMAT "x max_load=0x%" ADDRESS_FORMAT "x",
				  rela_addr, si.plt_rela_count, rela_bytes, si.min_load, si.max_load);
			return false;
		}
		si.plt_rela = reinterpret_cast<Elf_Rela*>(base + rela_addr);
	} else if (has_rela) {
		if (!range_in_load_segments(rela_addr, static_cast<Elf_Addr>(sizeof(Elf_Rela)))) {
			FLOGE("DT_RELA地址无效：rela_addr=0x%" ADDRESS_FORMAT "x rela_size=%zu min_load=0x%" ADDRESS_FORMAT
				  "x max_load=0x%" ADDRESS_FORMAT "x",
				  rela_addr, sizeof(Elf_Rela), si.min_load, si.max_load);
			return false;
		}
		si.plt_rela = reinterpret_cast<Elf_Rela*>(base + rela_addr);
	}
	if (si.plt_rel_count != 0) {
		// 校验PLT重定位条目类型、长度和范围。
		if (!has_jmprel) {
			FLOGE("动态段不完整：存在DT_PLTRELSZ但缺少DT_JMPREL，plt_rel_count=%zu", si.plt_rel_count);
			return false;
		}
		size_t plt_ent_size = 0;
		if (si.plt_type == DT_RELA) {
			plt_ent_size = sizeof(Elf_Rela);
		} else if (si.plt_type == DT_REL) {
			plt_ent_size = sizeof(Elf_Rel);
		} else {
			FLOGE("Unsupported DT_PLTREL type: 0x%" ADDRESS_FORMAT "x", static_cast<Elf_Addr>(si.plt_type));
			return false;
		}
		Elf_Addr plt_bytes = 0;
		if (!CountToBytes(si.plt_rel_count, plt_ent_size, &plt_bytes) ||
			!range_in_load_segments(jmprel_addr, plt_bytes)) {
			FLOGE("DT_JMPREL范围无效：jmprel_addr=0x%" ADDRESS_FORMAT "x plt_rel_count=%zu plt_ent_size=%zu bytes=0x%"
				  ADDRESS_FORMAT "x min_load=0x%" ADDRESS_FORMAT "x max_load=0x%" ADDRESS_FORMAT "x",
				  jmprel_addr, si.plt_rel_count, plt_ent_size, plt_bytes, si.min_load, si.max_load);
			return false;
		}
		si.plt_rel = reinterpret_cast<Elf_Rel*>(base + jmprel_addr);
	} else if (has_jmprel) {
		// DT_JMPREL存在但DT_PLTRELSZ为0时，仍需做最小探测。
		// 探测大小必须跟随DT_PLTREL类型：
		// - DT_REL  -> sizeof(Elf_Rel)
		// - DT_RELA -> sizeof(Elf_Rela)
		// 否则在RELA场景会按更小的REL尺寸误判通过，掩盖边界问题。
		Elf_Addr jmprel_probe_bytes = static_cast<Elf_Addr>(sizeof(Elf_Rel));
		if (si.plt_type == DT_RELA) {
			jmprel_probe_bytes = static_cast<Elf_Addr>(sizeof(Elf_Rela));
		}
		if (!range_in_load_segments(jmprel_addr, jmprel_probe_bytes)) {
			FLOGE("DT_JMPREL地址无效：jmprel_addr=0x%" ADDRESS_FORMAT "x probe_bytes=0x%" ADDRESS_FORMAT
				  "x plt_type=0x%" ADDRESS_FORMAT "x min_load=0x%" ADDRESS_FORMAT "x max_load=0x%" ADDRESS_FORMAT "x",
				  jmprel_addr, jmprel_probe_bytes, static_cast<Elf_Addr>(si.plt_type), si.min_load, si.max_load);
			return false;
		}
		si.plt_rel = reinterpret_cast<Elf_Rel*>(base + jmprel_addr);
	}
	(void)needed_count;
	FLOGD("=======================ReadSoInfo End=========================");
	return true;
}

// 组装最终重建产物：加载段数据＋.shstrtab＋节头表。
bool ElfRebuilder::RebuildFin() {
	FLOGD(
		"=======================try to finish file rebuild "
		"=========================");
	// RebuildFin负责把“内存镜像＋节名字串＋节头表”拼成最终ELF字节流。
	// 这里的边界校验必须严格，否则会把前面步骤的中间错误放大成输出损坏或越界访问。
	if (si.load_bias == nullptr) {
		FLOGE("soinfo加载基址为空，无法拼接输出：load_bias=%p", si.load_bias);
		return false;
	}
	if (shdrs.empty()) {
		FLOGE("节头表为空，无法拼接输出：shdr_count=%zu", shdrs.size());
		return false;
	}
	if (si.max_load < si.min_load) {
		FLOGE("加载范围无效：min_load=0x%" ADDRESS_FORMAT "x max_load=0x%" ADDRESS_FORMAT "x", si.min_load,
			  si.max_load);
		return false;
	}
	if (si.max_load > static_cast<Elf_Addr>(std::numeric_limits<size_t>::max())) {
		FLOGE("加载上界超出size_t范围：max_load=0x%" ADDRESS_FORMAT "x max_size_t=0x%zx", si.max_load,
			  std::numeric_limits<size_t>::max());
		return false;
	}
	const auto load_size = static_cast<size_t>(si.max_load - si.min_load);
	const auto file_load_end = static_cast<size_t>(si.max_load);
	const auto shstr_size = shstrtab.length();
	if (shdrs.size() > std::numeric_limits<size_t>::max() / sizeof(Elf_Shdr)) {
		FLOGE("节头表大小溢出：shdr_count=%zu shdr_size=%zu", shdrs.size(), sizeof(Elf_Shdr));
		return false;
	}
	const auto shdr_bytes = shdrs.size() * sizeof(Elf_Shdr);
	if (file_load_end > std::numeric_limits<size_t>::max() - shstr_size - shdr_bytes) {
		FLOGE("重建缓冲总大小溢出：file_load_end=0x%zx shstr_size=0x%zx shdr_bytes=0x%zx", file_load_end, shstr_size,
			  shdr_bytes);
		return false;
	}
	// 输出布局说明：
	// [0, file_load_end)                   -> 已加载镜像对应的文件区
	// [file_load_end, shdr_off)            -> .shstrtab
	// [shdr_off, shdr_off + shdr_bytes)    -> 节头表
	rebuild_size = file_load_end + shstr_size + shdr_bytes;
	const auto min_load = static_cast<size_t>(si.min_load);
	if (min_load > rebuild_size || load_size > rebuild_size - min_load) {
		FLOGE("镜像拷贝范围无效：min_load=0x%zx load_size=0x%zx rebuild_size=0x%zx", min_load, load_size, rebuild_size);
		return false;
	}
	rebuild_data_.reset();
	rebuild_data_ = std::unique_ptr<uint8_t[]>(new (std::nothrow) uint8_t[rebuild_size]);
	if (rebuild_data_ == nullptr) {
		FLOGE("重建输出内存分配失败：rebuild_size=0x%zx", rebuild_size);
		return false;
	}
	auto* rebuild_data = rebuild_data_.get();
	memset(rebuild_data, 0, rebuild_size);
	// 计算源地址时显式拆分为“基址＋偏移”，并在加法前做上限校验。
	// 这样可同时覆盖32位与64位构建，避免整数回绕后memcpy读取错误源地址。
	const auto load_bias_addr = reinterpret_cast<uintptr_t>(si.load_bias);
	const auto min_load_addr = static_cast<uintptr_t>(si.min_load);
	if (load_bias_addr > std::numeric_limits<uintptr_t>::max() - min_load_addr) {
		FLOGE("加载数据源地址溢出：load_bias=0x%llx min_load=0x%" ADDRESS_FORMAT "x",
			  static_cast<unsigned long long>(load_bias_addr), si.min_load);
		return false;
	}
	const auto source_addr = load_bias_addr + min_load_addr;
	auto* source = reinterpret_cast<const void*>(source_addr);
	// 仅拷贝[min_load,max_load)对应的数据区，前导空洞由memset维持为0。
	memcpy(rebuild_data + min_load, source, load_size);
	// 追加节名字串表。
	if (shstr_size != 0) {
		memcpy(rebuild_data + file_load_end, shstrtab.c_str(), shstr_size);
	}
	// 追加节头表。
	const auto shdr_off = file_load_end + shstr_size;
	if (shdr_bytes != 0) {
		memcpy(rebuild_data + shdr_off, shdrs.data(), shdr_bytes);
	}
	// 全量校验节头落盘区间，避免输出“节头可读但区间越界”的损坏文件。
	// 校验口径：
	// 1）SHT_NOBITS不占用文件空间，可跳过文件区间检查；
	// 2）其余节若sh_size>0，必须满足[sh_offset, sh_offset+sh_size)落在rebuild_size内；
	// 3）对每个节逐一给出索引/类型/偏移/大小，便于定位问题输入。
	for (size_t i = 0; i < shdrs.size(); ++i) {
		const Elf_Shdr& shdr = shdrs[i];
		if (shdr.sh_type == SHT_NOBITS || shdr.sh_size == 0) {
			continue;
		}
		const size_t sec_off = static_cast<size_t>(shdr.sh_offset);
		const size_t sec_size = static_cast<size_t>(shdr.sh_size);
		if (sec_off > rebuild_size) {
			FLOGE("节区间越界：index=%zu type=0x%x offset=0x%" ADDRESS_FORMAT "x size=0x%" ADDRESS_FORMAT
				  "x rebuild_size=0x%zx",
				  i, shdr.sh_type, shdr.sh_offset, shdr.sh_size, rebuild_size);
			return false;
		}
		if (sec_size > rebuild_size - sec_off) {
			FLOGE("节大小越界：index=%zu type=0x%x offset=0x%" ADDRESS_FORMAT "x size=0x%" ADDRESS_FORMAT
				  "x rebuild_size=0x%zx",
				  i, shdr.sh_type, shdr.sh_offset, shdr.sh_size, rebuild_size);
			return false;
		}
	}
	auto ehdr = *elf_reader_->record_ehdr();
	ehdr.e_type = ET_DYN;
	if (shdrs.size() > static_cast<size_t>(std::numeric_limits<decltype(ehdr.e_shnum)>::max())) {
		FLOGE("节头数量超出ELF头字段范围：count=%zu", shdrs.size());
		return false;
	}
	ehdr.e_shnum = static_cast<decltype(ehdr.e_shnum)>(shdrs.size());
	// ELF头中的e_shoff字段是Elf_Addr。
	// 先校验size_t偏移可安全收窄到Elf_Addr，再写入头字段，避免生成截断的节头偏移。
	if (shdr_off > static_cast<size_t>(std::numeric_limits<Elf_Addr>::max())) {
		FLOGE("节头表偏移超出Elf_Addr范围：offset=%zu", shdr_off);
		return false;
	}
	ehdr.e_shoff = static_cast<Elf_Addr>(shdr_off);
	if (sSHSTRTAB > static_cast<Elf_Word>(std::numeric_limits<decltype(ehdr.e_shstrndx)>::max())) {
		FLOGE("节名字串表索引超出ELF头字段范围：index=%u", static_cast<unsigned>(sSHSTRTAB));
		return false;
	}
	ehdr.e_shstrndx = static_cast<decltype(ehdr.e_shstrndx)>(sSHSTRTAB);
	memcpy(rebuild_data, &ehdr, sizeof(Elf_Ehdr));

	FLOGD("=======================End=========================");
	return true;
}

template <bool isRela>
// 按重定位类型修正目标地址。
// 规则：REL相对重定位先减转储基址；导入重定位映射到导入槽；RELA场景再按addend覆盖特定相对类型。
void ElfRebuilder::relocate(uint8_t* base, Elf_Rel* rel, Elf_Addr dump_base) {
	if (rel == nullptr) {
		FLOGW("重定位条目为空，已跳过");
		return;
	}
	if (si.max_load < sizeof(Elf_Addr)) {
		FLOGW("重定位目标校验失败：max_load过小，max_load=0x%" ADDRESS_FORMAT "x addr_size=%zu", si.max_load,
			  sizeof(Elf_Addr));
		return;
	}
	if (rel->r_offset < si.min_load) {
		FLOGW("重定位偏移低于最小加载地址：r_offset=0x%" ADDRESS_FORMAT "x min_load=0x%" ADDRESS_FORMAT "x",
			  rel->r_offset, si.min_load);
		return;
	}
	if (rel->r_offset > si.max_load - sizeof(Elf_Addr)) {
		FLOGW("重定位偏移超过最大加载地址：r_offset=0x%" ADDRESS_FORMAT "x max_load=0x%" ADDRESS_FORMAT
			  "x addr_size=%zu",
			  rel->r_offset, si.max_load, sizeof(Elf_Addr));
		return;
	}
#ifndef __SO64__
	auto type = ELF32_R_TYPE(rel->r_info);
	auto sym = ELF32_R_SYM(rel->r_info);
#else
	auto type = ELF64_R_TYPE(rel->r_info);
	auto sym = ELF64_R_SYM(rel->r_info);
#endif
	// 重定位目标写入必须落在单个PT_LOAD内。
	// 仅使用[min_load,max_load)会把段间空洞当成可写区域，导致无效输入写坏镜像。
	if (!RangeInLoadSegments(rel->r_offset, static_cast<Elf_Addr>(sizeof(Elf_Addr)), si.phdr, si.phnum)) {
		FLOGW("重定位目标不在可加载段内：r_offset=0x%" ADDRESS_FORMAT "x type=0x%x phdr=%p phnum=%zu", rel->r_offset,
			  type, si.phdr, si.phnum);
		return;
	}
	auto prel = reinterpret_cast<Elf_Addr*>(base + rel->r_offset);
	switch (type) {
		// 默认分支：缺少外部SO信息时采用保守修复策略。
		default:
			if (IsRelativeRelocType(type)) {
				if (*prel >= dump_base) {
					*prel = *prel - dump_base;
				}
				break;
			}
			if (!IsImportRelocType(type)) {
				break;
			}
			{
				// 无法稳定解析符号时，按出现顺序分配导入槽位。
				auto apply_import_fallback = [&]() -> bool {
					auto import_base = si.max_load;
					if (external_pointer > std::numeric_limits<Elf_Addr>::max() - sizeof(*prel)) {
						FLOGW("导入槽位分配失败：external_pointer溢出，offset=0x%" ADDRESS_FORMAT
							  "x ext=0x%" ADDRESS_FORMAT "x slot_size=%zu",
							  rel->r_offset, external_pointer, sizeof(*prel));
						return false;
					}
					if (import_base > std::numeric_limits<Elf_Addr>::max() - external_pointer) {
						FLOGW("导入槽位分配失败：导入基址溢出，offset=0x%" ADDRESS_FORMAT
							  "x import_base=0x%" ADDRESS_FORMAT "x ext=0x%" ADDRESS_FORMAT "x",
							  rel->r_offset, import_base, external_pointer);
						return false;
					}
					*prel = import_base + external_pointer;
					external_pointer += sizeof(*prel);
					return true;
				};
				size_t symtab_count_hint = si.nchain;
				if (si.mips_symtabno > symtab_count_hint) {
					symtab_count_hint = si.mips_symtabno;
				}
				if (symtab_count_hint != 0 && sym >= symtab_count_hint) {
					apply_import_fallback();
					break;
				}
				if (si.symtab == nullptr) {
					apply_import_fallback();
					break;
				}
				const auto sym_base = reinterpret_cast<uintptr_t>(si.symtab);
				if (sym > (std::numeric_limits<uintptr_t>::max() - sym_base) / sizeof(Elf_Sym)) {
					apply_import_fallback();
					break;
				}
				const Elf_Sym* syminfo_ptr = reinterpret_cast<const Elf_Sym*>(sym_base + sym * sizeof(Elf_Sym));
				if (!PointerInLoadSegments(si.load_bias, syminfo_ptr, sizeof(Elf_Sym), si.phdr, si.phnum)) {
					FLOGW("导入符号信息越界，回退槽位分配：sym=%zu sym_ptr=%p r_offset=0x%" ADDRESS_FORMAT
						  "x min_load=0x%" ADDRESS_FORMAT "x max_load=0x%" ADDRESS_FORMAT "x",
						  static_cast<size_t>(sym), syminfo_ptr, rel->r_offset, si.min_load, si.max_load);
					apply_import_fallback();
					break;
				}
				auto syminfo = *syminfo_ptr;
				if (syminfo.st_value != 0) {
					*prel = syminfo.st_value;
				} else {
					auto import_base = si.max_load;
					if (mImports.size() == 0) {
						apply_import_fallback();
					} else {  // 已收集导入符号时，优先使用符号索引映射到稳定槽位。
						int nIndex = GetImportSlotBySymIndex(sym);
						if (nIndex != -1) {
							const auto slot_index = static_cast<size_t>(nIndex);
							Elf_Addr slot_addr = 0;
							if (!CountToBytes(slot_index, sizeof(*prel), &slot_addr)) {
								FLOGW("导入槽位偏移计算失败：slot_index=%zu slot_size=%zu", slot_index, sizeof(*prel));
								apply_import_fallback();
							} else {
								Elf_Addr import_target = 0;
								if (!AddElfAddr(import_base, slot_addr, &import_target)) {
									FLOGW("导入地址超出范围：import_base=0x%" ADDRESS_FORMAT
										  "x slot_addr=0x%" ADDRESS_FORMAT "x",
										  import_base, slot_addr);
									apply_import_fallback();
								} else {
									*prel = import_target;
								}
							}
						} else {
							apply_import_fallback();
						}
						//                FLOGD("type:0x%x offset:0x%x -- symname:%s
						//                nIndex:%d\r\n", type, rel->r_offset, symname,
						//                nIndex);
					}
				}
				break;
			}
	}
	if constexpr (isRela) {
		Elf_Rela* rela = (Elf_Rela*)rel;
		switch (type) {
			case R_AARCH64_RELATIVE:
			case R_X86_64_RELATIVE:
				// RELA的addend是有符号值，负数是合法场景（如相对基址向前回退）。
				// 旧逻辑会忽略负addend，导致该重定位保持转储时绝对地址，输出SO不自洽。
				// 这里统一按ELF语义直接回写addend的补码位模式，让加载器执行B+A。
				// 若addend为负，强转为Elf_Addr后会保留其底层二进制表示。
				*prel = static_cast<Elf_Addr>(rela->r_addend);
				break;
			default:
				break;
		}
	}
};

// 按符号索引查询导入槽位，不存在返回-1。
int ElfRebuilder::GetImportSlotBySymIndex(size_t symIndex) const {
	auto it = mImportSymIndexToImportSlot.find(symIndex);
	if (it == mImportSymIndexToImportSlot.end()) {
		return -1;
	}
	return static_cast<int>(it->second);
}

// 将导入表符号按顺序保存到mImports，后续可据此定位导入槽位。
// 扫描重定位使用到的符号索引，建立“符号索引->导入槽位”映射。
void ElfRebuilder::SaveImportsymNames() {
	mImports.clear();
	mImportSymIndexToImportSlot.clear();
	if (si.symtab == nullptr || si.strtab == nullptr || si.strtabsize == 0) {
		return;
	}

	size_t max_sym_index = 0;
	auto update_max_sym_rel = [&max_sym_index](Elf_Rel* rel, size_t count) {
		if (rel == nullptr || count == 0) {
			return;
		}
		for (size_t i = 0; i < count; ++i) {
#ifndef __SO64__
			auto sym = static_cast<size_t>(ELF32_R_SYM(rel[i].r_info));
#else
			auto sym = static_cast<size_t>(ELF64_R_SYM(rel[i].r_info));
#endif
			if (sym > max_sym_index) {
				max_sym_index = sym;
			}
		}
	};
	auto update_max_sym_rela = [&max_sym_index](Elf_Rela* rela, size_t count) {
		if (rela == nullptr || count == 0) {
			return;
		}
		for (size_t i = 0; i < count; ++i) {
#ifndef __SO64__
			auto sym = static_cast<size_t>(ELF32_R_SYM(rela[i].r_info));
#else
			auto sym = static_cast<size_t>(ELF64_R_SYM(rela[i].r_info));
#endif
			if (sym > max_sym_index) {
				max_sym_index = sym;
			}
		}
	};

	update_max_sym_rel(si.rel, si.rel_count);
	update_max_sym_rela(si.plt_rela, si.plt_rela_count);
	if (si.plt_type == DT_RELA) {
		update_max_sym_rela(reinterpret_cast<Elf_Rela*>(si.plt_rel), si.plt_rel_count);
	} else {
		update_max_sym_rel(si.plt_rel, si.plt_rel_count);
	}

	// 防止max_sym_index+1在极端损坏输入下发生回绕，导致后续扫描边界失真。
	if (max_sym_index == std::numeric_limits<size_t>::max()) {
		FLOGE("重定位符号索引异常：max_sym_index达到size_t上限，rel_count=%zu rela_count=%zu plt_rel_count=%zu",
			  si.rel_count, si.plt_rela_count, si.plt_rel_count);
		return;
	}
	size_t symbol_scan_limit = max_sym_index + 1;
	if (si.nchain > symbol_scan_limit) {
		symbol_scan_limit = si.nchain;
	}
	if (si.mips_symtabno > symbol_scan_limit) {
		symbol_scan_limit = si.mips_symtabno;
	}
	// 基于symtab在加载区中的真实可访问范围，再给symbol_scan_limit加一层硬上限。
	// 背景：
	// 1）nchain/mips_symtabno来自动态段，损坏输入可能给出非常大的计数；
	// 2）现有循环虽会在PointerInLoad失败时中断，但在上限过大时仍会做大量无效迭代；
	// 3）导入符号扫描本质上只可能落在[symtab, max_load)内，超过这一区间没有任何有效数据。
	// 因此这里按“可达字节数/Elf_Sym大小”计算最大可扫描条目，确保复杂度与实际映射区间一致。
	Elf_Addr symtab_off = 0;
	if (!PointerToElfAddrOffset(si.load_bias, si.symtab, "导入扫描symtab偏移", &symtab_off)) {
		FLOGW("导入符号扫描已跳过：无法计算symtab偏移");
		return;
	}
	if (symtab_off >= si.max_load) {
		FLOGW("导入符号扫描已跳过：symtab超出加载范围，symtab_off=0x%" ADDRESS_FORMAT "x max_load=0x%" ADDRESS_FORMAT
			  "x",
			  symtab_off, si.max_load);
		return;
	}
	const Elf_Addr symtab_span = si.max_load - symtab_off;
	const size_t max_symbols_by_load = static_cast<size_t>(symtab_span / static_cast<Elf_Addr>(sizeof(Elf_Sym)));
	if (max_symbols_by_load == 0) {
		FLOGW("导入符号扫描已跳过：symtab可扫描区间为空，symtab_off=0x%" ADDRESS_FORMAT "x max_load=0x%" ADDRESS_FORMAT
			  "x",
			  symtab_off, si.max_load);
		return;
	}
	if (symbol_scan_limit > max_symbols_by_load) {
		FLOGW("导入符号扫描上限已裁剪：requested=%zu capped=%zu", symbol_scan_limit, max_symbols_by_load);
		symbol_scan_limit = max_symbols_by_load;
	}

	for (size_t nIndex = 0; nIndex < symbol_scan_limit; ++nIndex) {
		const auto sym_base = reinterpret_cast<uintptr_t>(si.symtab);
		if (nIndex > (std::numeric_limits<uintptr_t>::max() - sym_base) / sizeof(Elf_Sym)) {
			FLOGW("导入符号扫描终止：符号地址计算溢出，index=%zu sym_base=0x%llx sym_size=%zu", nIndex,
				  static_cast<unsigned long long>(sym_base), sizeof(Elf_Sym));
			break;
		}
		const Elf_Sym* sym_ptr = reinterpret_cast<const Elf_Sym*>(sym_base + nIndex * sizeof(Elf_Sym));
		if (!PointerInLoadSegments(si.load_bias, sym_ptr, sizeof(Elf_Sym), si.phdr, si.phnum)) {
			FLOGW("导入符号扫描终止：符号指针越界，index=%zu sym_ptr=%p min_load=0x%" ADDRESS_FORMAT
				  "x max_load=0x%" ADDRESS_FORMAT "x",
				  nIndex, sym_ptr, si.min_load, si.max_load);
			break;
		}
		const Elf_Sym& sym = *sym_ptr;
		if (sym.st_name == 0) {
			continue;
		}
		if (sym.st_shndx != SHN_UNDEF) {
			continue;
		}
		if (!StringOffsetValid(si.strtab, si.strtabsize, sym.st_name)) {
			continue;
		}
		const char* symname = si.strtab + static_cast<size_t>(sym.st_name);
		if (*symname == '\0') {
			continue;
		}
		mImportSymIndexToImportSlot[nIndex] = mImports.size();
		mImports.emplace_back(symname);
	}
}

// 按收集到的重定位表逐项修复内容。
bool ElfRebuilder::RebuildRelocs() {
	FLOGD("=====================SaveImportsymNames=====================");
	SaveImportsymNames();
	external_pointer = 0;

	if (elf_reader_->dump_so_base_ == 0) return true;
	FLOGD("=======================RebuildRelocs=======================");
	auto rel = si.rel;
	for (size_t i = 0; i < si.rel_count; i++, rel++) {
		relocate<false>(si.load_bias, rel, elf_reader_->dump_so_base_);
	}

	auto rela = reinterpret_cast<Elf_Rela*>(si.plt_rela);
	for (size_t i = 0; i < si.plt_rela_count; i++, rela++) {
		relocate<true>(si.load_bias, reinterpret_cast<Elf_Rel*>(rela), elf_reader_->dump_so_base_);
	}

	if (si.plt_type == DT_REL) {
		rel = si.plt_rel;
		for (size_t i = 0; i < si.plt_rel_count; i++, rel++) {
			relocate<false>(si.load_bias, rel, elf_reader_->dump_so_base_);
		}
	} else {
		rela = reinterpret_cast<Elf_Rela*>(si.plt_rel);
		for (size_t i = 0; i < si.plt_rel_count; i++, rela++) {
			relocate<true>(si.load_bias, reinterpret_cast<Elf_Rel*>(rela), elf_reader_->dump_so_base_);
		}
	}
	FLOGD("=======================RebuildRelocs End=======================");
	return true;
}
