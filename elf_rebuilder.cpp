//===------------------------------------------------------------*- C++ -*-===//
//
//                     由F8LEFT创建于2017/6/4。
//                   版权所有（c）2017。
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//
// 文件功能：实现ELF修复重建流程，包括动态信息提取、节表生成与重定位修正。
#include <cstdio>
#include <cstring>
#include <limits>
#include <new>
#include "elf_rebuilder.h"
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

// 校验［start,start+size）是否完整位于加载范围内。
bool RangeInLoad(Elf_Addr start, Elf_Addr size, Elf_Addr min_load, Elf_Addr max_load) {
    if (size == 0) {
        return start >= min_load && start <= max_load;
    }
    if (start < min_load) {
        return false;
    }
    Elf_Addr end = 0;
    if (!AddElfAddr(start, size, &end)) {
        return false;
    }
    return end >= start && end <= max_load;
}

// 基于运行时指针计算偏移后，校验指针范围是否合法。
bool PointerInLoad(const uint8_t* base,
                   const void* ptr,
                   size_t size,
                   Elf_Addr min_load,
                   Elf_Addr max_load) {
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
    return RangeInLoad(static_cast<Elf_Addr>(offset),
                       static_cast<Elf_Addr>(size),
                       min_load,
                       max_load);
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
    return type == R_386_RELATIVE ||
           type == R_ARM_RELATIVE ||
           type == R_X86_64_RELATIVE ||
           type == R_AARCH64_RELATIVE;
}

// 判断是否为导入符号相关重定位类型。
bool IsImportRelocType(Elf_Addr type) {
    return type == R_386_GLOB_DAT ||
           type == R_386_JMP_SLOT ||
           type == R_ARM_GLOB_DAT ||
           type == R_ARM_JUMP_SLOT ||
           type == R_X86_64_GLOB_DAT ||
           type == R_X86_64_JUMP_SLOT ||
           type == R_AARCH64_GLOB_DAT ||
           type == R_AARCH64_JUMP_SLOT ||
           type == 0x401 ||
           type == 0x402;
}
}

// 绑定读取器实例。
ElfRebuilder::ElfRebuilder(ObElfReader *elf_reader) {
    elf_reader_ = elf_reader;
}

// 重写程序头：输出文件偏移按已加载内存地址布局。
bool ElfRebuilder::RebuildPhdr() {
    FLOGD("=====================RebuildPhdr======================");


    auto phdr = (Elf_Phdr*)elf_reader_->loaded_phdr();
    for (size_t i = 0; i < elf_reader_->phdr_count(); ++i) {
        phdr->p_filesz = phdr->p_memsz;     // 输出文件大小与内存段大小保持一致。
        // p_paddr和p_align在当前重建路径不参与装载决策。
        // 输出文件偏移按内存镜像布局修正。
        phdr->p_paddr = phdr->p_vaddr;
        phdr->p_offset = phdr->p_vaddr;     // 当前已按内存地址布局加载。
        phdr++;
    }
    FLOGD("===================RebuildPhdr End====================");
    return true;
}

// 重建节头表和节名表。
bool ElfRebuilder::RebuildShdr() {
    FLOGD("=======================RebuildShdr=========================");
    // 重建节头表和节索引关联信息。
    auto base = si.load_bias;
    shstrtab.push_back('\0');

    // 0号节：空节。
    if(true) {
        Elf_Shdr shdr = {};
        shdrs.push_back(shdr);
    }

    // 生成.dynsym节。
    if(si.symtab != nullptr) {
        sDYNSYM = shdrs.size();

        Elf_Shdr shdr = {};
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".dynsym");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_DYNSYM;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (uintptr_t)si.symtab - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = 0;   // 后续根据下一节地址回填大小。
        shdr.sh_link = 0;   // 后续回填到.dynstr。
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
    if(si.strtab != nullptr) {
        sDYNSTR = shdrs.size();

        Elf_Shdr shdr = {};
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".dynstr");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_STRTAB;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (uintptr_t)si.strtab - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.strtabsize;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 1;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // 生成.hash节。
    if(si.hash != nullptr) {
        sHASH = shdrs.size();

        Elf_Shdr shdr = {};
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".hash");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_HASH;
        shdr.sh_flags = SHF_ALLOC;

        shdr.sh_addr = si.hash - base;
        shdr.sh_offset = shdr.sh_addr;
        Elf_Addr hash_word_count = 0;
        if (!AddElfAddr(static_cast<Elf_Addr>(si.nbucket),
                        static_cast<Elf_Addr>(si.nchain),
                        &hash_word_count) ||
            !AddElfAddr(hash_word_count, 2, &hash_word_count)) {
            FLOGE("Invalid hash table size");
            return false;
        }
        Elf_Addr hash_size = 0;
        if (!CountToBytes(static_cast<size_t>(hash_word_count), sizeof(Elf_Word), &hash_size)) {
            FLOGE("Invalid hash table bytes");
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
    if(si.rel != nullptr) {
        sRELDYN = shdrs.size();

        Elf_Shdr shdr = {};
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".rel.dyn");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_REL;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (uintptr_t)si.rel - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.rel_count * sizeof(Elf_Rel);
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
        sRELADYN = shdrs.size();
        Elf_Shdr shdr = {};
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".rela.dyn");
        shstrtab.push_back('\0');
        shdr.sh_type = SHT_RELA;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (uintptr_t)si.plt_rela - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.plt_rela_count * sizeof(Elf_Rela);
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
    if(si.plt_rel != nullptr) {
        if (si.plt_type != DT_REL && si.plt_type != DT_RELA) {
            FLOGE("Unsupported plt relocation type: 0x%" ADDRESS_FORMAT "x", static_cast<Elf_Addr>(si.plt_type));
            return false;
        }
        sRELPLT = shdrs.size();

        Elf_Shdr shdr = {};
        shdr.sh_name = shstrtab.length();
        if (si.plt_type == DT_REL){
            shstrtab.append(".rel.plt");
        } else {
            shstrtab.append(".rela.plt");
        }
        shstrtab.push_back('\0');

        if (si.plt_type == DT_REL) {
            shdr.sh_type = SHT_REL;
        } else {
            shdr.sh_type = SHT_RELA;
        }
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (uintptr_t)si.plt_rel - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        if (si.plt_type == DT_REL){
            shdr.sh_size = si.plt_rel_count * sizeof(Elf_Rel);
        }else {
            shdr.sh_size = si.plt_rel_count * sizeof(Elf_Rela);
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
    if(si.plt_rel != nullptr) {
        sPLT = shdrs.size();

        Elf_Shdr shdr = {};
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".plt");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        shdr.sh_addr = shdrs[sRELPLT].sh_addr + shdrs[sRELPLT].sh_size;
        shdr.sh_offset = shdr.sh_addr;
        // 后续可按架构重新校准.plt模板长度。
        shdr.sh_size = 20/*仅指令体大小*/ + 12 * si.plt_rel_count;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // 生成.text&ARM.extab过渡节。
    if(si.plt_rel != nullptr) {
        sTEXTTAB = shdrs.size();

        Elf_Shdr shdr = {};
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".text&ARM.extab");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        shdr.sh_addr =  shdrs[sPLT].sh_addr + shdrs[sPLT].sh_size;
        // 按8字节对齐。
        while (shdr.sh_addr & 0x7) {
            shdr.sh_addr ++;
        }

        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = 0;       // 后续回填。
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // 生成.ARM.exidx节。
    if(si.ARM_exidx != nullptr) {
        sARMEXIDX = shdrs.size();

        Elf_Shdr shdr = {};
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".ARM.exidx");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_ARMEXIDX;
        shdr.sh_flags = SHF_ALLOC | SHF_LINK_ORDER;
        shdr.sh_addr = (uintptr_t)si.ARM_exidx - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.ARM_exidx_count * sizeof(Elf_Addr);
        shdr.sh_link = sTEXTTAB;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x8;

        shdrs.push_back(shdr);
    }
    // 生成.fini_array节。
    if(si.fini_array != nullptr) {
        sFINIARRAY = shdrs.size();

        Elf_Shdr shdr = {};
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".fini_array");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_FINI_ARRAY;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = (uintptr_t)si.fini_array - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.fini_array_count * sizeof(Elf_Addr);
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
    if(si.init_array != nullptr) {
        sINITARRAY = shdrs.size();

        Elf_Shdr shdr = {};
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".init_array");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_INIT_ARRAY;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = (uintptr_t)si.init_array - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.init_array_count * sizeof(Elf_Addr);
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
    if(si.dynamic != nullptr) {
        sDYNAMIC = shdrs.size();

        Elf_Shdr shdr = {};
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".dynamic");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_DYNAMIC;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = (uintptr_t)si.dynamic - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.dynamic_count * sizeof(Elf_Dyn);
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
//        shdr.sh_size = (uintptr_t)(si.plt_got + si.plt_rel_count) - shdr.sh_addr - (uintptr_t)base + 3 * sizeof(Elf_Addr);
//        shdr.sh_link = 0;
//        shdr.sh_info = 0;
//#ifdef __SO64__
//        shdr.sh_addralign = 8;
//#else
//        shdr.sh_addralign = 4;
//#endif
//        shdr.sh_entsize = 0x0;
//
//        shdrs.push_back(shdr);
//    }

    // 生成.data节。
    if(true) {
        sDATA = shdrs.size();
        auto sLast = sDATA - 1;

        Elf_Shdr shdr = {};
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".data");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = shdrs[sLast].sh_addr + shdrs[sLast].sh_size;
        shdr.sh_offset = shdr.sh_addr;
        if (si.max_load > shdr.sh_addr) {
            shdr.sh_size = si.max_load - shdr.sh_addr;
        } else {
            shdr.sh_size = 0;
        }
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
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
    if(true) {
        sSHSTRTAB = shdrs.size();

        Elf_Shdr shdr = {};
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".shstrtab");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_STRTAB;
        shdr.sh_flags = 0;
        shdr.sh_addr = si.max_load;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = shstrtab.length();
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
            if(shdrs[i].sh_addr > shdrs[j].sh_addr) {
                // 交换两个节头条目。
                auto tmp = shdrs[i];
                shdrs[i] = shdrs[j];
                shdrs[j] = tmp;

                // 同步交换关联索引。
                auto chgIdx = [i, j](Elf_Word &t) {
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
    if (sRELDYN != 0){
        shdrs[sRELDYN].sh_link = sDYNSYM;
    }
    if (sRELADYN != 0){
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
    if(sDYNSYM != 0) {
        shdrs[sDYNSYM].sh_link = sDYNSTR;
    }

    if(sDYNSYM != 0) {
        auto sNext = sDYNSYM + 1;
        if (sNext >= shdrs.size() || shdrs[sNext].sh_addr < shdrs[sDYNSYM].sh_addr) {
            FLOGE("Invalid dynsym section order");
            return false;
        }
        shdrs[sDYNSYM].sh_size = shdrs[sNext].sh_addr - shdrs[sDYNSYM].sh_addr;
    }

    if(sTEXTTAB != 0) {
        auto sNext = sTEXTTAB + 1;
        if (sNext >= shdrs.size() || shdrs[sNext].sh_addr < shdrs[sTEXTTAB].sh_addr) {
            FLOGE("Invalid text section order");
            return false;
        }
        shdrs[sTEXTTAB].sh_size = shdrs[sNext].sh_addr - shdrs[sTEXTTAB].sh_addr;
    }

    // 纠正可能的节大小重叠
    for (size_t i = 2; i < shdrs.size(); ++i) {
        if(shdrs[i].sh_offset - shdrs[i-1].sh_offset < shdrs[i-1].sh_size) {
            shdrs[i-1].sh_size = shdrs[i].sh_offset - shdrs[i-1].sh_offset;
        }
    }

    FLOGD("=====================RebuildShdr End======================");
    return true;
}

// 重建主流程：先修程序头，再读SO信息，最后构造节表、重定位和输出。
bool ElfRebuilder::Rebuild() {
    return RebuildPhdr() &&
           ReadSoInfo() &&
           RebuildShdr() &&
           RebuildRelocs() &&
           RebuildFin();
}

// 从动态段提取重建所需信息，并做完整边界与一致性校验。
bool ElfRebuilder::ReadSoInfo() {
    FLOGD("=======================ReadSoInfo=========================");
    si.base = si.load_bias = elf_reader_->load_bias();
    si.phdr = elf_reader_->loaded_phdr();
    si.phnum = elf_reader_->phdr_count();
    auto base = si.load_bias;
    if (phdr_table_get_load_size(si.phdr, si.phnum, &si.min_load, &si.max_load) == 0) {
        FLOGE("Invalid loadable segment range");
        return false;
    }
    if (elf_reader_->pad_size_ > std::numeric_limits<Elf_Addr>::max() - si.max_load) {
        FLOGE("Invalid load range after padding");
        return false;
    }
    si.max_load += elf_reader_->pad_size_;

    /* 提取动态段信息 */
    elf_reader_->get_dynamic_section(&si.dynamic, &si.dynamic_count, &si.dynamic_flags);
    if (si.dynamic == nullptr || si.dynamic_count == 0) {
        FLOGE("No valid dynamic phdr data");
        return false;
    }
    if (!PointerInLoad(base, si.dynamic, sizeof(Elf_Dyn), si.min_load, si.max_load)) {
        FLOGE("Dynamic section pointer out of load range");
        return false;
    }

    phdr_table_get_arm_exidx(si.phdr, si.phnum, si.base,
                             &si.ARM_exidx, (unsigned*)&si.ARM_exidx_count);

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
        switch(d->d_tag){
            case DT_HASH: {
                Elf_Addr hash_addr = d->d_un.d_ptr;
                Elf_Addr hash_head_size = static_cast<Elf_Addr>(2 * sizeof(unsigned));
                if (!RangeInLoad(hash_addr, hash_head_size, si.min_load, si.max_load)) {
                    FLOGE("Invalid DT_HASH table header");
                    return false;
                }
                auto hash_data = reinterpret_cast<unsigned*>(base + hash_addr);
                const size_t nbucket = hash_data[0];
                const size_t nchain = hash_data[1];
                const size_t total_words = 2 + nbucket + nchain;
                Elf_Addr hash_table_bytes = 0;
                if (!CountToBytes(total_words, sizeof(unsigned), &hash_table_bytes) ||
                    !RangeInLoad(hash_addr, hash_table_bytes, si.min_load, si.max_load)) {
                    FLOGE("Invalid DT_HASH table size");
                    return false;
                }
                si.hash = d->d_un.d_ptr + (uint8_t*)base;
                si.nbucket = nbucket;
                si.nchain = nchain;
                si.bucket = (unsigned *) (base + d->d_un.d_ptr + 2 * sizeof(unsigned));
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
                si.plt_type = d->d_un.d_val;
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
                    FLOGE("Invalid DT_RELSZ alignment");
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
                    FLOGE("Invalid DT_RELASZ alignment");
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
                    FLOGE("Invalid DT_INIT_ARRAYSZ alignment");
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
                    FLOGE("Invalid DT_FINI_ARRAYSZ alignment");
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
                    FLOGE("Invalid DT_PREINIT_ARRAYSZ alignment");
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
                si.mips_symtabno = d->d_un.d_val;
                break;

            case DT_MIPS_LOCAL_GOTNO:
                si.mips_local_gotno = d->d_un.d_val;
                break;

            case DT_MIPS_GOTSYM:
                si.mips_gotsym = d->d_un.d_val;
                break;
            case DT_SONAME:
                soname_off = d->d_un.d_val;
                has_soname = true;
                break;
            default:
                FLOGD("Unused DT entry: type 0x%08" ADDRESS_FORMAT "x arg 0x%08" ADDRESS_FORMAT "x", d->d_tag, d->d_un.d_val);
                break;
        }
    }
    if (has_strtab) {
        // 第二阶段：统一做范围校验后再转成可访问指针。
        if (si.strtabsize == 0 ||
            si.strtabsize > static_cast<size_t>(std::numeric_limits<Elf_Addr>::max()) ||
            !RangeInLoad(strtab_addr,
                         static_cast<Elf_Addr>(si.strtabsize),
                         si.min_load,
                         si.max_load)) {
            FLOGE("Invalid DT_STRTAB range");
            return false;
        }
        si.strtab = reinterpret_cast<const char*>(base + strtab_addr);
    }
    if (has_symtab) {
        if (!RangeInLoad(symtab_addr, static_cast<Elf_Addr>(sizeof(Elf_Sym)), si.min_load, si.max_load)) {
            FLOGE("Invalid DT_SYMTAB pointer");
            return false;
        }
        si.symtab = reinterpret_cast<Elf_Sym*>(base + symtab_addr);
    }
    if (has_pltgot) {
        if (!RangeInLoad(pltgot_addr, static_cast<Elf_Addr>(sizeof(Elf_Addr)), si.min_load, si.max_load)) {
            FLOGE("Invalid DT_PLTGOT pointer");
            return false;
        }
        si.plt_got = reinterpret_cast<Elf_Addr*>(base + pltgot_addr);
    }
    if (has_init) {
        if (!RangeInLoad(init_addr, 1, si.min_load, si.max_load)) {
            FLOGE("Invalid DT_INIT pointer");
            return false;
        }
        si.init_func = reinterpret_cast<void*>(base + init_addr);
    }
    if (has_fini) {
        if (!RangeInLoad(fini_addr, 1, si.min_load, si.max_load)) {
            FLOGE("Invalid DT_FINI pointer");
            return false;
        }
        si.fini_func = reinterpret_cast<void*>(base + fini_addr);
    }
    if (has_init_array) {
        Elf_Addr init_array_bytes = 0;
        if (!CountToBytes(si.init_array_count, sizeof(Elf_Addr), &init_array_bytes)) {
            FLOGE("Invalid DT_INIT_ARRAY size");
            return false;
        }
        if (!RangeInLoad(init_array_addr, init_array_bytes, si.min_load, si.max_load)) {
            FLOGE("Invalid DT_INIT_ARRAY range");
            return false;
        }
        si.init_array = reinterpret_cast<void**>(base + init_array_addr);
    }
    if (has_fini_array) {
        Elf_Addr fini_array_bytes = 0;
        if (!CountToBytes(si.fini_array_count, sizeof(Elf_Addr), &fini_array_bytes)) {
            FLOGE("Invalid DT_FINI_ARRAY size");
            return false;
        }
        if (!RangeInLoad(fini_array_addr, fini_array_bytes, si.min_load, si.max_load)) {
            FLOGE("Invalid DT_FINI_ARRAY range");
            return false;
        }
        si.fini_array = reinterpret_cast<void**>(base + fini_array_addr);
    }
    if (has_preinit_array) {
        Elf_Addr preinit_array_bytes = 0;
        if (!CountToBytes(si.preinit_array_count, sizeof(Elf_Addr), &preinit_array_bytes)) {
            FLOGE("Invalid DT_PREINIT_ARRAY size");
            return false;
        }
        if (!RangeInLoad(preinit_array_addr, preinit_array_bytes, si.min_load, si.max_load)) {
            FLOGE("Invalid DT_PREINIT_ARRAY range");
            return false;
        }
        si.preinit_array = reinterpret_cast<void**>(base + preinit_array_addr);
    }
    if (has_soname) {
        if (StringOffsetValid(si.strtab, si.strtabsize, soname_off)) {
            si.name = si.strtab + soname_off;
            FLOGD("soname %s", si.name);
        } else {
            FLOGW("Ignore invalid DT_SONAME offset");
        }
    }
    if (has_syment && syment != sizeof(Elf_Sym)) {
        FLOGE("Unsupported DT_SYMENT: %" ADDRESS_FORMAT "u", syment);
        return false;
    }
    if (has_relent && relent != sizeof(Elf_Rel)) {
        FLOGE("Unsupported DT_RELENT: %" ADDRESS_FORMAT "u", relent);
        return false;
    }
    if (has_relaent && relaent != sizeof(Elf_Rela)) {
        FLOGE("Unsupported DT_RELAENT: %" ADDRESS_FORMAT "u", relaent);
        return false;
    }
    if ((has_jmprel || plt_rel_size_bytes != 0) && si.plt_type != DT_REL && si.plt_type != DT_RELA) {
        FLOGE("Unsupported DT_PLTREL type: 0x%" ADDRESS_FORMAT "x", static_cast<Elf_Addr>(si.plt_type));
        return false;
    }
    if (plt_rel_size_bytes != 0) {
        if (si.plt_type == DT_RELA) {
            if (!BytesToCount(plt_rel_size_bytes, sizeof(Elf_Rela), &si.plt_rel_count)) {
                FLOGE("Invalid DT_PLTRELSZ alignment for RELA");
                return false;
            }
        } else if (si.plt_type == DT_REL) {
            if (!BytesToCount(plt_rel_size_bytes, sizeof(Elf_Rel), &si.plt_rel_count)) {
                FLOGE("Invalid DT_PLTRELSZ alignment for REL");
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
            FLOGE("DT_RELSZ found but DT_REL missing");
            return false;
        }
        Elf_Addr rel_bytes = 0;
        if (!CountToBytes(si.rel_count, sizeof(Elf_Rel), &rel_bytes) ||
            !RangeInLoad(rel_addr, rel_bytes, si.min_load, si.max_load)) {
            FLOGE("Invalid DT_REL range");
            return false;
        }
        si.rel = reinterpret_cast<Elf_Rel*>(base + rel_addr);
    } else if (has_rel) {
        if (!RangeInLoad(rel_addr, static_cast<Elf_Addr>(sizeof(Elf_Rel)), si.min_load, si.max_load)) {
            FLOGE("Invalid DT_REL pointer");
            return false;
        }
        si.rel = reinterpret_cast<Elf_Rel*>(base + rel_addr);
    }
    if (si.plt_rela_count != 0) {
        // 同步校验RELA主重定位表。
        if (!has_rela) {
            FLOGE("DT_RELASZ found but DT_RELA missing");
            return false;
        }
        Elf_Addr rela_bytes = 0;
        if (!CountToBytes(si.plt_rela_count, sizeof(Elf_Rela), &rela_bytes) ||
            !RangeInLoad(rela_addr, rela_bytes, si.min_load, si.max_load)) {
            FLOGE("Invalid DT_RELA range");
            return false;
        }
        si.plt_rela = reinterpret_cast<Elf_Rela*>(base + rela_addr);
    } else if (has_rela) {
        if (!RangeInLoad(rela_addr, static_cast<Elf_Addr>(sizeof(Elf_Rela)), si.min_load, si.max_load)) {
            FLOGE("Invalid DT_RELA pointer");
            return false;
        }
        si.plt_rela = reinterpret_cast<Elf_Rela*>(base + rela_addr);
    }
    if (si.plt_rel_count != 0) {
        // 校验PLT重定位条目类型、长度和范围。
        if (!has_jmprel) {
            FLOGE("DT_PLTRELSZ found but DT_JMPREL missing");
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
            !RangeInLoad(jmprel_addr, plt_bytes, si.min_load, si.max_load)) {
            FLOGE("Invalid DT_JMPREL range");
            return false;
        }
        si.plt_rel = reinterpret_cast<Elf_Rel*>(base + jmprel_addr);
    } else if (has_jmprel) {
        if (!RangeInLoad(jmprel_addr, static_cast<Elf_Addr>(sizeof(Elf_Rel)), si.min_load, si.max_load)) {
            FLOGE("Invalid DT_JMPREL pointer");
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
    FLOGD("=======================try to finish file rebuild =========================");
    if (si.max_load < si.min_load) {
        FLOGE("Invalid load range");
        return false;
    }
    if (si.max_load > static_cast<Elf_Addr>(std::numeric_limits<size_t>::max())) {
        FLOGE("Load range too large");
        return false;
    }
    const auto load_size = static_cast<size_t>(si.max_load - si.min_load);
    const auto file_load_end = static_cast<size_t>(si.max_load);
    const auto shstr_size = shstrtab.length();
    if (shdrs.size() > std::numeric_limits<size_t>::max() / sizeof(Elf_Shdr)) {
        FLOGE("Section header table too large");
        return false;
    }
    const auto shdr_bytes = shdrs.size() * sizeof(Elf_Shdr);
    if (file_load_end > std::numeric_limits<size_t>::max() - shstr_size - shdr_bytes) {
        FLOGE("Rebuild buffer size overflow");
        return false;
    }
    rebuild_size = file_load_end + shstr_size + shdr_bytes;
    const auto min_load = static_cast<size_t>(si.min_load);
    if (min_load > rebuild_size || load_size > rebuild_size - min_load) {
        FLOGE("Invalid rebuild copy range");
        return false;
    }
    rebuild_data_.reset();
    rebuild_data_ = std::unique_ptr<uint8_t[]>(new (std::nothrow) uint8_t[rebuild_size]);
    if (rebuild_data_ == nullptr) {
        FLOGE("重建输出内存分配失败");
        return false;
    }
    auto* rebuild_data = rebuild_data_.get();
    memset(rebuild_data, 0, rebuild_size);
    memcpy(rebuild_data + min_load, (void*)(si.load_bias + si.min_load), load_size);
    // 追加节名字串表。
    memcpy(rebuild_data + file_load_end, shstrtab.c_str(), shstrtab.length());
    // 追加节头表。
    const auto shdr_off = file_load_end + shstrtab.length();
    memcpy(rebuild_data + shdr_off, (void*)&shdrs[0],
           shdrs.size() * sizeof(Elf_Shdr));
    auto ehdr = *elf_reader_->record_ehdr();
    ehdr.e_type = ET_DYN;
    ehdr.e_shnum = shdrs.size();
    ehdr.e_shoff = static_cast<Elf_Addr>(shdr_off);
    ehdr.e_shstrndx = sSHSTRTAB;
    memcpy(rebuild_data, &ehdr, sizeof(Elf_Ehdr));

    FLOGD("=======================End=========================");
    return true;
}

template <bool isRela>
// 按重定位类型修正目标地址。
// 规则：REL相对重定位先减转储基址；导入重定位映射到导入槽；RELA场景再按addend覆盖特定相对类型。
void ElfRebuilder::relocate(uint8_t * base, Elf_Rel* rel, Elf_Addr dump_base) {
    if(rel == nullptr) return ;
    if (si.max_load < sizeof(Elf_Addr)) return;
    if (rel->r_offset < si.min_load) return;
    if (rel->r_offset > si.max_load - sizeof(Elf_Addr)) return;
#ifndef __SO64__
    auto type = ELF32_R_TYPE(rel->r_info);
    auto sym = ELF32_R_SYM(rel->r_info);
#else
    auto type = ELF64_R_TYPE(rel->r_info);
    auto sym = ELF64_R_SYM(rel->r_info);
#endif
    auto prel = reinterpret_cast<Elf_Addr *>(base + rel->r_offset);
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
            auto apply_import_fallback = [&]() {
                auto import_base = si.max_load;
                if (external_pointer > std::numeric_limits<Elf_Addr>::max() - sizeof(*prel)) {
                    return;
                }
                if (import_base > std::numeric_limits<Elf_Addr>::max() - external_pointer) {
                    return;
                }
                *prel = import_base + external_pointer;
                external_pointer += sizeof(*prel);
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
            const Elf_Sym* syminfo_ptr =
                    reinterpret_cast<const Elf_Sym*>(sym_base + sym * sizeof(Elf_Sym));
            if (!PointerInLoad(si.load_bias, syminfo_ptr, sizeof(Elf_Sym), si.min_load, si.max_load)) {
                apply_import_fallback();
                break;
            }
            auto syminfo = *syminfo_ptr;
            if (syminfo.st_value != 0) {
                *prel = syminfo.st_value;
            } else {
              auto import_base = si.max_load;
              if (mImports.size() == 0){
                apply_import_fallback();
              }else{ // 已收集导入符号时，优先使用符号索引映射到稳定槽位。
                int nIndex = GetImportSlotBySymIndex(sym);
                if (nIndex != -1){
                  const auto slot = static_cast<Elf_Addr>(nIndex);
                  if (slot <= (std::numeric_limits<Elf_Addr>::max() / sizeof(*prel))) {
                      const auto slot_addr = slot * sizeof(*prel);
                      if (import_base <= std::numeric_limits<Elf_Addr>::max() - slot_addr) {
                          *prel = import_base + slot_addr;
                      } else {
                          apply_import_fallback();
                      }
                  } else {
                      apply_import_fallback();
                  }
                } else {
                  apply_import_fallback();
                }
//                FLOGD("type:0x%x offset:0x%x -- symname:%s nIndex:%d\r\n", type, rel->r_offset, symname, nIndex);
              }
            }
            break;
            }
    }
    if (isRela){
        Elf_Rela* rela = (Elf_Rela*)rel;
        switch (type){
            case R_AARCH64_RELATIVE:
            case R_X86_64_RELATIVE:
                *prel = rela->r_addend;
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
void ElfRebuilder::SaveImportsymNames(){
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

    size_t symbol_scan_limit = max_sym_index + 1;
    if (si.nchain > symbol_scan_limit) {
        symbol_scan_limit = si.nchain;
    }
    if (si.mips_symtabno > symbol_scan_limit) {
        symbol_scan_limit = si.mips_symtabno;
    }

    for (size_t nIndex = 0; nIndex < symbol_scan_limit; ++nIndex) {
        const auto sym_base = reinterpret_cast<uintptr_t>(si.symtab);
        if (nIndex > (std::numeric_limits<uintptr_t>::max() - sym_base) / sizeof(Elf_Sym)) {
            break;
        }
        const Elf_Sym* sym_ptr = reinterpret_cast<const Elf_Sym*>(sym_base + nIndex * sizeof(Elf_Sym));
        if (!PointerInLoad(si.load_bias, sym_ptr, sizeof(Elf_Sym), si.min_load, si.max_load)) {
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

    if(elf_reader_->dump_so_base_ == 0) return true;
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
    auto relocate_address = [](Elf_Addr * pelf, Elf_Addr dump_base){
        if (*pelf > dump_base)
            *pelf = *pelf - dump_base;
    };
    // 预留：统一地址回退辅助函数，当前路径由relocate分支完成修复。
//        relocate_address(p, elf_reader_->dump_so_base_);
//        relocate_address(p, elf_reader_->dump_so_base_);
    FLOGD("=======================RebuildRelocs End=======================");
    return true;
}
