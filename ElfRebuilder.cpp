//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2017/6/4.
//                   Copyright (c) 2017. All rights reserved.
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//
#include <cstdio>
#include <cstring>
#include <limits>
#include "ElfRebuilder.h"
#include "elf.h"
#include "FDebug.h"


#ifdef __SO64__
#define ADDRESS_FORMAT "ll"
#else
#define ADDRESS_FORMAT ""
#endif

namespace {
bool AddElfAddr(Elf_Addr lhs, Elf_Addr rhs, Elf_Addr* out) {
    if (lhs > std::numeric_limits<Elf_Addr>::max() - rhs) {
        return false;
    }
    *out = lhs + rhs;
    return true;
}

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
}

ElfRebuilder::ElfRebuilder(ObElfReader *elf_reader) {
    elf_reader_ = elf_reader;
}

bool ElfRebuilder::RebuildPhdr() {
    FLOGD("=============LoadDynamicSectionFromBaseSource==========RebuildPhdr=========================");


    auto phdr = (Elf_Phdr*)elf_reader_->loaded_phdr();
    for(auto i = 0; i < elf_reader_->phdr_count(); i++) {
        phdr->p_filesz = phdr->p_memsz;     // expend filesize to memsiz
        // p_paddr and p_align is not used in load, just ignore it.
        // fix file offset.
        phdr->p_paddr = phdr->p_vaddr;
        phdr->p_offset = phdr->p_vaddr;     // elf has been loaded.
        phdr++;
    }
    FLOGD("=====================RebuildPhdr End======================");
    return true;
}

bool ElfRebuilder::RebuildShdr() {
    FLOGD("=======================RebuildShdr=========================");
    // rebuilding shdr, link information
    auto base = si.load_bias;
    shstrtab.push_back('\0');

    // empty shdr
    if(true) {
        Elf_Shdr shdr = {0};
        shdrs.push_back(shdr);
    }

    // gen .dynsym
    if(si.symtab != nullptr) {
        sDYNSYM = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".dynsym");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_DYNSYM;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (uintptr_t)si.symtab - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = 0;   // calc sh_size later(pad to next shdr)
        shdr.sh_link = 0;   // link to dynstr later
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

    // gen .dynstr
    if(si.strtab != nullptr) {
        sDYNSTR = shdrs.size();

        Elf_Shdr shdr;
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

    // gen .hash
    if(si.hash != nullptr) {
        sHASH = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".hash");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_HASH;

        shdr.sh_addr = si.hash - base;
        shdr.sh_offset = shdr.sh_addr;
        // TODO 32bit, 64bit?
        shdr.sh_size = (si.nbucket + si.nchain) * sizeof(Elf_Addr) + 2 * sizeof(Elf_Addr);
        shdr.sh_link = sDYNSYM;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x4;

        shdrs.push_back(shdr);
    }

    // gen .rel.dyn
    if(si.rel != nullptr) {
        sRELDYN = shdrs.size();

        Elf_Shdr shdr;
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
        shdr.sh_entsize = 0x18;
#else
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x8;
#endif

        shdrs.push_back(shdr);
    }

    if (si.plt_rela != nullptr) {
        sRELADYN = shdrs.size();
        Elf_Shdr shdr;
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
    // gen .rel.plt
    if(si.plt_rel != nullptr) {
        sRELPLT = shdrs.size();

        Elf_Shdr shdr;
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

    // gen.plt with .rel.plt
    if(si.plt_rel != nullptr) {
        sPLT = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".plt");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        shdr.sh_addr = shdrs[sRELPLT].sh_addr + shdrs[sRELPLT].sh_size;
        shdr.sh_offset = shdr.sh_addr;
        // TODO fix size 32bit 64bit?
        shdr.sh_size = 20/*Pure code*/ + 12 * si.plt_rel_count;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // gen.text&ARM.extab
    if(si.plt_rel != nullptr) {
        sTEXTTAB = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".text&ARM.extab");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        shdr.sh_addr =  shdrs[sPLT].sh_addr + shdrs[sPLT].sh_size;
        // Align 8
        while (shdr.sh_addr & 0x7) {
            shdr.sh_addr ++;
        }

        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = 0;       // calc later
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // gen ARM.exidx
    if(si.ARM_exidx != nullptr) {
        sARMEXIDX = shdrs.size();

        Elf_Shdr shdr;
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
    // gen .fini_array
    if(si.fini_array != nullptr) {
        sFINIARRAY = shdrs.size();

        Elf_Shdr shdr;
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

    // gen .init_array
    if(si.init_array != nullptr) {
        sINITARRAY = shdrs.size();

        Elf_Shdr shdr;
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

    // gen .dynamic
    if(si.dynamic != nullptr) {
        sDYNAMIC = shdrs.size();

        Elf_Shdr shdr;
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

    // get .got
//    if(si.plt_got != nullptr) {
//        // global_offset_table
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
//        // Align8??
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

    // gen .data
    if(true) {
        sDATA = shdrs.size();
        auto sLast = sDATA - 1;

        Elf_Shdr shdr;
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

    // gen .bss
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
//        shdr.sh_size = 0;   // not used
//        shdr.sh_link = 0;
//        shdr.sh_info = 0;
//        shdr.sh_addralign = 8;
//        shdr.sh_entsize = 0x0;
//
//        shdrs.push_back(shdr);
//    }

    // gen .shstrtab, pad into last data
    if(true) {
        sSHSTRTAB = shdrs.size();

        Elf_Shdr shdr;
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

    // link section data

    // sort shdr and recalc size
    for(auto i = 1; i < shdrs.size(); i++) {
        for(auto j = i + 1; j < shdrs.size(); j++) {
            if(shdrs[i].sh_addr > shdrs[j].sh_addr) {
                // exchange i, j
                auto tmp = shdrs[i];
                shdrs[i] = shdrs[j];
                shdrs[j] = tmp;

                // exchange index
                auto chgIdx = [i, j](Elf_Word &t) {
                    if(t == i) {
                        t = j;
                    } else if(t == j) {
                        t = i;
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
        shdrs[sDYNSYM].sh_size = shdrs[sNext].sh_addr - shdrs[sDYNSYM].sh_addr;
    }

    if(sTEXTTAB != 0) {
        auto sNext = sTEXTTAB + 1;
        shdrs[sTEXTTAB].sh_size = shdrs[sNext].sh_addr - shdrs[sTEXTTAB].sh_addr;
    }

    // fix for size
    for(auto i = 2; i < shdrs.size(); i++) {
        if(shdrs[i].sh_offset - shdrs[i-1].sh_offset < shdrs[i-1].sh_size) {
            shdrs[i-1].sh_size = shdrs[i].sh_offset - shdrs[i-1].sh_offset;
        }
    }

    FLOGD("=====================RebuildShdr End======================");
    return true;
}

bool ElfRebuilder::Rebuild() {
    return RebuildPhdr() &&
           ReadSoInfo() &&
           RebuildShdr() &&
           RebuildRelocs() &&
           RebuildFin();
}

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

    /* Extract dynamic section */
    elf_reader_->GetDynamicSection(&si.dynamic, &si.dynamic_count, &si.dynamic_flags);
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

    // Extract useful information from dynamic section.
    uint32_t needed_count = 0;
    size_t plt_rel_size_bytes = 0;
    Elf_Addr strtab_addr = 0;
    bool has_strtab = false;
    Elf_Addr symtab_addr = 0;
    bool has_symtab = false;
    Elf_Word soname_off = 0;
    bool has_soname = false;
    for (size_t dyn_idx = 0; dyn_idx < si.dynamic_count; ++dyn_idx) {
        Elf_Dyn* d = si.dynamic + dyn_idx;
        if (d->d_tag == DT_NULL) {
            break;
        }
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
                si.plt_rel = (Elf_Rel*) (base + d->d_un.d_ptr);
                FLOGD("%s plt_rel (DT_JMPREL) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                plt_rel_size_bytes = d->d_un.d_val;
                break;
            case DT_REL:
                si.rel = (Elf_Rel*) (base + d->d_un.d_ptr);
                FLOGD("%s rel (DT_REL) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
                break;
            case DT_RELSZ:
                si.rel_count = d->d_un.d_val / sizeof(Elf_Rel);
                FLOGD("%s rel_size (DT_RELSZ) %zu", si.name, si.rel_count);
                break;
            case DT_PLTGOT:
                /* Save this in case we decide to do lazy binding. We don't yet. */
                si.plt_got = (Elf_Addr *)(base + d->d_un.d_ptr);
                break;
            case DT_DEBUG:
                // Set the DT_DEBUG entry to the address of _r_debug for GDB
                // if the dynamic table is writable
                break;
            case DT_RELA:
                si.plt_rela = (Elf_Rela*)(base + d->d_un.d_ptr);
                break;
            case DT_RELASZ:
                si.plt_rela_count = d->d_un.d_val / sizeof(Elf_Rela);
                break;
            case DT_INIT:
                si.init_func = reinterpret_cast<void*>(base + d->d_un.d_ptr);
                FLOGD("%s constructors (DT_INIT) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
                break;
            case DT_FINI:
                si.fini_func = reinterpret_cast<void*>(base + d->d_un.d_ptr);
                FLOGD("%s destructors (DT_FINI) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
                break;
            case DT_INIT_ARRAY:
                si.init_array = reinterpret_cast<void**>(base + d->d_un.d_ptr);
                FLOGD("%s constructors (DT_INIT_ARRAY) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
                break;
            case DT_INIT_ARRAYSZ:
                si.init_array_count = ((unsigned)d->d_un.d_val) / sizeof(Elf_Addr);
                FLOGD("%s constructors (DT_INIT_ARRAYSZ) %zu", si.name, si.init_array_count);
                break;
            case DT_FINI_ARRAY:
                si.fini_array = reinterpret_cast<void**>(base + d->d_un.d_ptr);
                FLOGD("%s destructors (DT_FINI_ARRAY) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
                break;
            case DT_FINI_ARRAYSZ:
                si.fini_array_count = ((unsigned)d->d_un.d_val) / sizeof(Elf_Addr);
                FLOGD("%s destructors (DT_FINI_ARRAYSZ) %zu", si.name, si.fini_array_count);
                break;
            case DT_PREINIT_ARRAY:
                si.preinit_array = reinterpret_cast<void**>(base + d->d_un.d_ptr);
                FLOGD("%s constructors (DT_PREINIT_ARRAY) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
                break;
            case DT_PREINIT_ARRAYSZ:
                si.preinit_array_count = ((unsigned)d->d_un.d_val) / sizeof(Elf_Addr);
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
            case DT_RELENT:
                break;
            case DT_MIPS_RLD_MAP:
                // Set the DT_MIPS_RLD_MAP entry to the address of _r_debug for GDB.
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
    if (has_soname) {
        if (StringOffsetValid(si.strtab, si.strtabsize, soname_off)) {
            si.name = si.strtab + soname_off;
            FLOGD("soname %s", si.name);
        } else {
            FLOGW("Ignore invalid DT_SONAME offset");
        }
    }
    if (plt_rel_size_bytes != 0) {
        if (si.plt_type == DT_RELA) {
            si.plt_rel_count = plt_rel_size_bytes / sizeof(Elf_Rela);
        } else if (si.plt_type == DT_REL) {
            si.plt_rel_count = plt_rel_size_bytes / sizeof(Elf_Rel);
        } else {
            FLOGE("Unsupported DT_PLTREL type: 0x%" ADDRESS_FORMAT "x", static_cast<Elf_Addr>(si.plt_type));
            return false;
        }
        FLOGD("%s plt_rel_count (DT_PLTRELSZ) %zu", si.name, si.plt_rel_count);
    }
    if (si.rel_count != 0) {
        if (si.rel == nullptr) {
            FLOGE("DT_RELSZ found but DT_REL missing");
            return false;
        }
        Elf_Addr rel_bytes = 0;
        if (!CountToBytes(si.rel_count, sizeof(Elf_Rel), &rel_bytes) ||
            !PointerInLoad(base, si.rel, rel_bytes, si.min_load, si.max_load)) {
            FLOGE("Invalid DT_REL range");
            return false;
        }
    }
    if (si.plt_rela_count != 0) {
        if (si.plt_rela == nullptr) {
            FLOGE("DT_RELASZ found but DT_RELA missing");
            return false;
        }
        Elf_Addr rela_bytes = 0;
        if (!CountToBytes(si.plt_rela_count, sizeof(Elf_Rela), &rela_bytes) ||
            !PointerInLoad(base, si.plt_rela, rela_bytes, si.min_load, si.max_load)) {
            FLOGE("Invalid DT_RELA range");
            return false;
        }
    }
    if (si.plt_rel_count != 0) {
        if (si.plt_rel == nullptr) {
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
            !PointerInLoad(base, si.plt_rel, plt_bytes, si.min_load, si.max_load)) {
            FLOGE("Invalid DT_JMPREL range");
            return false;
        }
    }
    (void)needed_count;
    FLOGD("=======================ReadSoInfo End=========================");
    return true;
}

// Finally, generate rebuild_data
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
    if (rebuild_data != nullptr) {
        delete []rebuild_data;
        rebuild_data = nullptr;
    }
    rebuild_data = new uint8_t[rebuild_size];
    memset(rebuild_data, 0, rebuild_size);
    memcpy(rebuild_data + min_load, (void*)(si.load_bias + si.min_load), load_size);
    // pad with shstrtab
    memcpy(rebuild_data + file_load_end, shstrtab.c_str(), shstrtab.length());
    // pad with shdrs
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
        // I don't known other so info, if i want to fix it, I must dump other so file
        case R_386_RELATIVE:
        case R_ARM_RELATIVE:
            if (*prel >= dump_base) {
                *prel = *prel - dump_base;
            }
            break;
        case R_386_GLOB_DAT:
        case R_386_JMP_SLOT:
        case R_ARM_GLOB_DAT:
        case R_ARM_JUMP_SLOT:
        case 0x401: //看到也有该type的重定位信息，其中也是导入表相关内容，所以这里也加上
        case 0x402:{
            auto apply_import_fallback = [&]() {
                auto import_base = si.max_load;
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
              }else{ //这里如果获取了导入符号内容，并且不为空，则从保存的导入符号数组中获取导入表索引值
                int nIndex = GetImportSlotBySymIndex(sym);
                if (nIndex != -1){
                  *prel = import_base + nIndex*sizeof(*prel);
                } else {
                  apply_import_fallback();
                }
//                FLOGD("type:0x%x offset:0x%x -- symname:%s nIndex:%d\r\n", type, rel->r_offset, symname, nIndex);
              }
            }
            break;
        }
        default:
            break;
    }
    if (isRela){
        Elf_Rela* rela = (Elf_Rela*)rel;
        switch (type){
            case 0x403:
                *prel = rela->r_addend;
                break;
            default:
                break;
        }
    }
};

int ElfRebuilder::GetImportSlotBySymIndex(size_t symIndex) const {
    auto it = mImportSymIndexToImportSlot.find(symIndex);
    if (it == mImportSymIndexToImportSlot.end()) {
        return -1;
    }
    return static_cast<int>(it->second);
}


//将导入表的符号按顺序保存在 std::vector<std::string>  mImports; 中，以便后面获得导入符号序号 
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


bool ElfRebuilder::RebuildRelocs() {

    FLOGD("=======================Save_importsym_names=========================");
    SaveImportsymNames();
    external_pointer = 0;

    if(elf_reader_->dump_so_base_ == 0) return true;
    FLOGD("=======================RebuildRelocs=========================");
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
//        relocate_address(p, elf_reader_->dump_so_base_);
//        relocate_address(p, elf_reader_->dump_so_base_);
    FLOGD("=======================RebuildRelocs End=======================");
    return true;
}
