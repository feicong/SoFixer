//===------------------------------------------------------------*- C++ -*-===//
//
//                     由F8LEFT创建于2017/6/4。
//                   版权所有（c）2017。
//===----------------------------------------------------------------------===//
// 基于ElfReader重建ELF文件。
//===----------------------------------------------------------------------===//
// 文件功能：定义ELF重建器接口与soinfo结构体，组织重建所需状态。
// 设计目标：把读取阶段得到的运行时信息转成可落盘的完整ELF文件布局。

#ifndef SOFIXER_ELFREBUILDER_H
#define SOFIXER_ELFREBUILDER_H

#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>
#include <memory>
#include "ob_elf_reader.h"



#define SOINFO_NAME_LEN 128
// soinfo结构：重建阶段使用的运行时元数据快照。
struct soinfo {
public:
    // SO名称（优先取DT_SONAME）。
    const char* name = "name";
    // 程序头信息。
    const Elf_Phdr* phdr = nullptr;
    size_t phnum = 0;
    // 入口点和基址信息。
    Elf_Addr entry = 0;
    uint8_t * base = 0;
    unsigned size = 0;

    // 加载范围［min_load,max_load）。
    Elf_Addr min_load;
    Elf_Addr max_load;

    uint32_t unused1 = 0;  // 兼容保留字段，请勿使用。  

    // 动态段信息。
    Elf_Dyn* dynamic = nullptr;
    size_t dynamic_count = 0;
    Elf_Word dynamic_flags = 0;

    uint32_t unused2 = 0; // 兼容保留字段，请勿使用
    uint32_t unused3 = 0; // 兼容保留字段，请勿使用

    unsigned flags = 0;

    // 动态符号与字符串表。
    const char* strtab = nullptr;
    Elf_Sym* symtab = nullptr;

    // SysV哈希表。
    uint8_t * hash = 0;
    size_t strtabsize = 0;
    size_t nbucket = 0;
    size_t nchain = 0;
    unsigned* bucket = nullptr;
    unsigned* chain = nullptr;

    // PLT/GOT与重定位信息。
    Elf_Addr * plt_got = nullptr;

    uint32_t plt_type = DT_REL;
    Elf_Rel* plt_rel = nullptr;
    size_t plt_rel_count = 0;
    Elf_Rela* plt_rela = nullptr;
    size_t plt_rela_count = 0;

    Elf_Rel* rel = nullptr;
    size_t rel_count = 0;

    // 构造／析构相关指针。
    void* preinit_array = nullptr;
    size_t preinit_array_count = 0;

    void** init_array = nullptr;
    size_t init_array_count = 0;
    void** fini_array = nullptr;
    size_t fini_array_count = 0;

    void* init_func = nullptr;
    void* fini_func = nullptr;

    // ARM异常回溯索引信息。
    Elf_Addr * ARM_exidx = nullptr;
    size_t ARM_exidx_count = 0;
    unsigned mips_symtabno = 0;
    unsigned mips_local_gotno = 0;
    unsigned mips_gotsym = 0;

    // 运行时地址偏移基址。
    uint8_t * load_bias = nullptr;

    // 动态标志位。
    bool has_text_relocations = false;
    bool has_DT_SYMBOLIC = false;
};


class ElfRebuilder {
public:
    // 绑定读取器实例。
    ElfRebuilder(ObElfReader* elf_reader);
    // 释放重建产物缓冲。
    ~ElfRebuilder() = default;
    // 执行完整重建流程。
    bool Rebuild();
    // 现代化调用接口。
    bool rebuild() { return Rebuild(); }

    // 读取重建后的二进制缓冲。
    void* getRebuildData() { return rebuild_data_.get(); }
    void* rebuild_data_ptr() { return getRebuildData(); }
    // 读取重建后的二进制大小。
    size_t getRebuildSize() const { return rebuild_size; }
    size_t rebuild_size_bytes() const { return getRebuildSize(); }
private:
    // 重建阶段核心步骤：
    // RebuildPhdr修正程序头；
    // ReadSoInfo提取动态元数据；
    // RebuildShdr构建节头与节名字串；
    // RebuildRelocs修复重定位内容；
    // RebuildFin拼接最终输出文件。
    // 重建程序头表。
    bool RebuildPhdr();
    // 重建节头表。
    bool RebuildShdr();
    // 从动态段提取重建所需元数据。
    bool ReadSoInfo();
    // 修复重定位条目。
    bool RebuildRelocs();
    // 拼接最终输出缓冲。
    bool RebuildFin();

    // 通过符号索引查找导入槽位。
    int GetImportSlotBySymIndex(size_t symIndex) const;
    // 扫描并缓存导入符号名和“符号索引->导入槽位”映射。
    void SaveImportsymNames();
    std::vector<std::string>  mImports;
    std::unordered_map<size_t, size_t> mImportSymIndexToImportSlot;

    // 根据重定位类型修正目标地址。
    template <bool isRela>
    void relocate(uint8_t * base, Elf_Rel* rel, Elf_Addr dump_base);
    // 输入读取器。
    ObElfReader* elf_reader_;
    // 当前SO信息快照。
    soinfo si;

    // 重建输出缓冲信息。
    size_t rebuild_size = 0;
    std::unique_ptr<uint8_t[]> rebuild_data_;

    // 各节在shdr数组中的索引。
    Elf_Word sDYNSYM = 0;
    Elf_Word sDYNSTR = 0;
    Elf_Word sHASH = 0;
    Elf_Word sRELDYN = 0;
    Elf_Word sRELADYN = 0;
    Elf_Word sRELPLT = 0;
    Elf_Word sPLT = 0;
    Elf_Word sTEXTTAB = 0;
    Elf_Word sARMEXIDX = 0;
    Elf_Word sFINIARRAY = 0;
    Elf_Word sINITARRAY = 0;
    Elf_Word sDYNAMIC = 0;
    Elf_Word sGOT = 0;
    Elf_Word sDATA = 0;
    Elf_Word sBSS = 0;
    Elf_Word sSHSTRTAB = 0;

    std::vector<Elf_Shdr> shdrs;
    std::string shstrtab;

    // 为外部导入符号分配虚拟槽位时使用的递增偏移。
    Elf_Addr external_pointer = 0;
private:
    bool isPatchInit = false;
public:
    // 兼容旧逻辑的开关。
    void setPatchInit(bool b) { isPatchInit = b; }
    void set_patch_init(bool b) { setPatchInit(b); }
};


#endif //SOFIXER_ELFREBUILDER_H
