//===------------------------------------------------------------*- C++ -*-===//
//
//                     由F8LEFT创建于2021/1/5。
//===----------------------------------------------------------------------===//
// 面向混淆SO文件的ELF读取扩展。
//===----------------------------------------------------------------------===//
// 文件功能：定义面向内存转储/壳场景的读取器扩展接口，支持程序头修正与动态段回填。
// 典型场景：转储SO程序头失真或动态段缺失，需要借助原始SO补齐关键信息。
#ifndef SOFIXER_OBELFREADER_H
#define SOFIXER_OBELFREADER_H

#include "elf_reader.h"
#include <memory>
#include <string>
#include <string_view>
class ElfRebuilder;

// ObElfReader：面向内存转储场景的ELF读取器。
class ObElfReader: public ElfReader {
public:
    // 释放动态段缓存。
    ~ObElfReader() override;
    // 现代化调用接口。
    bool load() override { return Load(); }
    // 修正转储SO中的程序头（常见于壳导致的段信息异常）。
    void FixDumpSoPhdr();

    // 重载加载流程，支持从原始SO补动态段。
    bool Load() override;
    bool load_dynamic_section_from_base_source() { return LoadDynamicSectionFromBaseSource(); }
    // 从原始SO中提取动态段内容。
    bool LoadDynamicSectionFromBaseSource();

    // 设置转储SO的内存基址。
    void setDumpSoBaseAddr(Elf_Addr base) { dump_so_base_ = base; }
    void set_dump_so_base_addr(Elf_Addr base) { setDumpSoBaseAddr(base); }

    // 设置原始SO路径。
    void setBaseSoName(const char* name) {
        base_so_name_ = (name == nullptr) ? "" : name;
    }
    void set_base_so_name(std::string_view name) { base_so_name_ = std::string(name); }

//    void GetDynamicSection(Elf_Dyn** dynamic, size_t* dynamic_count, Elf_Word* dynamic_flags) override;
    // 检查动态段是否已位于任意可加载段内。
    bool haveDynamicSectionInLoadableSegment();
    bool has_dynamic_section_in_loadable_segment() { return haveDynamicSectionInLoadableSegment(); }

private:
    // 把读取到的动态段写入当前加载缓冲并修正对应程序头。
    void ApplyDynamicSection();

    // 转储SO在内存中的基址。
    Elf_Addr dump_so_base_ = 0;

    // 原始SO路径。
    std::string base_so_name_;

    // 从原始SO提取出的动态段缓存。
    std::unique_ptr<uint8_t[]> dynamic_sections_holder_;
    void* dynamic_sections_ = nullptr;
    size_t dynamic_count_ = 0;
    Elf_Word dynamic_flags_ = 0;

    friend class ElfRebuilder;

};


#endif //SOFIXER_OBELFREADER_H
