//===------------------------------------------------------------*- C++ -*-===//
//
//                     由F8LEFT创建于2017/6/3。
//                   版权所有（c）2017。
//===----------------------------------------------------------------------===//
// 解析并读取ELF文件。
//===----------------------------------------------------------------------===//
// 文件功能：定义ELF读取器接口，负责加载流程与程序头/动态段访问能力。
// 职责边界：仅做读取与内存镜像构建，不直接参与重定位修复和节表重建。

#ifndef SOFIXER_ELFREADER_H
#define SOFIXER_ELFREADER_H

#include "common.h"

#include <cstdint>
#include <cstddef>
#include <memory.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <memory>
#include <string>
#include <string_view>

class ElfRebuilder;
class ObElfReader;

// 文件读取器：跨平台文件读取封装，支持大文件偏移读取。
class FileReader {
public:
    // 仅记录路径，不立即打开。
    explicit FileReader(std::string_view name): source_(name){}
    // 析构时自动关闭文件。
    ~FileReader() {
        close();
    }
    // 打开文件并获取文件大小。
    bool open() {
        if (is_open()) {
            return false;
        }
        stream_.open(source_, std::ios::binary | std::ios::ate);
        if (!stream_.is_open()) {
            return false;
        }
        const auto end = stream_.tellg();
        if (end < 0) {
            close();
            return false;
        }
        file_size_ = static_cast<uint64_t>(end);
        stream_.seekg(0, std::ios::beg);
        if (stream_.fail()) {
            close();
            return false;
        }
        return true;
    }
    // 关闭文件句柄。
    bool close() {
        if (is_open()) {
            stream_.close();
            return true;
        }
        return false;
    }
    // 判断文件句柄是否有效。
    [[nodiscard]] bool is_open() const {
        return stream_.is_open();
    }
    // 获取源文件路径。
    [[nodiscard]] const std::string& source_path() const {
        return source_;
    }
    // 从指定偏移读取len字节；offset缺省时按当前文件指针读取，返回实际读取字节数。
    // 失败策略：返回已读取字节数；若发生定位错误则返回0。
    size_t read(void *addr, size_t len, uint64_t offset = std::numeric_limits<uint64_t>::max()) {
        if (!is_open()) {
            return 0;
        }
        if (addr == nullptr || len == 0) {
            return 0;
        }
        if (len > static_cast<size_t>(std::numeric_limits<std::streamsize>::max())) {
            return 0;
        }
        if (offset != std::numeric_limits<uint64_t>::max()) {
            if (offset > static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max())) {
                FLOGE("\"%s\"在%llx处定位失败", source_.c_str(), static_cast<unsigned long long>(offset));
                return 0;
            }
            stream_.clear();
            stream_.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
            if (stream_.fail()) {
                FLOGE("\"%s\"在%llx处定位失败", source_.c_str(), static_cast<unsigned long long>(offset));
                return 0;
            }
        }
        stream_.read(static_cast<char*>(addr), static_cast<std::streamsize>(len));
        const auto read_count = stream_.gcount();
        const auto rc = read_count > 0 ? static_cast<size_t>(read_count) : 0U;
        if (rc != len) {
            if (offset == std::numeric_limits<uint64_t>::max()) {
                FLOGE("\"%s\"读取%zx字节失败，文件数据不足或转储不完整", source_.c_str(), len);
            } else {
                FLOGE("\"%s\"在%llx:%zx处读取失败，文件数据不足或转储不完整",
                      source_.c_str(),
                      static_cast<unsigned long long>(offset),
                      len);
            }
            return rc;
        }
        return rc;
    }
    // 返回文件总大小。
    [[nodiscard]] uint64_t file_size() const {
        return file_size_;
    }

    // 兼容旧调用接口。
    bool Open() { return open(); }
    bool Close() { return close(); }
    [[nodiscard]] bool IsValid() const { return is_open(); }
    const char* getSource() const { return source_.c_str(); }
    size_t Read(void *addr, size_t len, uint64_t offset = std::numeric_limits<uint64_t>::max()) { return read(addr, len, offset); }
    [[nodiscard]] uint64_t FileSize() const { return file_size(); }

private:
    std::ifstream stream_;
    std::string source_;
    uint64_t file_size_ = 0;
};



class ElfReader {
public:
    // 初始化读取器状态，不做任何IO操作。
    ElfReader();
    // 释放已分配的程序头缓冲、加载缓冲和文件句柄
    virtual ~ElfReader();

    // 执行完整的ELF加载流程（头校验、程序头读取、段加载、定位已加载程序头）。
    virtual bool Load();
    // 现代化调用接口。
    virtual bool load() { return Load(); }
    // 设置输入文件路径并打开文件。
    bool setSource(const char* source);
    bool set_source(std::string_view source);

    // 返回程序头数量
    [[nodiscard]] size_t phdr_count() const { return phdr_num_; }
    // 返回已分配的加载起始地址
    [[nodiscard]] uint8_t * load_start() const { return load_start_; }
    // 返回加载地址范围大小
    [[nodiscard]] Elf_Addr load_size() const { return load_size_; }
    // 返回加载偏移基址。
    [[nodiscard]] uint8_t * load_bias() const { return load_bias_; }
    // 返回内存中的程序头表地址
    [[nodiscard]] const Elf_Phdr* loaded_phdr() const { return loaded_phdr_; }

    // 返回原始ELF头快照。
    [[nodiscard]] const Elf_Ehdr* record_ehdr() const { return &header_; }

protected:
    // 读取阶段函数：
    // ReadElfHeader/VerifyElfHeader负责头部读取与合法性校验；
    // ReadProgramHeader负责读取程序头表；
    // ReserveAddressSpace/LoadSegments负责构建内存镜像；
    // FindPhdr/CheckPhdr负责定位并校验已加载程序头地址。
    // 读取ELF文件头。
    bool ReadElfHeader();
    bool read_elf_header() { return ReadElfHeader(); }
    // 校验ELF魔数、位数和字节序等基础属性。
    bool VerifyElfHeader();
    bool verify_elf_header() { return VerifyElfHeader(); }
    // 读取程序头表
    bool ReadProgramHeader();
    bool read_program_header() { return ReadProgramHeader(); }
    // 预留加载地址空间（可附加padding）。
    bool ReserveAddressSpace(uint32_t padding_size = 0);
    bool reserve_address_space(uint32_t padding_size = 0) { return ReserveAddressSpace(padding_size); }
    // 将所有PT_LOAD段读入内存缓冲。
    bool LoadSegments();
    bool load_segments() { return LoadSegments(); }
    // 在已加载镜像中定位有效的程序头表地址
    bool FindPhdr();
    bool find_phdr() { return FindPhdr(); }
    // 校验给定程序头地址是否位于可加载段内
    bool CheckPhdr(uint8_t *);
    bool check_phdr(uint8_t *loaded) { return CheckPhdr(loaded); }
    // 将临时程序头表回写到加载镜像中的程序头区域
    void ApplyPhdrTable();
    void apply_phdr_table() { ApplyPhdrTable(); }

    // 解析动态段并返回动态表指针、数量和标志
    virtual void GetDynamicSection(Elf_Dyn** dynamic, size_t* dynamic_count, Elf_Word* dynamic_flags);
    virtual void get_dynamic_section(Elf_Dyn** dynamic, size_t* dynamic_count, Elf_Word* dynamic_flags) {
        GetDynamicSection(dynamic, dynamic_count, dynamic_flags);
    }

    // 输入文件路径
    const char* name_ = nullptr;
    std::string name_storage_;
    // 文件读取器
    std::unique_ptr<FileReader> source_holder_;
    FileReader* source_ = nullptr;

    // ELF头缓存。
    Elf_Ehdr header_;
    // 程序头数量
    size_t phdr_num_ = 0;

    // 程序头原始缓冲
    std::unique_ptr<uint8_t[]> phdr_mmap_holder_;
    void* phdr_mmap_ = nullptr;
    // 程序头表地址
    Elf_Phdr* phdr_table_ = nullptr;
    // 程序头表字节大小
    Elf_Addr phdr_size_ = 0;

    // 已分配加载缓冲起始地址
    std::unique_ptr<uint8_t[]> load_start_holder_;
    uint8_t * load_start_ = nullptr;
    // 已分配加载范围大小
    Elf_Addr load_size_ = 0;
    // 额外预留的padding大小（字节）。
    Elf_Addr pad_size_ = 0;
    // 输入文件大小（字节）。
    size_t file_size = 0;
    // 运行时虚拟地址到缓冲地址的偏移
    uint8_t * load_bias_ = nullptr;

    // 加载后可直接访问的程序头表地址
    const Elf_Phdr* loaded_phdr_ = nullptr;


private:

    friend class ElfRebuilder;
    friend class ObElfReader;

};



// 计算所有PT_LOAD段覆盖的页对齐地址范围大小。
size_t
phdr_table_get_load_size(const Elf_Phdr* phdr_table,
                         size_t phdr_count,
                         Elf_Addr* min_vaddr = NULL,
                         Elf_Addr* max_vaddr = NULL);

// 恢复只读段保护属性（当前实现保留接口）
int
phdr_table_protect_segments(const Elf_Phdr* phdr_table,
                            int               phdr_count,
                            uint8_t * load_bias);

// 临时放宽段保护属性（当前实现保留接口）
int
phdr_table_unprotect_segments(const Elf_Phdr* phdr_table,
                              int               phdr_count,
                              uint8_t * load_bias);

// 对GNU RELRO区域设置保护（当前实现保留接口）。
int
phdr_table_protect_gnu_relro(const Elf_Phdr* phdr_table,
                             int               phdr_count,
                             uint8_t *load_bias);


// 读取.ARM.exidx段地址和项数量。
int phdr_table_get_arm_exidx(const Elf_Phdr* phdr_table,
                         int               phdr_count,
                         uint8_t * load_bias,
                         Elf_Addr**      arm_exidx,
                         unsigned*         arm_exidx_count);

// 从程序头中定位动态段并输出动态表信息
void
phdr_table_get_dynamic_section(const Elf_Phdr* phdr_table,
                               int               phdr_count,
                               uint8_t * load_bias,
                               Elf_Dyn**       dynamic,
                               size_t*           dynamic_count,
                               Elf_Word*       dynamic_flags);


#endif //SOFIXER_ELFREADER_H
