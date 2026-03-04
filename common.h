//===------------------------------------------------------------*- C++ -*-===//
//
//                     由F8LEFT创建于2017/6/28。
//                   版权所有（c）2017。
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//
// 文件功能：定义与目标位数相关的ELF类型别名和页对齐辅助宏。
// 目标：屏蔽32位与64位差异，统一上层解析与重建代码写法。

#ifndef FAOATDUMP_EXELF_H
#define FAOATDUMP_EXELF_H

#include "elf.h"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <utility>

// 根据编译位数统一类型别名，简化业务代码中的类型分支
#ifndef __SO64__
using Elf_Ehdr = Elf32_Ehdr;
using Elf_Phdr = Elf32_Phdr;
using Elf_Shdr = Elf32_Shdr;
using Elf_Sym = Elf32_Sym;
using Elf_Dym = Elf32_Dyn;
using Elf_Rel = Elf32_Rel;
using Elf_Rela = Elf32_Rela;
using Elf_Addr = Elf32_Addr;
using Elf_Dyn = Elf32_Dyn;
using Elf_Word = Elf32_Word;
#else
using Elf_Ehdr = Elf64_Ehdr;
using Elf_Phdr = Elf64_Phdr;
using Elf_Shdr = Elf64_Shdr;
using Elf_Sym = Elf64_Sym;
using Elf_Dym = Elf64_Dyn;
using Elf_Rel = Elf64_Rel;
using Elf_Rela = Elf64_Rela;
using Elf_Addr = Elf64_Addr;
using Elf_Dyn = Elf64_Dyn;
using Elf_Word = Elf64_Word;
#endif

#ifndef PAGE_SIZE
// 默认按4KB页处理地址对齐。
#define PAGE_SIZE 0x1000

// 页掩码
#define PAGE_MASK (~(PAGE_SIZE-1))
// 取地址x所在页的起始地址。
#define PAGE_START(x)  ((x) & PAGE_MASK)

// 取地址x在页内的偏移。
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)

// 取包含地址x的末尾页边界（向上按页对齐）。
#define PAGE_END(x)    PAGE_START((x) + (PAGE_SIZE-1))
#endif

#ifndef TEMP_FAILURE_RETRY
// 系统调用在EINTR时自动重试。
#define TEMP_FAILURE_RETRY(expression) \
  (__extension__\
   ({ long int __result;\
       do __result = (long int)(expression);\
       while(__result == -1L&& errno == EINTR);\
       __result;}))
#endif

#ifndef ANDDBG_ALOG_H
#define ANDDBG_ALOG_H
namespace sofixer {
enum class log_level : int {
    error = 0,
    warning = 1,
    info = 2,
    debug = 3,
    verbose = 4,
};

class logger {
public:
    static void set_level(log_level level) noexcept {
        current_level_ = level;
    }

    template <typename... Args>
    static void log(log_level level,
                    const char* function,
                    int line,
                    const char* format,
                    Args&&... args) noexcept {
        if (level > current_level_ || format == nullptr) {
            return;
        }
        std::printf("[%s:%d] %s: ", safe_function_name(function), line, level_text(level));
        if constexpr (sizeof...(Args) == 0) {
            std::fputs(format, stdout);
        } else {
            std::printf(format, std::forward<Args>(args)...);
        }
        std::printf("\n");
    }

private:
    static const char* safe_function_name(const char* function) noexcept {
        return function == nullptr ? "unknown" : function;
    }

    static const char* level_text(log_level level) noexcept {
        switch (level) {
            case log_level::error:
                return "ERROR";
            case log_level::warning:
                return "WARN";
            case log_level::info:
                return "INFO";
            case log_level::debug:
                return "DEBUG";
            case log_level::verbose:
                return "VERBOSE";
            default:
                return "UNKNOWN";
        }
    }

    inline static log_level current_level_ = log_level::info;
};
} // namespace sofixer

#define FLOGE(fmt, ...) sofixer::logger::log(sofixer::log_level::error, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#define FLOGW(fmt, ...) sofixer::logger::log(sofixer::log_level::warning, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#define FLOGI(fmt, ...) sofixer::logger::log(sofixer::log_level::info, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#define FLOGD(fmt, ...) sofixer::logger::log(sofixer::log_level::debug, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#define FLOGV(fmt, ...) sofixer::logger::log(sofixer::log_level::verbose, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#endif //ANDDBG_ALOG_H


#endif //FAOATDUMP_EXELF_H
