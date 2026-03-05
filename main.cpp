// 命令行入口实现：负责参数解析、重建流程调度与结果落盘。
#include <cstdlib>
#include <fstream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

#include "elf_rebuilder.h"
#include "ob_elf_reader.h"

// 文件功能：命令行入口，负责参数解析、调用读取器与重建器并输出结果文件。
// 处理流程：解析参数→加载输入SO→执行重建→写出重建产物。
// 按编译位数选择默认工具名。
#ifdef __SO64__
#define TARGET_NAME "SoFixer64"
#else
#define TARGET_NAME "SoFixer32"
#endif

namespace {

struct app_config {
	std::string source;
	std::string output;
	std::string base_so;
	std::optional<Elf_Addr> memory_base;
	bool debug = false;
	bool show_help = false;
};

void usage() {
	FLOGI(TARGET_NAME "v2.1 作者F8LEFT(currwin)");
	FLOGI("用法：SoFixer <option(s)> -s sourcefile -o generatefile");
	FLOGI("功能：基于程序头重建节头信息");
	FLOGI("参数说明：");

	FLOGI("  -d --debug                                 显示调试信息");
	FLOGI("  -m --memso memBaseAddr(number format)      输入SO转储时的内存基址（支持十进制或十六进制，可带0x前缀）");
	FLOGI("  -s --source sourceFilePath                 输入文件路径");
	FLOGI(
		"  -b --baseso baseFilePath                   "
		"原始SO路径（用于补基础信息，实验特性）");
	FLOGI("  -o --output generateFilePath               输出文件路径");
	FLOGI("  -h --help                                  显示帮助信息");
}

bool match_long_option(std::string_view arg, std::string_view name, std::string& value) {
	std::string prefix(name);
	prefix += "=";
	if (arg.rfind(prefix, 0) == 0) {
		value = std::string(arg.substr(prefix.size()));
		return true;
	}
	return false;
}

std::optional<Elf_Addr> parse_memory_base(std::string_view value) {
	if (value.empty()) {
		return std::nullopt;
	}
	try {
		size_t pos = 0;
		int base = 10;
		if (value.size() > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) {
			base = 16;
		} else {
			for (const char ch : value) {
				if ((ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
					base = 16;
					break;
				}
			}
		}
		unsigned long long parsed = std::stoull(std::string(value), &pos, base);
		if (pos != value.size()) {
			return std::nullopt;
		}
		if (parsed > static_cast<unsigned long long>(std::numeric_limits<Elf_Addr>::max())) {
			return std::nullopt;
		}
		return static_cast<Elf_Addr>(parsed);
	} catch (...) {
		return std::nullopt;
	}
}

std::optional<app_config> parse_command_line(int argc, char* argv[]) {
	app_config config;
	for (int i = 1; i < argc; ++i) {
		std::string arg = argv[i];
		if (arg == "-d" || arg == "--debug") {
			config.debug = true;
			FLOGI("已启用调试模式");
			continue;
		}
		if (arg == "-h" || arg == "--help") {
			config.show_help = true;
			return config;
		}
		if (arg == "-s" || arg == "--source") {
			if (i + 1 >= argc) return std::nullopt;
			config.source = argv[++i];
			continue;
		}
		if (arg == "-o" || arg == "--output") {
			if (i + 1 >= argc) return std::nullopt;
			config.output = argv[++i];
			continue;
		}
		if (arg == "-b" || arg == "--baseso") {
			if (i + 1 >= argc) return std::nullopt;
			config.base_so = argv[++i];
			continue;
		}
		if (arg == "-m" || arg == "--memso") {
			if (i + 1 >= argc) return std::nullopt;
			auto parsed = parse_memory_base(argv[++i]);
			if (!parsed.has_value()) {
				return std::nullopt;
			}
			config.memory_base = parsed.value();
			continue;
		}

		std::string value;
		if (match_long_option(arg, "--source", value)) {
			config.source = value;
			continue;
		}
		if (match_long_option(arg, "--output", value)) {
			config.output = value;
			continue;
		}
		if (match_long_option(arg, "--baseso", value)) {
			config.base_so = value;
			continue;
		}
		if (match_long_option(arg, "--memso", value)) {
			auto parsed = parse_memory_base(value);
			if (!parsed.has_value()) {
				return std::nullopt;
			}
			config.memory_base = parsed.value();
			continue;
		}

		return std::nullopt;
	}

	if (config.source.empty() && !config.show_help) {
		return std::nullopt;
	}

	return config;
}

bool write_output_file(const std::string& output, const void* data, size_t size) {
	if (size != 0 && data == nullptr) {
		return false;
	}
	if (size > static_cast<size_t>(std::numeric_limits<std::streamsize>::max())) {
		return false;
	}
	std::ofstream out(output, std::ios::binary | std::ios::trunc);
	if (!out.is_open()) {
		return false;
	}
	if (size == 0) {
		return out.good();
	}
	out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
	return out.good();
}

bool run_main(const app_config& config) {
	sofixer::logger::set_level(config.debug ? sofixer::log_level::debug : sofixer::log_level::info);
	ObElfReader elf_reader;
	if (config.memory_base.has_value()) {
		elf_reader.set_dump_so_base_addr(config.memory_base.value());
	}

	FLOGI("开始重建ELF文件");
	if (!elf_reader.set_source(config.source)) {
		FLOGE("无法打开输入文件");
		return false;
	}
	if (!config.base_so.empty()) {
		elf_reader.set_base_so_name(config.base_so);
	}

	if (!elf_reader.load()) {
		FLOGE("输入SO文件无效");
		return false;
	}

	ElfRebuilder elf_rebuilder(&elf_reader);
	if (!elf_rebuilder.rebuild()) {
		FLOGE("重建ELF文件时发生错误");
		return false;
	}

	if (!config.output.empty() &&
		!write_output_file(config.output, elf_rebuilder.rebuild_data_ptr(), elf_rebuilder.rebuild_size_bytes())) {
		FLOGE("输出SO文件写入失败");
		return false;
	}
	return true;
}

}  // namespace

// 进程入口：成功返回0，失败返回-1并打印帮助。
int main(int argc, char* argv[]) {
	auto parsed = parse_command_line(argc, argv);
	if (!parsed.has_value()) {
		usage();
		return -1;
	}
	if (parsed->show_help) {
		usage();
		return 0;
	}
	if (!run_main(parsed.value())) {
		usage();
		return -1;
	}
	FLOGI("处理完成");
	return 0;
}
