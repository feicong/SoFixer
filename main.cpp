#include <iostream>
#include "ObElfReader.h"
#include "ElfRebuilder.h"
#include "FDebug.h"
#include <stdio.h>
#include <cstring>
#include <cstdlib>

#ifdef __SO64__
#define TARGET_NAME "SoFixer64"
#else
#define TARGET_NAME "SoFixer32"
#endif


void useage();

static bool is16Bit(const char* value) {
    if (value == nullptr || *value == '\0') {
        return false;
    }
    auto len = strlen(value);
    if (len > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) {
        return true;
    }
    for (size_t i = 0; i < len; i++) {
        if ((value[i] >= 'a' && value[i] <= 'f') ||
            (value[i] >= 'A' && value[i] <= 'F')) {
            return true;
        }
    }
    return false;
}

static bool matchLongOption(const std::string& arg, const char* name, std::string& value) {
    std::string prefix(name);
    prefix += "=";
    if (arg.rfind(prefix, 0) == 0) {
        value = arg.substr(prefix.size());
        return true;
    }
    return false;
}

bool main_loop(int argc, char* argv[]) {
    ObElfReader elf_reader;

    std::string source, output, baseso;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-d" || arg == "--debug") {
            FLOGI("Use debug mode");
            continue;
        }
        if (arg == "-h" || arg == "--help") {
            return false;
        }
        if (arg == "-s" || arg == "--source") {
            if (i + 1 >= argc) return false;
            source = argv[++i];
            continue;
        }
        if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) return false;
            output = argv[++i];
            continue;
        }
        if (arg == "-b" || arg == "--baseso") {
            if (i + 1 >= argc) return false;
            baseso = argv[++i];
            continue;
        }
        if (arg == "-m" || arg == "--memso") {
            if (i + 1 >= argc) return false;
            const char* memArg = argv[++i];
#ifndef __SO64__
            auto base = strtoul(memArg, nullptr, is16Bit(memArg) ? 16 : 10);
#else
            auto base = strtoull(memArg, nullptr, is16Bit(memArg) ? 16 : 10);
#endif
            elf_reader.setDumpSoBaseAddr(base);
            continue;
        }

        std::string value;
        if (matchLongOption(arg, "--source", value)) {
            source = value;
            continue;
        }
        if (matchLongOption(arg, "--output", value)) {
            output = value;
            continue;
        }
        if (matchLongOption(arg, "--baseso", value)) {
            baseso = value;
            continue;
        }
        if (matchLongOption(arg, "--memso", value)) {
#ifndef __SO64__
            auto base = strtoul(value.c_str(), nullptr, is16Bit(value.c_str()) ? 16 : 10);
#else
            auto base = strtoull(value.c_str(), nullptr, is16Bit(value.c_str()) ? 16 : 10);
#endif
            elf_reader.setDumpSoBaseAddr(base);
            continue;
        }

        return false;
    }

    FLOGI("start to rebuild elf file");
    if (!elf_reader.setSource(source.c_str())) {
        FLOGE("unable to open source file");
        return false;
    }
    if (!baseso.empty()) {
        elf_reader.setBaseSoName(baseso.c_str());
    }

    if(!elf_reader.Load()) {
        FLOGE("source so file is invalid");
        return false;
    }

    ElfRebuilder elf_rebuilder(&elf_reader);
    if(!elf_rebuilder.Rebuild()) {
        FLOGE("error occured in rebuilding elf file");
        return false;
    }

    if (!output.empty()) {
        auto* file = fopen(output.c_str(), "wb+");
        if(nullptr == file) {
            FLOGE("output so file cannot write !!!");
            return false;
        }
        fwrite(elf_rebuilder.getRebuildData(), 1, elf_rebuilder.getRebuildSize(),  file);
        fclose(file);
    }

    return true;
}

int main(int argc, char* argv[]) {
    if (main_loop(argc, argv)) {
        FLOGI("Done!!!");
        return 0;
    }
    useage();
    return -1;
}

void useage() {
    FLOGI(TARGET_NAME "v2.1 author F8LEFT(currwin)");
    FLOGI("Useage: SoFixer <option(s)> -s sourcefile -o generatefile");
    FLOGI(" try rebuild shdr with phdr");
    FLOGI(" Options are:");

    FLOGI("  -d --debug                                 Show debug info");
    FLOGI("  -m --memso memBaseAddr(16bit format)       the memory address x which the source so is dump from");
    FLOGI("  -s --source sourceFilePath                 Source file path");
    FLOGI("  -b --baseso baseFilePath                   Original so file path.(used to get base information)(experimental)");
    FLOGI("  -o --output generateFilePath               Generate file path");
    FLOGI("  -h --help                                  Display this information");
}
