//===------------------------------------------------------------*- C++ -*-===//
//
//                     由F8LEFT创建于2021/1/5。
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//
// 文件功能：实现ObElfReader扩展逻辑，处理转储SO程序头修复和原始SO动态段补齐。
// 核心策略：优先使用转储SO自身动态段；缺失时再从原始SO提取并回填。
#include "ob_elf_reader.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <new>
#include <vector>

// 修正内存转储场景下可能失真的程序头信息。
void ObElfReader::FixDumpSoPhdr() {
	// 未提供转储基址时，按“普通ELF文件”处理，程序头保持原样。
	// 关键原因：
	// 1）LoadSegments读取文件时依赖原始p_offset；
	// 2）若在非转储输入上强制改写p_offset=p_vaddr，可能导致段读取偏移错误；
	// 3）输出阶段仍会在RebuildPhdr统一改写文件布局，因此这里无需提前篡改。
	if (dump_so_base_ == 0) {
		return;
	}
	// 部分壳会丢失可加载段之间的数据，按内存镜像方式重算段大小。
	// 仅在用户显式提供转储基址时启用这条“激进修正”路径，普通文件输入保持原始程序头。
	std::vector<Elf_Phdr*> loaded_phdrs;
	// 收集全部可加载段。
	for (size_t i = 0; i < phdr_num_; i++) {
		auto phdr = &phdr_table_[i];
		if (phdr->p_type != PT_LOAD) continue;
		loaded_phdrs.push_back(phdr);
	}
	// 按虚拟地址排序，便于推导每段大小。
	std::sort(loaded_phdrs.begin(), loaded_phdrs.end(),
			  [](Elf_Phdr* first, Elf_Phdr* second) { return first->p_vaddr < second->p_vaddr; });
	if (!loaded_phdrs.empty()) {
		// 通过“到下一段起始地址”的方式重算p_memsz/p_filesz。
		for (size_t i = 0, total = loaded_phdrs.size(); i < total; i++) {
			auto phdr = loaded_phdrs[i];
			if (i != total - 1) {
				// 以“下一可加载段起点”作为当前段结尾。
				auto nphdr = loaded_phdrs[i + 1];
				if (nphdr->p_vaddr > phdr->p_vaddr) {
					phdr->p_memsz = nphdr->p_vaddr - phdr->p_vaddr;
				} else {
					phdr->p_memsz = 0;
				}
			} else {
				// 最后一段没有“下一段起点”可参考，退化为“输入文件末尾-当前段起点”。
				// 这里依赖后续输出布局“p_offset==p_vaddr”的约束来近似还原段长度。
				if (file_size > phdr->p_vaddr) {
					const auto memsz_size_t = file_size - phdr->p_vaddr;
					if (memsz_size_t > static_cast<size_t>(std::numeric_limits<Elf_Addr>::max())) {
						FLOGE("重算段大小超出范围：memsz=%zu", memsz_size_t);
						phdr->p_memsz = 0;
					} else {
						phdr->p_memsz = static_cast<Elf_Addr>(memsz_size_t);
					}
				} else {
					phdr->p_memsz = 0;
				}
			}
			phdr->p_filesz = phdr->p_memsz;
		}
	}

	auto phdr = phdr_table_;
	for (size_t i = 0; i < phdr_num_; i++) {
		// 历史实现会统一改写所有程序头的文件布局字段，而不是仅PT_LOAD。
		// 这样做风险较高，但能保持旧版SoFixer在转储场景下的兼容行为。
		phdr->p_paddr = phdr->p_vaddr;
		phdr->p_filesz = phdr->p_memsz;	 // 扩展文件大小与内存大小一致。
		phdr->p_offset = phdr->p_vaddr;	 // 已按内存镜像加载，文件偏移直接对齐虚拟地址。
										 //            phdr->p_flags = 0                 //
										 //            后续可按段类型补齐默认权限
		phdr++;
	}
}

// 转储SO加载主流程：必要时从原始SO补动态段。
bool ObElfReader::Load() {
	// 按基础读取流程读取ELF头和程序头。
	if (!read_elf_header()) {
		FLOGE("读取ELF头失败，无法进入转储修复流程：input=%s", name_ == nullptr ? "<null>" : name_);
		return false;
	}
	if (!verify_elf_header()) {
		FLOGE("ELF头校验失败，停止转储修复流程：input=%s", name_ == nullptr ? "<null>" : name_);
		return false;
	}
	if (!read_program_header()) {
		FLOGE("程序头读取失败，停止转储修复流程：input=%s", name_ == nullptr ? "<null>" : name_);
		return false;
	}
	FixDumpSoPhdr();

	bool has_base_dynamic_info = false;
	// 需要额外预留给回填动态段的空间大小。
	Elf_Addr base_dynamic_size = 0;
	// 预取baseso动态段作为“兜底候选”，但是否使用要等当前转储装载后做语义判定。
	// 这样即使当前PT_DYNAMIC“位置合法但内容只有DT_NULL”，也能直接切换到baseso回填路径，
	// 同时提前把padding空间预留好，避免后面临时发现要补段却没有附加空间。
	if (!base_so_name_.empty()) {
		if (!LoadDynamicSectionFromBaseSource()) {
			FLOGW("原始SO动态段预取失败，将先尝试仅使用转储动态段：baseso=%s", base_so_name_.c_str());
		} else {
			has_base_dynamic_info = dynamic_sections_ != nullptr && dynamic_count_ > 0;
			if (!has_base_dynamic_info) {
				FLOGW("原始SO动态段预取结果为空：baseso=%s dynamic_sections=%p dynamic_count=%zu",
					  base_so_name_.c_str(), dynamic_sections_, dynamic_count_);
			} else {
				const auto max_dynamic_count =
					static_cast<size_t>(std::numeric_limits<Elf_Addr>::max() / static_cast<Elf_Addr>(sizeof(Elf_Dyn)));
				if (dynamic_count_ > max_dynamic_count) {
					FLOGE("原始SO动态段大小溢出，无法附加：dynamic_count=%zu max_dynamic_count=%zu", dynamic_count_,
						  max_dynamic_count);
					return false;
				}
				base_dynamic_size = static_cast<Elf_Addr>(dynamic_count_) * static_cast<Elf_Addr>(sizeof(Elf_Dyn));
				FLOGI("已预取原始SO动态段：baseso=%s dynamic_count=%zu dynamic_size=0x%llx", base_so_name_.c_str(),
					  dynamic_count_, static_cast<unsigned long long>(base_dynamic_size));
			}
		}
	}

	if (!reserve_address_space(base_dynamic_size)) {
		FLOGE("预留加载地址空间失败：pad=0x%llx", static_cast<unsigned long long>(base_dynamic_size));
		return false;
	}
	if (!load_segments()) {
		FLOGE("加载PT_LOAD段失败：input=%s", name_ == nullptr ? "<null>" : name_);
		return false;
	}
	if (!find_phdr()) {
		FLOGE("定位内存中程序头失败：input=%s", name_ == nullptr ? "<null>" : name_);
		return false;
	}

	// 注意：这里必须做“语义可用性”判定，而不仅是“PT_DYNAMIC是否落在PT_LOAD内”。
	// 典型坏样本：动态段位置合法，但内容只有1条DT_NULL。
	// 若直接判定为可用，ReadSoInfo会得到空动态信息，后续节头与重定位重建必然失真。
	// 判定策略：
	// 1）未提供可用baseso时，保留历史兼容性：允许“缺少DT_NULL终止符”的动态段继续进入解析；
	// 2）已预取到可用baseso动态段时，严格要求必须存在DT_NULL终止符；
	//    若缺少终止符，则优先走baseso回填，避免把损坏转储动态段继续传播到后续重建步骤。
	const bool allow_missing_terminator = !has_base_dynamic_info;
	if (!HasUsableLoadedDynamicSection(allow_missing_terminator)) {
		if (!has_base_dynamic_info) {
			FLOGE("当前转储动态段不可用且无可回填的原始SO动态段：input=%s baseso=%s",
				  name_ == nullptr ? "<null>" : name_, base_so_name_.empty() ? "<empty>" : base_so_name_.c_str());
			return false;
		}
		// 把动态段附加到load区尾部并修正动态段程序头。
		ApplyDynamicSection();
		// 回填后必须再次确认“语义可用”。
		// 这是后续ReadSoInfo/重建流程读取DT_*条目的硬前提。
		if (!HasUsableLoadedDynamicSection(false)) {
			FLOGE("动态段回填后仍不可用，无法继续重建：input=%s baseso=%s", name_ == nullptr ? "<null>" : name_,
				  base_so_name_.empty() ? "<empty>" : base_so_name_.c_str());
			return false;
		}
		FLOGI("已使用原始SO动态段完成回填：baseso=%s", base_so_name_.empty() ? "<empty>" : base_so_name_.c_str());
	} else if (has_base_dynamic_info) {
		FLOGI("当前转储动态段已可用，忽略原始SO动态段回填：baseso=%s", base_so_name_.c_str());
	}

	apply_phdr_table();

	return true;
}

// void ObElfReader::GetDynamicSection(Elf_Dyn **dynamic, size_t *dynamic_count,
// Elf_Word *dynamic_flags) {
//     if (dynamic_sections_ == nullptr) {
//         ElfReader::GetDynamicSection(dynamic, dynamic_count, dynamic_flags);
//         return;
//     }
//     *dynamic = reinterpret_cast<Elf_Dyn*>(dynamic_sections_);
//     if (dynamic_count) {
//         *dynamic_count = dynamic_count_;
//     }
//     if (dynamic_flags) {
//         *dynamic_flags = dynamic_flags_;
//     }
//     return;
// }

// 析构函数：释放从原始SO复制的动态段缓冲。
ObElfReader::~ObElfReader() = default;

// 从原始SO读取动态段，供转储SO缺失动态段时回填。
bool ObElfReader::LoadDynamicSectionFromBaseSource() {
	dynamic_sections_holder_.reset();
	dynamic_sections_ = nullptr;
	dynamic_count_ = 0;
	dynamic_flags_ = 0;

	if (base_so_name_.empty()) {
		FLOGE("未提供原始SO路径，无法补齐动态段：baseso为空");
		return false;
	}
	ElfReader base_reader;

	// 已提供原始SO时，从中读取动态段。
	if (!base_reader.set_source(base_so_name_) || !base_reader.read_elf_header() || !base_reader.verify_elf_header() ||
		!base_reader.read_program_header()) {
		FLOGE("无法解析原始SO文件：baseso=%s", base_so_name_.c_str());
		return false;
	}
	const Elf_Phdr* phdr_table_ = base_reader.phdr_table_;
	const Elf_Phdr* phdr_limit = phdr_table_ + base_reader.phdr_num_;
	const Elf_Phdr* phdr;
	size_t dynamic_candidate_count = 0;
	size_t invalid_not_in_load_count = 0;
	size_t invalid_no_terminator_count = 0;
	size_t invalid_only_null_count = 0;
	auto dynamic_in_load = [phdr_table_, phdr_limit](Elf_Addr dyn_start, Elf_Addr dyn_size) -> bool {
		if (dyn_size < static_cast<Elf_Addr>(sizeof(Elf_Dyn))) {
			return false;
		}
		if (dyn_start > std::numeric_limits<Elf_Addr>::max() - dyn_size) {
			return false;
		}
		const Elf_Addr dyn_end = dyn_start + dyn_size;
		for (const Elf_Phdr* load = phdr_table_; load < phdr_limit; ++load) {
			if (load->p_type != PT_LOAD) {
				continue;
			}
			if (load->p_vaddr > std::numeric_limits<Elf_Addr>::max() - load->p_memsz) {
				continue;
			}
			const Elf_Addr load_end = load->p_vaddr + load->p_memsz;
			if (dyn_start >= load->p_vaddr && dyn_end <= load_end) {
				return true;
			}
		}
		return false;
	};

	for (phdr = phdr_table_; phdr < phdr_limit; phdr++) {
		if (phdr->p_type != PT_DYNAMIC) {
			continue;
		}
		++dynamic_candidate_count;
		// 基准SO的动态段也必须满足“可加载可访问”条件。
		// 若基准本身的PT_DYNAMIC不落在任何PT_LOAD里，复制出来依然不可用，必须跳过继续找下一个候选。
		Elf_Addr dyn_size = phdr->p_memsz;
		if (phdr->p_filesz != 0 && phdr->p_filesz < dyn_size) {
			dyn_size = phdr->p_filesz;
		}
		if (!dynamic_in_load(phdr->p_vaddr, dyn_size)) {
			++invalid_not_in_load_count;
			FLOGW("忽略基准SO中不可加载的PT_DYNAMIC：vaddr=0x%llx memsz=0x%llx filesz=0x%llx",
				  static_cast<unsigned long long>(phdr->p_vaddr), static_cast<unsigned long long>(phdr->p_memsz),
				  static_cast<unsigned long long>(phdr->p_filesz));
			continue;
		}

		// 复制动态段原始字节到本地缓存。
		// 这里的缓存长度必须与“可解析长度dyn_size”一致，不能直接用p_memsz。
		// 原因：上面可用性判定已经采用min(p_memsz,p_filesz)，
		// 若这里继续按p_memsz分配，遇到异常头字段会把无效尾部当成动态表范围，增加误判与内存压力。
		if (dyn_size == 0 || dyn_size > static_cast<Elf_Addr>(std::numeric_limits<size_t>::max())) {
			FLOGE("原始SO动态段可解析大小无效：dyn_size=0x%llx memsz=0x%llx filesz=0x%llx",
				  static_cast<unsigned long long>(dyn_size), static_cast<unsigned long long>(phdr->p_memsz),
				  static_cast<unsigned long long>(phdr->p_filesz));
			return false;
		}
		const size_t dynamic_size_bytes = static_cast<size_t>(dyn_size);
		dynamic_sections_holder_ = std::unique_ptr<uint8_t[]>(new (std::nothrow) uint8_t[dynamic_size_bytes]);
		if (dynamic_sections_holder_ == nullptr) {
			FLOGE("原始SO动态段内存分配失败：size=%zu", dynamic_size_bytes);
			return false;
		}
		dynamic_sections_ = dynamic_sections_holder_.get();
		memset(dynamic_sections_, 0, dynamic_size_bytes);
		// 文件读取长度与缓存一致，避免“读一段、算另一段”的口径不一致。
		const size_t load_size = dynamic_size_bytes;
		auto read_size = base_reader.source_->read(dynamic_sections_, load_size, phdr->p_offset);
		if (read_size != load_size) {
			dynamic_sections_holder_.reset();
			dynamic_sections_ = nullptr;
			FLOGE("读取原始SO动态段失败：offset=0x%llx expect=%zu actual=%zu",
				  static_cast<unsigned long long>(phdr->p_offset), load_size, read_size);
			return false;
		}

		// 只统计完整Elf_Dyn条目，尾部不足一个条目的字节按无效数据忽略。
		// dynamic_count_先按“可解析缓存长度”计算，后续再根据DT_NULL终止符裁剪。
		dynamic_count_ = dynamic_size_bytes / sizeof(Elf_Dyn);
		if (dynamic_count_ == 0) {
			dynamic_sections_holder_.reset();
			dynamic_sections_ = nullptr;
			FLOGE("原始SO动态段条目不足：p_memsz=0x%llx entry_size=%zu", static_cast<unsigned long long>(phdr->p_memsz),
				  sizeof(Elf_Dyn));
			return false;
		}

		// 基准SO动态段需要满足更严格的语义条件：
		// 1）必须存在DT_NULL终止符；
		// 2）终止符之前至少有一个非DT_NULL条目；
		// 3）回填长度裁剪到“终止符所在条目（含）”，避免把尾部噪声复制到输出。
		// 这样可避免“基准动态段本身损坏”时把无效数据扩散到目标样本。
		auto* dynamic_table = reinterpret_cast<Elf_Dyn*>(dynamic_sections_);
		size_t terminator_idx = dynamic_count_;
		bool has_non_null_before_terminator = false;
		for (size_t dyn_idx = 0; dyn_idx < dynamic_count_; ++dyn_idx) {
			const auto tag = dynamic_table[dyn_idx].d_tag;
			if (tag == DT_NULL) {
				terminator_idx = dyn_idx;
				break;
			}
			has_non_null_before_terminator = true;
		}
		if (terminator_idx == dynamic_count_) {
			++invalid_no_terminator_count;
			FLOGW("忽略基准SO中缺少DT_NULL终止符的PT_DYNAMIC：vaddr=0x%llx dyn_count=%zu",
				  static_cast<unsigned long long>(phdr->p_vaddr), dynamic_count_);
			dynamic_sections_holder_.reset();
			dynamic_sections_ = nullptr;
			dynamic_count_ = 0;
			continue;
		}
		if (!has_non_null_before_terminator) {
			++invalid_only_null_count;
			FLOGW("忽略基准SO中仅含DT_NULL的PT_DYNAMIC：vaddr=0x%llx terminator_idx=%zu dyn_count=%zu",
				  static_cast<unsigned long long>(phdr->p_vaddr), terminator_idx, dynamic_count_);
			dynamic_sections_holder_.reset();
			dynamic_sections_ = nullptr;
			dynamic_count_ = 0;
			continue;
		}
		const size_t trimmed_dynamic_count = terminator_idx + 1;
		if (trimmed_dynamic_count < dynamic_count_) {
			FLOGI("基准SO动态段已按DT_NULL裁剪：original_count=%zu trimmed_count=%zu", dynamic_count_,
				  trimmed_dynamic_count);
		}
		dynamic_count_ = trimmed_dynamic_count;
		dynamic_flags_ = phdr->p_flags;
		return true;
	}

	if (dynamic_candidate_count == 0) {
		FLOGE("原始SO未找到PT_DYNAMIC段：phdr_count=%zu", base_reader.phdr_num_);
	} else {
		FLOGE("原始SO未找到可用PT_DYNAMIC段：candidate=%zu not_in_load=%zu no_terminator=%zu only_null=%zu",
			  dynamic_candidate_count, invalid_not_in_load_count, invalid_no_terminator_count, invalid_only_null_count);
	}
	return false;
}

// 将补充的动态段写入当前镜像末尾并更新动态段程序头。
void ObElfReader::ApplyDynamicSection() {
	if (dynamic_sections_ == nullptr || dynamic_count_ == 0 || load_start_ == nullptr || load_bias_ == nullptr) {
		FLOGE("动态段回填前置条件不满足：dynamic_sections=%p dynamic_count=%zu load_start=%p load_bias=%p",
			  dynamic_sections_, dynamic_count_, load_start_, load_bias_);
		return;
	}
	const auto max_dynamic_count =
		static_cast<size_t>(std::numeric_limits<Elf_Addr>::max() / static_cast<Elf_Addr>(sizeof(Elf_Dyn)));
	if (dynamic_count_ > max_dynamic_count) {
		FLOGE("动态段条目数溢出，跳过回填：dynamic_count=%zu max_dynamic_count=%zu", dynamic_count_, max_dynamic_count);
		return;
	}
	Elf_Addr dynamic_size = static_cast<Elf_Addr>(dynamic_count_) * static_cast<Elf_Addr>(sizeof(Elf_Dyn));
	if (load_size_ > std::numeric_limits<Elf_Addr>::max() - dynamic_size) {
		FLOGE("动态段附加地址溢出，跳过回填：load_size=0x%llx dynamic_size=0x%llx",
			  static_cast<unsigned long long>(load_size_), static_cast<unsigned long long>(dynamic_size));
		return;
	}
	uint8_t* wbuf_start = load_start_ + load_size_;
	// 保护校验：仅当预留空间足够时才执行回填，避免越界写入。
	if (pad_size_ < dynamic_size) {
		FLOGE("动态段预留空间不足：pad_size=0x%llx dynamic_size=0x%llx", static_cast<unsigned long long>(pad_size_),
			  static_cast<unsigned long long>(dynamic_size));
		return;
	}
	const auto wbuf_addr = reinterpret_cast<uintptr_t>(wbuf_start);
	const auto bias_addr = reinterpret_cast<uintptr_t>(load_bias_);
	if (wbuf_addr < bias_addr) {
		FLOGE("动态段虚拟地址回推失败：wbuf_addr=0x%llx bias_addr=0x%llx", static_cast<unsigned long long>(wbuf_addr),
			  static_cast<unsigned long long>(bias_addr));
		return;
	}
	const auto new_vaddr_uintptr = wbuf_addr - bias_addr;
	if (new_vaddr_uintptr > static_cast<uintptr_t>(std::numeric_limits<Elf_Addr>::max())) {
		FLOGE("动态段虚拟地址超出范围：new_vaddr=0x%llx", static_cast<unsigned long long>(new_vaddr_uintptr));
		return;
	}
	const Elf_Addr new_vaddr = static_cast<Elf_Addr>(new_vaddr_uintptr);
	if (new_vaddr > std::numeric_limits<Elf_Addr>::max() - dynamic_size) {
		FLOGE("动态段结束地址溢出：new_vaddr=0x%llx dynamic_size=0x%llx", static_cast<unsigned long long>(new_vaddr),
			  static_cast<unsigned long long>(dynamic_size));
		return;
	}
	const Elf_Addr dynamic_end = new_vaddr + dynamic_size;
	// 直接把动态段原始字节复制到补齐区。
	// 写入位置固定为“已加载区末尾”，因此不会覆盖原始段内容。
	memcpy(wbuf_start, dynamic_sections_, dynamic_size);
	// 修正动态段程序头。
	// 路径A：优先更新已有PT_DYNAMIC，保持原程序头布局最小变更。
	// 路径B：若完全缺失PT_DYNAMIC，尝试复用一个PT_NULL槽位创建新动态段头。
	// 若两者都不可用，则无法把回填字节接入ELF元数据，必须失败。
	Elf_Phdr* dynamic_phdr = nullptr;
	Elf_Phdr* null_slot = nullptr;
	for (auto p = phdr_table_, pend = phdr_table_ + phdr_num_; p < pend; ++p) {
		if (p->p_type == PT_DYNAMIC) {
			dynamic_phdr = p;
			break;
		}
		if (null_slot == nullptr && p->p_type == PT_NULL) {
			null_slot = p;
		}
	}
	if (dynamic_phdr == nullptr && null_slot != nullptr) {
		dynamic_phdr = null_slot;
		dynamic_phdr->p_type = PT_DYNAMIC;
		// 以基准SO中的动态段权限为准；若未知则保守给只读权限。
		dynamic_phdr->p_flags = (dynamic_flags_ != 0) ? dynamic_flags_ : static_cast<Elf_Word>(PF_R);
		dynamic_phdr->p_align = sizeof(Elf_Addr);
		FLOGI("复用PT_NULL槽位创建PT_DYNAMIC程序头");
	}
	if (dynamic_phdr == nullptr) {
		FLOGE("动态段回填失败：既没有PT_DYNAMIC也没有PT_NULL可复用，phdr_count=%zu", phdr_num_);
		return;
	}
	dynamic_phdr->p_vaddr = new_vaddr;
	dynamic_phdr->p_paddr = dynamic_phdr->p_vaddr;
	dynamic_phdr->p_offset = dynamic_phdr->p_vaddr;
	// 大小改为新附加区长度。
	// 回填来源是基准SO，权限和对齐值优先采用基准动态段语义，避免沿用损坏转储中的脏值。
	if (dynamic_flags_ != 0) {
		dynamic_phdr->p_flags = dynamic_flags_;
	}
	if (dynamic_phdr->p_align == 0 || dynamic_phdr->p_align > PAGE_SIZE) {
		dynamic_phdr->p_align = sizeof(Elf_Addr);
	}
	dynamic_phdr->p_memsz = dynamic_size;
	dynamic_phdr->p_filesz = dynamic_phdr->p_memsz;

	// 回填后的动态段必须被某个PT_LOAD完整覆盖，否则后续动态段扫描仍会判无效。
	// 由于wbuf_start位于“页对齐后的load区末尾”，这里需要扩展末尾PT_LOAD，
	// 把“原段尾到页边界的空洞＋动态段正文”整体并入同一个可加载范围。
	Elf_Phdr* tail_load = nullptr;
	Elf_Addr tail_load_end = 0;
	for (auto p = phdr_table_, pend = phdr_table_ + phdr_num_; p < pend; ++p) {
		if (p->p_type != PT_LOAD) {
			continue;
		}
		if (p->p_vaddr > std::numeric_limits<Elf_Addr>::max() - p->p_memsz) {
			FLOGW("忽略回绕的PT_LOAD范围：vaddr=0x%llx memsz=0x%llx", static_cast<unsigned long long>(p->p_vaddr),
				  static_cast<unsigned long long>(p->p_memsz));
			continue;
		}
		Elf_Addr load_end = p->p_vaddr + p->p_memsz;
		if (tail_load == nullptr || load_end > tail_load_end) {
			tail_load = p;
			tail_load_end = load_end;
		}
	}
	if (tail_load == nullptr) {
		FLOGE("动态段回填失败：未找到可扩展的PT_LOAD程序头，phdr_count=%zu dynamic_vaddr=0x%llx dynamic_size=0x%llx",
			  phdr_num_, static_cast<unsigned long long>(new_vaddr), static_cast<unsigned long long>(dynamic_size));
		return;
	}
	if (dynamic_end < tail_load->p_vaddr) {
		FLOGE("动态段回填失败：动态段结束地址异常，dynamic_end=0x%llx load_vaddr=0x%llx",
			  static_cast<unsigned long long>(dynamic_end), static_cast<unsigned long long>(tail_load->p_vaddr));
		return;
	}
	Elf_Addr required_memsz = dynamic_end - tail_load->p_vaddr;
	if (required_memsz > tail_load->p_memsz) {
		FLOGI("扩展末尾PT_LOAD以覆盖回填动态段：old_end=0x%llx new_end=0x%llx",
			  static_cast<unsigned long long>(tail_load_end), static_cast<unsigned long long>(dynamic_end));
		tail_load->p_memsz = required_memsz;
		if (tail_load->p_filesz < required_memsz) {
			tail_load->p_filesz = required_memsz;
		}
	}
}

// 判断PT_DYNAMIC是否完全落在某个PT_LOAD段中。
bool ObElfReader::haveDynamicSectionInLoadableSegment() {
	// 这里的“存在”必须是“可用的存在”：
	// 1）动态段至少能容纳一个Elf_Dyn条目；
	// 2）动态段区间不发生回绕；
	// 3）动态段完整落在任一PT_LOAD范围内。
	// 只有满足以上条件才返回true，否则允许后续走baseso补齐路径。
	const Elf_Phdr* phdr = phdr_table_;
	const Elf_Phdr* phdr_limit = phdr + phdr_num_;

	for (phdr = phdr_table_; phdr < phdr_limit; phdr++) {
		if (phdr->p_type != PT_DYNAMIC) {
			continue;
		}
		Elf_Addr dyn_size = phdr->p_memsz;
		if (phdr->p_filesz != 0 && phdr->p_filesz < dyn_size) {
			// 保守策略：优先使用文件中真实存在的动态段字节数做可用性判定。
			dyn_size = phdr->p_filesz;
		}
		if (dyn_size < static_cast<Elf_Addr>(sizeof(Elf_Dyn))) {
			// 至少要容纳一个Elf_Dyn条目，否则后续扫描DT_*标签没有意义。
			FLOGW("忽略无效PT_DYNAMIC段：vaddr=0x%llx size=0x%llx", static_cast<unsigned long long>(phdr->p_vaddr),
				  static_cast<unsigned long long>(dyn_size));
			continue;
		}
		Elf_Addr dyn_start = phdr->p_vaddr;
		Elf_Addr dyn_end = dyn_start + dyn_size;
		if (dyn_end < dyn_start) {
			// 检测到地址回绕时不能直接break。
			// 一个SO里可能存在多个PT_DYNAMIC候选，继续扫描可提高容错率。
			FLOGW("忽略回绕的PT_DYNAMIC范围：vaddr=0x%llx size=0x%llx", static_cast<unsigned long long>(dyn_start),
				  static_cast<unsigned long long>(dyn_size));
			continue;
		}

		for (const Elf_Phdr* load = phdr_table_; load < phdr_limit; load++) {
			if (load->p_type != PT_LOAD) {
				continue;
			}
			Elf_Addr load_start = load->p_vaddr;
			Elf_Addr load_end = load_start + load->p_memsz;
			if (load_end < load_start) {
				continue;
			}
			if (dyn_start >= load_start && dyn_end <= load_end) {
				return true;
			}
		}
	}
	return false;
}

// 判断当前已加载镜像中的动态段是否“语义可用”：
// 1）先复用基础读取器的动态段解析逻辑拿到dynamic指针和dynamic_count；
// 2）按ELF约定把“首个DT_NULL”视为动态段终止符；
// 3）终止符之前至少存在一个非DT_NULL条目时，才判定为可用；
// 4）只有“可访问＋有实际标签”两者都满足，才认为动态段可用。
// allow_missing_terminator用于控制“缺少DT_NULL终止符”场景的容忍度：
// 1）true：保留历史兼容行为，在存在非空条目时继续；
// 2）false：按不可用处理，强制回退到baseso动态段。
bool ObElfReader::HasUsableLoadedDynamicSection(bool allow_missing_terminator) {
	Elf_Dyn* dynamic = nullptr;
	size_t dynamic_count = 0;
	Elf_Word dynamic_flags = 0;
	get_dynamic_section(&dynamic, &dynamic_count, &dynamic_flags);
	if (dynamic == nullptr) {
		FLOGW("动态段不可用：未定位到有效PT_DYNAMIC，phdr_count=%zu", phdr_num_);
		return false;
	}
	if (dynamic_count == 0) {
		FLOGW("动态段不可用：dynamic_count为0，dynamic=%p flags=0x%x", dynamic, dynamic_flags);
		return false;
	}
	bool has_non_null_before_terminator = false;
	for (size_t dyn_idx = 0; dyn_idx < dynamic_count; ++dyn_idx) {
		const auto tag = dynamic[dyn_idx].d_tag;
		if (tag == DT_NULL) {
			if (!has_non_null_before_terminator) {
				FLOGW(
					"动态段不可用：首个终止符前无有效条目，dynamic=%p dynamic_count=%zu terminator_idx=%zu flags=0x%x",
					dynamic, dynamic_count, dyn_idx, dynamic_flags);
				return false;
			}
			FLOGI("动态段语义可用：dynamic=%p dynamic_count=%zu first_terminator_idx=%zu flags=0x%x", dynamic,
				  dynamic_count, dyn_idx, dynamic_flags);
			return true;
		}
		has_non_null_before_terminator = true;
	}
	// 没有遇到DT_NULL通常表示动态段被截断或大小字段异常。
	// 是否继续由allow_missing_terminator决定：
	// 1）兼容模式（true）下，保留历史行为，允许继续；
	// 2）严格模式（false）下，优先触发baseso回填，避免损坏动态段继续参与重建。
	if (has_non_null_before_terminator) {
		if (allow_missing_terminator) {
			FLOGW("动态段缺少DT_NULL终止符，按兼容模式继续：dynamic=%p dynamic_count=%zu flags=0x%x", dynamic,
				  dynamic_count, dynamic_flags);
			return true;
		}
		FLOGW("动态段缺少DT_NULL终止符，按严格模式判不可用：dynamic=%p dynamic_count=%zu flags=0x%x", dynamic,
			  dynamic_count, dynamic_flags);
		return false;
	}
	FLOGW("动态段不可用：动态条目全部为空，dynamic=%p dynamic_count=%zu flags=0x%x", dynamic, dynamic_count,
		  dynamic_flags);
	return false;
}
