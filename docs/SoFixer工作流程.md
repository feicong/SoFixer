# SoFixer工作流程
## 1.ELF修正顺序
SoFixer按ELF文件从上到下处理，顺序固定如下。
1.`Elf_Ehdr`。
2.`Elf_Phdr`。
3.`PT_LOAD`对应段内容与地址映射。
4.`Elf_Dyn`与`DT_*`动态条目。
5.`Elf_Rel/Elf_Rela`重定位条目。
6.`Elf_Shdr`。
7.回写`Elf_Ehdr`中节头相关字段。

对应主流程在`ElfRebuilder::Rebuild()`：`RebuildPhdr()->ReadSoInfo()->RebuildShdr()->RebuildRelocs()->RebuildFin()`。

## 2.Elf_Ehdr字段修正
### 2.1保持原值的字段
`e_ident`、`e_machine`、`e_entry`、`e_phoff`、`e_phentsize`、`e_phnum`保持原值。

计算依据：
1.这些字段定义目标架构和程序头读取方式。
2.SoFixer重建的是节头与动态信息，不重写指令入口和程序头表位置。

### 2.2回写字段
1.`e_type`
- 修正为`ET_DYN`。
- 依据：输出仍是共享库类型。

2.`e_shoff`
- 计算：`e_shoff=file_load_end+shstr_size`。
- 其中：`file_load_end=si.max_load`，`shstr_size=shstrtab.length()`。
- 依据：输出布局固定为`[load镜像][.shstrtab][section header table]`。

3.`e_shnum`
- 计算：`e_shnum=shdrs.size()`。
- 依据：节头表完全重建，数量以新表为准。

4.`e_shstrndx`
- 计算：`e_shstrndx=sSHSTRTAB`。
- 依据：`.shstrtab`索引在排序后可能变化，必须写回最终索引。

## 3.Elf_Phdr字段修正
### 3.1转储预修正（仅`-m`）
函数：`ObElfReader::FixDumpSoPhdr()`。

触发条件：`dump_so_base_!=0`。

`PT_LOAD`修正规则：
1.按`p_vaddr`升序排序。
2.非最后一段：`p_memsz=next_load.p_vaddr-cur_load.p_vaddr`。
3.最后一段：`p_memsz=file_size-cur_load.p_vaddr`，下溢时置`0`。
4.`p_filesz=p_memsz`。

全部程序头统一改写：
- `p_paddr=p_vaddr`。
- `p_offset=p_vaddr`。
- `p_filesz=p_memsz`。

计算依据：
1.转储文件通常接近内存连续布局，原始文件偏移语义已失真。
2.先把段边界和偏移统一到虚拟地址口径，后续装载和重建才能使用同一套地址系。

### 3.2动态段回填后的程序头修正
函数：`ObElfReader::ApplyDynamicSection()`。

触发流程：
1.若命令行提供了`baseso`，`Load()`先执行`LoadDynamicSectionFromBaseSource()`预取动态段并计算`base_dynamic_size`。
2.完成`ReserveAddressSpace()->LoadSegments()->FindPhdr()`后，执行`HasUsableLoadedDynamicSection()`。
3.若已预取到可用`baseso`动态段，则当前动态段判定使用严格模式：缺少`DT_NULL`终止符时直接视为不可用。
4.若当前转储动态段不可用且已预取到`baseso`动态段，执行`ApplyDynamicSection()`回填。
5.回填后再次执行`HasUsableLoadedDynamicSection()`，仍不可用则终止。

`PT_DYNAMIC`字段修正：
- `p_vaddr/p_paddr/p_offset=new_vaddr`。
- `p_memsz/p_filesz=dynamic_size`。
- `p_flags`优先使用`baseso`的`dynamic_flags_`。
- `p_align`异常时回落到`sizeof(Elf_Addr)`。

并发修正末尾`PT_LOAD`：
1.找`p_vaddr+p_memsz`最大的`PT_LOAD`作为尾段。
2.计算`required_memsz=dynamic_end-tail_load.p_vaddr`。
3.若`required_memsz>tail_load.p_memsz`，更新`tail_load.p_memsz/p_filesz`。

计算依据：
1.动态段必须被某个可加载段完整覆盖，否则后续`ReadSoInfo`会判定为无效动态段。
2.`PT_DYNAMIC`和`PT_LOAD`需要同时修正，缺一不可。

### 3.3最终统一修正
函数：`ElfRebuilder::RebuildPhdr()`。

重建输出前再次统一全部程序头：
- `p_filesz=p_memsz`。
- `p_paddr=p_vaddr`。
- `p_offset=p_vaddr`。

计算依据：
1.最终输出文件按内存镜像落盘。
2.程序头中的文件偏移与虚拟地址保持同口径，工具链读取更稳定。

## 4.PT_LOAD段内容与地址换算
函数：`phdr_table_get_load_size()`、`ReserveAddressSpace()`、`LoadSegments()`。

字段与公式：
1.`min_vaddr=PAGE_START(min(PT_LOAD.p_vaddr))`。
2.`max_vaddr=PAGE_START(max(PT_LOAD.p_vaddr+p_memsz+PAGE_SIZE-1))`。
3.`load_size=max_vaddr-min_vaddr`。
4.`load_bias=load_start-min_vaddr`。
5.运行时地址换算：`runtime_addr=load_bias+vaddr`。

段复制规则：
1.每个`PT_LOAD`从`p_offset`读取`p_filesz`字节到`load_bias+p_vaddr`。
2.若`p_memsz>p_filesz`，差值区域依赖预清零缓冲，不额外拷贝。
3.`FindPhdr`定位程序头时：
- 优先使用`PT_PHDR`。
- 兜底时遍历所有`p_offset==0`的`PT_LOAD`候选，不只看首个`PT_LOAD`。
- 地址计算使用已校验的`header_.e_phoff`并做无符号溢出检查。

计算依据：
1.先做页对齐后计算统一映射区间，避免跨页边界误差。
2.后续动态段、重定位、节头地址都基于`load_bias`换算。

## 5.Elf_Dyn与DT字段修正
### 5.1动态段可用性判定
函数：`HasUsableLoadedDynamicSection()`。

地址完整性条件：
1.`dyn_size>=sizeof(Elf_Dyn)`。
2.`dyn_start+dyn_size`不回绕。
3.`[dyn_start,dyn_end)`完整落在某个`PT_LOAD`内。

其中：
- `dyn_size=p_memsz`。
- 若`p_filesz!=0`且`p_filesz<p_memsz`，则`dyn_size=p_filesz`。

语义可用性条件：
1.`dynamic_count=dyn_size/sizeof(Elf_Dyn)`，按完整条目数向下取整。
2.扫描从索引`0`开始，遇到首个`DT_NULL`即视为动态段终止。
3.终止符之前至少存在一个`d_tag!=DT_NULL`条目。
4.若首条就是`DT_NULL`，判定为“段在但内容空”，必须走`baseso`回填路径。
5.若直到`dynamic_count`都未出现`DT_NULL`：
- 当存在可用`baseso`动态段时，按不可用处理并触发回填。
- 当不存在可用`baseso`动态段时，记录告警并按兼容模式继续。

计算依据：
1.动态段扫描按`Elf_Dyn`条目遍历，长度不足或越界会导致条目解析错误。
2.转储样本常见`p_memsz`与`p_filesz`不一致，使用较小值更保守。
3.仅靠“地址落在PT_LOAD内”无法排除“只有DT_NULL”的空动态段。
4.ELF动态表以`DT_NULL`作为终止标记，终止符之后的数据不应参与可用性判定。

### 5.2从baseso补动态段
函数：`LoadDynamicSectionFromBaseSource()`。

补段口径：
1.候选`PT_DYNAMIC`先通过与5.1相同的可加载性校验。
2.复制长度使用`dyn_size=min(p_memsz,p_filesz)`（`p_filesz==0`时按`p_memsz`）。
3.`dynamic_count=dyn_size/sizeof(Elf_Dyn)`，不足一个条目的尾字节丢弃。
4.基准动态段必须存在`DT_NULL`终止符，且终止符前至少一个非`DT_NULL`条目。
5.回填计数裁剪为`terminator_index+1`，只复制到终止符为止。
6.若候选`PT_DYNAMIC`全部无效，返回失败并输出分类统计（不在`PT_LOAD`内、缺少终止符、仅含`DT_NULL`）。

计算依据：
1.判定、分配、读取、计数全部使用同一`dyn_size`，避免口径不一致。
2.保证回填后的动态段长度与可解析条目数一一对应。
3.避免把基准SO动态段尾部噪声或损坏字段复制到目标样本。

### 5.3DT字段到soinfo的映射
函数：`ReadSoInfo()`。

主要字段映射：
1.`DT_HASH->si.hash/si.nbucket/si.nchain`。
2.`DT_STRTAB+DT_STRSZ->si.strtab/si.strtabsize`。
3.`DT_SYMTAB->si.symtab`。
4.`DT_REL+DT_RELSZ->si.rel/si.rel_count`。
5.`DT_RELA+DT_RELASZ->si.plt_rela/si.plt_rela_count`。
6.`DT_JMPREL+DT_PLTRELSZ+DT_PLTREL->si.plt_rel/si.plt_rel_count/si.plt_type`。
7.`DT_INIT_ARRAY+DT_INIT_ARRAYSZ->si.init_array/si.init_array_count`。
8.`DT_FINI_ARRAY+DT_FINI_ARRAYSZ->si.fini_array/si.fini_array_count`。

统一校验规则：
1.先收集地址和值。
2.再做范围校验`RangeInLoadSegments`和对齐校验`BytesToCount`。
3.范围校验按单个`PT_LOAD`逐段覆盖执行，不接受“仅落在`min_load~max_load`但位于段间空洞”的地址。
4.范围上界仅取`PT_LOAD`推导结果，不叠加读取缓冲预留的`padding`。
5.指针类校验同样按单个`PT_LOAD`逐段覆盖执行。
6.最后转换为可访问指针。
7.关键字段组合约束：
- `DT_SYMTAB`与`DT_STRTAB/DT_STRSZ`必须成对出现。
- 只要存在重定位表或`DT_HASH`，必须存在`DT_SYMTAB`。
8.`DT_JMPREL`在`DT_PLTRELSZ==0`时，探测长度仍跟随`DT_PLTREL`类型：
- `DT_REL`使用`sizeof(Elf_Rel)`。
- `DT_RELA`使用`sizeof(Elf_Rela)`。
9.`DT_HASH`按两阶段校验：
- 先校验表头`2*sizeof(Elf_Word)`是否在`PT_LOAD`范围内。
- 再读取`nbucket/nchain`计算总字节数并做整表范围校验。

计算依据：
1.避免边读边写导致错误值扩散。
2.统一校验后再落指针，能把损坏输入拦在重建前。
3.地址边界以程序头语义为准，可同时拦截段间空洞与`padding`误判问题。

## 6.Elf_Rel与Elf_Rela重定位修正
函数：`RebuildRelocs()`、`relocate<>()`。

触发条件：`dump_so_base_!=0`。

修正规则：
1.重定位写入目标地址校验
- 每条重定位先校验`r_offset`对应的`sizeof(Elf_Addr)`写入区间是否被单个`PT_LOAD`完整覆盖。
- 校验使用`RangeInLoadSegments`，不接受落在`min_load~max_load`连续区间但位于段间空洞的地址。

2.相对重定位（`R_*_RELATIVE`）
- 若目标值`>=dump_base`，执行`target-=dump_base`。

3.导入重定位（`GLOB_DAT/JUMP_SLOT`）
- 有符号索引映射时，按导入槽位表写入稳定地址。
- 缺失符号信息时，按出现顺序分配回退导入槽。

4.`RELA`相对重定位
- 对`R_AARCH64_RELATIVE`、`R_X86_64_RELATIVE`，按`r_addend`回写目标。

计算依据：
1.转储中的重定位目标多为运行时绝对地址。
2.减去转储基址后，才能回到文件内可重定位地址语义。
3.重定位目标写入区间必须满足ELF段覆盖语义，避免段间空洞写入污染输出镜像。

## 7.Elf_Shdr字段重建
函数：`RebuildShdr()`。

### 7.1统一规则
1.不修旧节头，全部重建。
2.`sh_offset=sh_addr`，沿用镜像地址布局。
3.节头构建完成后按`sh_addr`排序。
4.排序后同步修正`sh_link`与内部节索引。

### 7.2关键节字段计算
1.`.dynsym`
- `sh_addr=offset(si.symtab)`。
- `sh_size=next_section.sh_addr-cur_section.sh_addr`。
- `sh_link=sDYNSTR`。

2.`.dynstr`
- `sh_addr=offset(si.strtab)`。
- `sh_size=si.strtabsize`。

3.`.hash`
- `sh_addr=offset(si.hash)`。
- `sh_size=(2+nbucket+nchain)*sizeof(Elf_Word)`。
- `sh_link=sDYNSYM`。

4.`.rel.dyn`
- `sh_addr=offset(si.rel)`。
- `sh_size=si.rel_count*sizeof(Elf_Rel)`。
- `sh_link=sDYNSYM`。

5.`.rela.dyn`
- `sh_addr=offset(si.plt_rela)`。
- `sh_size=si.plt_rela_count*sizeof(Elf_Rela)`。
- `sh_link=sDYNSYM`。

6.`.rel.plt/.rela.plt`
- `sh_addr=offset(si.plt_rel)`。
- `sh_size=si.plt_rel_count*sizeof(entry)`，`entry`由`DT_PLTREL`决定。
- `sh_link=sDYNSYM`。

7.`.dynamic`
- `sh_addr=offset(si.dynamic)`。
- `sh_size=si.dynamic_count*sizeof(Elf_Dyn)`。
- `sh_link=sDYNSTR`。

8.`.init_array/.fini_array`
- `sh_addr=offset(si.init_array/si.fini_array)`。
- `sh_size=count*sizeof(Elf_Addr)`。

9.`.data`
- `sh_addr=max_end(所有SHF_ALLOC节)`。
- `sh_size=si.max_load-sh_addr`。
- 若`sh_addr>si.max_load`，直接报错并终止重建。

10.`.shstrtab`
- `sh_addr=si.max_load`。
- `sh_size=shstrtab.length()`。

计算依据：
1.节地址优先来源于动态段解析结果。
2.节头表只负责把已验证地址组织成标准节描述。

## 8.输出拼装与ELF头回写
函数：`RebuildFin()`。

输出布局：
1.`[0,file_load_end)`：加载镜像数据。
2.`[file_load_end,shdr_off)`：`.shstrtab`。
3.`[shdr_off,shdr_off+shdr_bytes)`：节头表。

关键公式：
1.`file_load_end=si.max_load`。
2.`shdr_bytes=shdrs.size()*sizeof(Elf_Shdr)`。
3.`shdr_off=file_load_end+shstr_size`。
4.`rebuild_size=file_load_end+shstr_size+shdr_bytes`。
5.对每个非`SHT_NOBITS`且`sh_size>0`的节，校验`[sh_offset,sh_offset+sh_size)`必须落在`rebuild_size`内。

头字段回写：
1.`ehdr.e_type=ET_DYN`。
2.`ehdr.e_shnum=shdrs.size()`。
3.`ehdr.e_shoff=shdr_off`。
4.`ehdr.e_shstrndx=sSHSTRTAB`。

计算依据：
1.节头表和节名字串在输出中的位置已变化，必须用新偏移覆盖旧值。
2.若不回写，`readelf`会按旧偏移读取错误位置。

## 9.libsgmainso.dump字段修正示例
### 9.1执行命令
```bash
./build-review64/SoFixer64 \
  -m 0x7b17877000 \
  -s /Volumes/macOS/libsgmainso.dump \
  -o /tmp/libsgmainso.fixed.latest.so
```

### 9.2Elf_Ehdr前后对照
输入：
- `e_shoff=0x212b30`
- `e_shnum=25`
- `e_shstrndx=24`

输出：
- `e_shoff=0x223071`
- `e_shnum=13`
- `e_shstrndx=12`

`e_shoff`计算：
- `file_load_end=0x223000`
- `shstr_size=0x71`
- `e_shoff=0x223000+0x71=0x223071`

### 9.3Elf_Phdr前后对照
1.`PT_LOAD[0]`
- 输入：`p_filesz/p_memsz=0x202950/0x202950`
- 输出：`p_filesz/p_memsz=0x212950/0x212950`
- 计算：`0x212950-0x0=0x212950`

2.`PT_LOAD[1]`
- 输入：`p_offset=0x202950`，`p_memsz=0x95668`
- 输出：`p_offset=0x212950`，`p_memsz=0x106b0`
- 计算：`0x223000-0x212950=0x106b0`

3.`PT_DYNAMIC`
- 输入：`p_offset=0x20ce80`
- 输出：`p_offset=0x21ce80`
- 依据：统一布局`p_offset=p_vaddr`

### 9.4Elf_Dyn前后对照
输入动态段：仅`1`条`DT_NULL`。

输出动态段：`.dynamic`段头大小为`0x210`，对应`33`个`Elf_Dyn`槽位；`llvm-readelf -d`读取到`29`条条目并在`DT_NULL`处终止，关键字段如下。
- `DT_HASH=0x228`
- `DT_SYMTAB=0x1408`
- `DT_STRTAB=0x4e40`
- `DT_RELA=0x74c8`
- `DT_RELASZ=119976`
- `DT_JMPREL=0x24970`
- `DT_PLTRELSZ=7368`
- `DT_INIT_ARRAY=0x212950`
- `DT_FINI_ARRAY=0x212958`

### 9.5Elf_Shdr结果
输出共`13`个节头，关键字段如下。
- `.hash`：`sh_addr=0x228`，`sh_size=0x11e0`
- `.dynsym`：`sh_addr=0x1408`，`sh_size=0x3a38`
- `.dynstr`：`sh_addr=0x4e40`，`sh_size=0x2147`
- `.rela.dyn`：`sh_addr=0x74c8`，`sh_size=0x1d4a8`
- `.rela.plt`：`sh_addr=0x24970`，`sh_size=0x1cc8`
- `.dynamic`：`sh_addr=0x21ce80`，`sh_size=0x210`
- `.shstrtab`：`sh_addr=0x223000`，`sh_size=0x71`

### 9.6输出大小校验
- `file_load_end=0x223000`
- `shstr_size=0x71`
- `shdr_bytes=13*0x40=0x340`
- `rebuild_size=0x223000+0x71+0x340=0x2233b1`

输出文件实际大小：`2241457`字节，即`0x2233b1`。
