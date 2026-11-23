"""Student-facing recipes distilled from the supplied disk and memory decks."""
def step(title,why,action,params=None,**extra):return dict(title=title,why=why,action=action,params=params or {},**extra)
RECIPES=[]
def recipe(identity,category,title,clue,source,steps,check):RECIPES.append(dict(id=identity,category=category,title=title,clue=clue,source=source,steps=steps,check=check))

recipe('unknown','file','陌生附件从哪里开始','扩展名不可信、没有明确提示时，先回答文件是什么，再决定后续路线。','基础流程',[
 step('识别结构','签名和内部结构比文件名更可靠。','file_type'),step('查看原始字节','确认签名、字节序、长度与可疑位置。','hex_view'),step('全文件线索检索','先检查直接可读与 UTF-16LE 文本，避免一开始盲猜复杂隐写。','keyword_search'),step('综合分流报告','按实际格式串联对应工具，并查看报告中的覆盖范围。','auto_analyze')],'记录来源字段、偏移与验证方式，不能仅提交工具猜测。')
recipe('disk-deleted','disk','磁盘目录与删除恢复','题目提示误删、回收站或重要文件消失。先确认文件系统，再按元数据恢复。','磁盘 PPT 10–15、34–35 页',[
 step('识别分区和目录','整盘和裸文件系统的起点不同；工具先验证起点再列出条目。','disk_inventory'),step('筛出删除项','删除标记是恢复候选，不保证数据还在；可增加路径关键词。','disk_inventory',{'mode':'deleted'}),step('批量恢复并记录来源','按当前镜像的元数据编号导出，完整结果与部分输出分开。','disk_batch_recover',{'mode':'deleted'}),step('目录恢复不完整时改用签名','PhotoRec 从数据内容寻找格式，通常不能保留原文件名与目录。','disk_photorec'),step('验证恢复内容','从结果区选择真实导出文件作为输入，再识别、解压或检索。','auto_analyze',input_hint='请选择恢复结果中的文件')],'对恢复结果检查类型、大小、完整性和 SHA256，注明未覆盖或无法恢复的范围。')
recipe('disk-timeline','disk','文件时间线与异常变更','题目提示 Timeline、某时刻发生的操作，或普通目录和关键词检索没有直接线索。','磁盘取证补充路线',[
 step('验证文件系统与起点','时间线必须基于正确分区解析，裸分区通常从 0 开始。','disk_inventory'),step('生成 MACB 时间线','先汇总全部文件时间，观察集中操作时间和离群时间；C 是元数据变更，不是创建。','disk_timeline'),step('缩小时间和路径范围','根据实际结果填写 UTC 时间范围、路径或时间类型；CSV 保存全部匹配事件。','disk_timeline'),step('核对 inode 详细信息','将时间线中的本次元数据编号填入，复核大小、时间与数据块。','disk_istat',{'sector':'0','inode':''}),step('导出并验证内容','按实际编号导出，选择输出继续预览文本或识别文件。','disk_recover',{'sector':'0','inode':''})],'时间先后不单独证明现实操作，时间戳也可能被修改。先从文件内容确认线索，再决定是否需要排序拼接或解码。')
recipe('ext-journal','disk','Ext3 / Ext4 删除文件','镜像是 Linux 分区，提示日志、inode 或被删除的文本。','磁盘 PPT 10–15 页',[
 step('确认 Ext 文件系统与起点','fsstat 的结果决定能否使用 Ext 工具，不能只凭 .img 命名。','disk_inventory'),step('先尝试元数据恢复','TSK 可以直接读取工作副本，不要求先在系统挂载。','disk_batch_recover',{'mode':'deleted'}),step('在未挂载副本上做日志恢复','extundelete 在 Kali 运行；Windows 此步给出适用条件与可直接运行的替代。','disk_extundelete'),step('补查签名与原始文本','日志不完整或特性不受支持时，保留失败诊断再走其他证据路线。','disk_photorec',{'partition':'none'})],'PPT 的先挂载观察不意味着恢复时仍应挂载。Ext4 只读观察使用 noload，日志恢复前卸载。')
recipe('virtual-disk','disk','VMDK / 虚拟机磁盘','只有 vmx、vmdk 或分片镜像，需要找到桌面、用户目录和浏览器数据。','磁盘 PPT 21–29 页',[
 step('浏览镜像里的路径','vmx 是配置，vmdk 才是磁盘内容；先找到用户目录，避免全盘乱提取。','disk_inventory'),step('按路径导出所需文件','可筛选 Desktop、桌面、places.sqlite 或 History，依据实际目录选择。','disk_batch_recover',{'mode':'all'}),step('必要时转换 RAW 工作副本','转换读取逻辑磁盘内容，便于后续按分区挂载；相邻分片必须齐全。','disk_image_convert'),step('继续分析导出附件','浏览器数据库、图片与压缩包采用不同路线，从导出列表换输入。','auto_analyze',input_hint='请选择从虚拟磁盘导出的文件')],'虚拟磁盘容器的文件偏移与其中逻辑磁盘偏移不同；用后端解析，不直接套载体字节偏移。')
recipe('nested','file','文件中还有文件','签名扫描出现 ZIP、PNG 或压缩流，或图片尾部有额外字节。','磁盘 PPT 23 页',[
 step('自动验证边界并分离','签名只负责发现候选，结构解析决定导出范围；查看分离清单。','separate_files'),step('先列出再展开压缩对象','选择分离的 ZIP / 7z 等附件，检查口令与条目后受限提取。','archive_general',{'mode':'extract'},input_hint='请选择已分离的压缩包'),step('继续检查子文件','嵌套题可能需要再次分离；始终保留父文件与偏移来源。','separate_files',input_hint='请选择实际解压出的子文件'),step('检索或自动识别','分离成功还需要验证内容，导出的文本、数据库和图片都能继续分析。','auto_analyze',input_hint='请选择待检查的导出文件')],'PNG 以 IEND、ZIP 以目录 / EOCD 等确定边界。PDF 增量更新和碎片文件仍需复核，不把任意 PK 命中当作完整 ZIP。')
recipe('browser','disk','浏览器历史与身份线索','恢复出 Firefox places.sqlite 或 Chromium History，要找访问时间、URL、账号线索。','磁盘 PPT 24–28 页',[
 step('核对表结构','不同浏览器版本字段会变化，先看真实表和列。','sqlite_tables'),step('关联访问历史与 URL','识别常见结构后联合查询，保留原始时间并明确换算成 UTC。','browser_history'),step('按实际字段继续只读查询','用已确认的字段筛选用户、网站、下载路径或时间范围。','sqlite_query'),step('验证候选口令线索','如果题目给出摘要与有依据的候选，离线验证；哈希不等于可以直接解密。','hash_tools',{'mode':'dictionary'})],'数据库记录属于样本中的活动痕迹。账号或 URL 的存在不能单独证明现实身份，WAL / SHM 应一同保留。')
recipe('container','disk','已知口令的加密容器','镜像没有可识别文件系统，同时题意给出 VeraCrypt 或容器口令线索。','磁盘 PPT 30–37 页',[
 step('先验证编码线索','核心价值观、Base64 等属于编码层；先还原候选口令并记录来源。','codec',{'operation':'core_values_decode'}),step('准备只读容器挂载','输入自己的已知口令、PIM / keyfile，查看方式与空闲盘符。','disk_mount',{'method':'veracrypt','mode':'plan'}),step('挂载后查看与导入','只读取本工作区创建的挂载卷，文件复制进任务目录后再分析。','mounted_files',{'mode':'list'}),step('用后续线索解码或解密','选导入文件继续转换；凯撒候选全不合理时也要考虑键盘编码、双拼等提示。','codec',{'operation':'caesar_all'})],'高熵与无法识别只是加密候选。现代 VeraCrypt、历史 TrueCrypt 与普通 AES 数据不能混用挂载或密钥参数。')
recipe('mount','disk','只读挂载与卸载','需要像查看普通盘符那样观察镜像内容，或把容器内文件带回工作台。','磁盘 PPT 11、14、32–35 页',[
 step('确认分区和文件系统','从目录工具取得实际起点；Windows 没有原生 Ext4 浏览支持时走 TSK。','disk_inventory'),step('查看挂载准备','RAW 分区选 ImDisk，ISO/VHD/VHDX 可用 Windows；不会自动格式化或写回镜像。','disk_mount',{'mode':'plan'}),step('首次准备驱动','只有需要 ImDisk 系统挂载时才安装随包驱动；按系统 UAC 完成。','disk_mount',{'mode':'install_imdisk','method':'imdisk'}),step('执行只读挂载','选择空闲 R～Z 盘符，填入已验证起点；完成后可浏览和导入。','disk_mount',{'mode':'mount'}),step('结束后卸载','仅允许卸载本工作区记录的挂载卷，避免操作其他磁盘。','disk_mount',{'mode':'unmount'})],'目录查看和数据恢复可不挂载。系统挂载状态与分析任务状态不同，完成报告不代表卷已卸载。')
recipe('memory-start','memory','内存题基础盘点','真实 RAM 到手，先确定系统解析是否可靠，再建立进程与文件视图。','内存 PPT 3、5、9–10、19–20 页',[
 step('确认系统解析','Vol3 检查层和符号；Vol2 先识别候选，profile 需再核对。','vol_info',v2_action='vol2_identify'),step('按题意生成盘点报告','按所选版本运行进程、参数与文件链，不对空输出作过度推断。','memory_triage',{'route':'general'}),step('看启动参数与脚本路径','PID 来自当前进程清单；命令行参数可能提供路径或编码线索。','vol_cmdline',{'pid':''},v2_action='vol2_processes',v2_params={'plugin':'cmdline','pid':''}),step('定向导出后验证','依据明确的文件对象地址或进程 PID 导出，不能照抄示例地址。','vol_dumpfiles',{'address':''},v2_action='vol2_dumpfiles',v2_params={'address':''})],'先让 info / KDBG 与进程结果相互支持。CSV、截图和合成片段不能交给 Volatility 当作 RAM。')
recipe('memory-history','memory','终端历史与命令参数','题目问执行过什么、脚本路径、上传 / 删除动作或控制台输出。','内存 PPT 18–21、26、38–41 页',[
 step('启动参数与历史一起看','cmdline 与交互历史是不同对象，先关联进程再恢复控制台。','memory_triage',{'route':'history'}),step('补看屏幕缓冲上下文','consoles 可能包含输出；命令历史本身不保证命令成功执行。','vol_history',{'plugin':'consoles'},v2_action='vol2_history',v2_params={'plugin':'consoles'}),step('追踪命令提到的文件','从本次 filescan 取得对象候选，并与进程句柄、路径交叉验证。','vol_files',v2_action='vol2_files'),step('还原参数中的编码','选择参数原值，只解码数据；无需执行恢复出的未知脚本。','codec',{'operation':'base64_decode'})],'Win7 等系统若 Vol3 控制台插件不支持，切 Vol2 并核对 profile，不把结构错误当成没有历史。')
recipe('memory-file','memory','从进程追到文件缓存','题目提到桌面文本、图片、压缩包，进程参数或历史中出现文件路径。','磁盘 PPT 16–20；内存 PPT 27–29、32–33、40–42 页',[
 step('进程与文件对象盘点','先收集参数和文件对象，按题意筛选路径。','memory_triage',{'route':'files'}),step('用句柄建立进程关联','同名路径可能有多个对象；句柄将当前 PID 与 File 对象联系起来。','vol_handles',{'pid':''},v2_action='vol2_files'),step('按正确地址类型导出','Vol3 要区分虚拟 / 物理 FILE_OBJECT；Vol2 -Q 使用当前 Offset(P)。','vol_dumpfiles',{'address':''},v2_action='vol2_dumpfiles',v2_params={'address':''}),step('继续识别导出内容','导出文件可能是缓存片段，不一定完整或最新。先检查再解压、检索或解码。','auto_analyze',input_hint='请选择实际导出的文件')],'dumpfiles 失败只说明当前缓存导出未成功，不能单凭它断定磁盘文件已删除。可转 MFT 或目标进程页。')
recipe('memory-unsaved','memory','记事本与未保存文本','目标是编辑器中的文字；启动参数无文档路径只是线索，仍需确认题意。','内存 PPT 22–25、30–31 页',[
 step('确认目标编辑器 PID','同名进程可能多个，结合参数、父进程和时间选择。','vol_processes',v2_action='vol2_processes'),step('导出目标进程页','文字缓冲区可能不在程序本体中；Vol3 memmap 与 pslist --dump 不能互相替代。','vol_memmap',{'pid':''},v2_action='vol2_memdump',v2_params={'pid':''}),step('检查两种文本编码','UTF-16LE 常有交替零字节，ASCII 无命中并不排除文字存在。','strings',{'encoding':'both','scan_mib':'0'},input_hint='请选择进程导出文件'),step('核对命中原字节','文件中的偏移不是原 RAM 物理地址；要映射回去需保留映射表。','hex_view',input_hint='请选择进程导出文件')],'旧 XP 可尝试 Vol2 notepad，但其适用范围有限；恢复不到时保留诊断，再查进程页。')
recipe('memory-mft','memory','MFT、驻留数据与备用路线','文件对象可见但缓存导出失败，题意涉及 NTFS 删除项或很小的文本文件。','磁盘 PPT 19–20 页',[
 step('扫描 MFT 记录','MFT 含元数据，部分小文件内容可能驻留其中；不是所有文件都在 MFT 中。','vol_artifacts',{'plugin':'mftscan.MFTScan'},v2_action='vol2_artifacts',v2_params={'plugin':'mftparser'}),step('查看驻留内容 / 导出','Vol3 ResidentData 给出驻留数据；Vol2 mftparser 会保留可恢复输出。','vol_artifacts',{'plugin':'mftscan.ResidentData'},v2_action='vol2_artifacts',v2_params={'plugin':'mftparser'}),step('检查恢复结果','关联记录编号、文件名、状态和内容，不把扫描残留等同于当前文件。','keyword_search',input_hint='请选择本次 MFT 报告或导出文件')],'MFT 命中不意味着完整数据可恢复；非驻留内容、重用记录与碎片需要其他证据。')
recipe('registry','memory','主机名与注册表键值','题目问电脑名、系统设置或用户活动，需要先找到正确 Hive。','内存 PPT 51–53 页',[
 step('列出 Hive 与实际偏移','文件名与虚拟偏移把 SYSTEM 等 Hive 区分开，不照抄 PPT 地址。','vol_registry',{'plugin':'hivelist'},v2_action='vol2_registry',v2_params={'plugin':'hivelist'}),step('先查 Select','SYSTEM 的 Select\\Current 决定应查哪个 ControlSet。','vol_registry',{'plugin':'printkey','key':'Select','address':''},v2_action='vol2_registry',v2_params={'plugin':'printkey','key':'Select','address':''}),step('查询实际 ControlSet 的 ComputerName','按 Current 值修改键路径；001 只是示例，不是每份镜像都相同。','vol_registry',{'plugin':'printkey','key':'ControlSet001\\Control\\ComputerName\\ComputerName'},v2_action='vol2_registry',v2_params={'plugin':'printkey','key':'ControlSet001\\Control\\ComputerName\\ComputerName'})],'记录 Hive 来源、偏移、键和值。Select 选择的当前配置与其他残留 ControlSet 要区分。')
recipe('credentials','memory','样本账号与口令线索','题目明确问样本系统口令，需要区分账号哈希、明文线索与已知候选。','内存 PPT 22、48–50 页',[
 step('查看账号相关证据','使用随包 hashdump 与 Hive 信息；输出的 NTLM 哈希不是明文口令。','memory_triage',{'route':'credentials'}),step('解析支持的内存凭据','结合 LSASS 页面与系统布局，区分明文、哈希与会话字段；插件不适用时保留诊断。','vol_extra',{'plugin':'vol_pypykatz.pypykatz'},v2_action='vol2_extra',v2_params={'plugin':'mimikatz'}),step('验证有依据的候选','选择 NTLM 或题目实际算法，从有限字典验证；无候选或未命中不能声称恢复口令。','hash_tools',{'mode':'dictionary','algorithm':'ntlm'}),step('交叉验证业务含义','保留账号、RID / Hive 来源与候选验证，只有题目授权的样本范围用于解题。','vol_registry',{'plugin':'hivelist'},v2_action='vol2_registry',v2_params={'plugin':'hivelist'})],'PPT 中的 mimikatz 属于另行安装的社区插件，并非所有版本的 stock Volatility 插件。本包已安装 Vol2 mimikatz 与 Vol3 pypykatz，使用对应扩展入口；仍须核对支持范围。')
recipe('clipboard','memory','复制粘贴与剪贴板','题意明确给出复制粘贴、剪贴板或临时文本线索。','内存 PPT 58–59 页',[
 step('确认系统与目标进程','剪贴板结构依系统版本而异，先完成系统解析。','memory_triage',{'route':'clipboard'}),step('旧系统查询剪贴板','当前包提供 Vol2 clipboard；使用已核对的 profile。','vol2_artifacts',{'plugin':'clipboard'}),step('转目标进程页检索','插件不适用或内容已覆盖时，按实际 PID 导出并检索文本编码。','vol_memmap',{'pid':''},v2_action='vol2_memdump',v2_params={'pid':''})],'Vol3 版没有伪造 clipboard 入口。空输出既可能是版本或结构条件，也可能是页面缺失或覆盖。')
recipe('memory-container','memory','内存里的加密容器线索','同题同时提供 RAM 和容器，进程清单出现 TrueCrypt / VeraCrypt。','内存 PPT 7–17 页',[
 step('关联加密进程与参数','进程名是线索，要结合历史、路径和当前系统判断。','memory_triage',{'route':'container'}),step('检查兼容的口令 / 密钥插件','插件依赖特定历史版本和驱动结构。master key、口令和 keyfile 不能互换。','vol_artifacts',{'plugin':'truecrypt.Passphrase'},v2_action='vol2_artifacts',v2_params={'plugin':'truecryptmaster'}),step('导出目标进程作后续证据','从当前输出取得 PID，记录范围与缺页；不保证任意内存都含可用密钥。','vol_memmap',{'pid':''},v2_action='vol2_memdump',v2_params={'pid':''}),step('有可用口令后处理容器','切换当前文件为容器，再准备对应的只读挂载。','disk_mount',{'method':'truecrypt','mode':'plan'},input_hint='请选择题目提供的容器，并按实际格式选择 TrueCrypt 或 VeraCrypt')],'EFDD 是 PPT 所用的商业工具，未随包分发。这里保留标准插件、进程导出和已知口令挂载路线，不宣称能自动解开任何加密容器。')
recipe('script-reverse','crypto','恢复脚本后的逆变换','从记事本、缓存或附件恢复了算法片段，需要按相反顺序还原字节。','内存 PPT 30–36 页',[
 step('保留脚本与密文原值','先查看源码而不执行，明确字符范围、移位、替换和编码顺序。','text_preview'),step('逆转字符偏移','若源码对字符减了 32，逆步骤加 32；参数必须来自实际脚本。','codec',{'operation':'ascii_shift','shift':'32'}),step('逆转字母移位','PPT 示例的字母加 3 对应逆向减 3；输出可继续作为下一步文本。','codec',{'operation':'caesar','shift':'-3'}),step('恢复特殊字符映射','逐字符替换表处理脚本中的自定义映射；不能只跑一个通用凯撒就宣布完成。','codec',{'operation':'replace','mapping':'{"!":"_"}'})],'逆变换按加密顺序反向执行，每层保留原值、参数与结果。不同脚本不要照抄 PPT 的 32 或 3。')
recipe('codecs','crypto','编码、异或与常用解密','文件、元数据、参数或文本出现编码串，或题目给出算法与已知密钥。','磁盘 PPT 28、30–31、36–37；内存 PPT 24、34–36、41–46 页',[
 step('先验证字节表示','区分 Base64 / HEX / URL / UTF-16LE，外观只是候选，来源字段也要保留。','codec'),step('有线索时枚举简单变换','凯撒 26 种或单字节 XOR 256 种是有限候选，排序不是证明。','codec',{'operation':'caesar_all'}),step('已知算法与密钥时解密','按题目给出的密钥表示、IV、填充和认证标签执行，不混用模式。','cipher'),step('继续识别解码后的文件','如果结果是二进制，选择导出的 .bin 继续识别或自动分离。','auto_analyze',input_hint='请选择转换结果的完整字节文件')],'MD5 / NTLM 等是摘要，使用候选验证。复杂密文缺少密钥时不能保证解密；CyberChef 提供其他常见转换入口。')
recipe('image','image','图片结构与隐写','图片不能正常打开、尺寸异常，或题目提示通道、尾部和最低位。','基础图片流程',[
 step('先查元数据和结构','便宜的结构检查能区分标签、损坏与像素层问题。','auto_analyze',{'workflow':'image'}),step('查看与修复已定位字节','确认偏移和原值后只改副本，再做解析验证。','hex_view'),step('分离尾部对象','结构完整的图片仍可能带有附加文件，验证边界后导出。','separate_files'),step('按明确参数提取位流','通道、位、扫描顺序与组字节方式必须可复述。','lsb_custom')],'图片正常显示不代表没有其他数据。PNG 宽度恢复、签名修复与 LSB 是不同假设。')

recipe('memory-bitlocker','memory','BitLocker 与内存密钥候选','题目同时提供加密磁盘与 RAM，或明确提示 BitLocker。先确认关联，再对密钥候选做卷级验证。','社区插件补充路线',[
 step('核对内存系统与加密线索','先保证内存可正确解释，记录系统构建与加密进程，避免把不同题目的证据混用。','memory_triage',{'route':'container'}),step('扫描 FVEK 候选','Vol3 检查 AES 扩展密钥；Vol2 按其支持的池结构扫描。候选要结合卷算法和布局验证。','vol_extra',{'plugin':'bitlocker.BitlockerFVEKScan','dump':'yes'},v2_action='vol2_extra',v2_params={'plugin':'bitlocker','dump':'yes'}),step('核对同题磁盘卷头','切换到磁盘，检查实际分区起点和 -FVE-FS- 等结构；FVEK 不是普通密码，也不是 VeraCrypt keyfile。','hex_view',input_hint='选择同题磁盘镜像，并填入该卷的实际字节偏移')],'保留扫描诊断、候选偏移、卷算法与验证结果。工作台不把密钥候选等同于成功解锁；未提供对应加密卷时不能证明密钥有效。')

CATEGORIES=[('all','全部路线'),('disk','磁盘与恢复'),('memory','内存'),('crypto','编码与解密'),('file','文件与分离'),('image','图片')]

def guide():
    from portal import ACTIONS
    names={a['id']:a['title'] for a in ACTIONS}
    text='''# 按题意选择解题工作流 · 工作台指南

## 01 / 从附件到下一步

从 index.html 进入可视化工具台。顶部始终显示当前附件和常用操作。导入新题后，在左侧“解题流程”按目标选路线；中间解释每一步为何使用该工具。需要自由分析时切换“全部工具”，可搜索操作。

右侧分为结构与结果、导出文件、原始输出、运行命令。点击导出文件的“作为下一步输入”，会切换当前附件，并尽量进入该路线下一个需要导出文件的步骤。原结果仍保留，最近记录可以重新打开。

内存路线可选择 Vol3 或 Vol2。profile、PID、Hive 偏移和 FILE_OBJECT 地址按当前附件记录；换镜像后重新识别。字段值来自本题的实际输出，不照抄 PPT 截图中的地址。相同工作区只运行有限并发任务，批量导入会排队。

## 02 / Windows 与 Kali 能力

| 能力 | Windows 完整包 | Kali / Linux |
|---|---|---|
| 十六进制分页、字节搜索、等长副本补丁 | 随包 Python，直接在工具台运行 | 使用资料包 Python 脚本 |
| TSK 目录、删除项、单项 / 批量恢复、镜像转换 | 随包 TSK，支持其构建识别的 RAW / E01 / VMDK / VHD | 安装 sleuthkit 后运行 |
| MACB 文件时间线、UTC 时间与路径筛选 | 随包 TSK 与 Python，保存 body 和完整 CSV | 安装 sleuthkit 后使用同一代码 |
| 自动文件分离 | 随包结构分离脚本，保留边界验证和来源 | 同一 Python 代码；PDF 验证需 pypdf |
| PhotoRec 签名恢复 | 随包官方 7.2；只对附件镜像运行，无需访问物理磁盘 | 安装 testdisk |
| Ext 日志恢复 | 提供 TSK 与 PhotoRec 替代；未冒充 Windows extundelete | 安装 extundelete，在未挂载的 Ext 分区副本运行 |
| 编码 / 核心价值观 / 凯撒 / XOR | 随包 Python | Python；图像与 PDF 等仍按原环境准备 |
| AES / DES / 3DES / RC4 与 NTLM 候选验证 | 已集成 PyCryptodome | 为平台 Python 安装 PyCryptodome |
| RAW 分区只读盘符 | 随包 ImDisk；首次系统挂载需准备驱动与 UAC | 工作台生成只读挂载脚本，在终端使用 sudo |
| ISO / VHD / VHDX 只读挂载 | 使用 Windows 自带 Mount-DiskImage | 按当前格式与系统工具选择挂载方式 |
| VeraCrypt / TrueCrypt 已知口令容器 | 随包 1.26.29 与旧格式兼容的 1.25.9，操作时可能需 UAC | 自行准备对应 VeraCrypt；生成终端脚本 |
| Vol3 / Vol2 | 两套入口并存，插件列表与当前包版本一致 | Vol3 环境和随包 Vol2 Linux 独立程序 |

Kali 环境补充命令，先按原讲义准备平台 Python，再安装新增依赖：

~~~bash setup
sudo apt update
sudo apt install sleuthkit testdisk extundelete 7zip libimage-exiftool-perl pngcheck python3-venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome==4.1.0 pillow pypdf pefile yara-python volatility3 pypykatz==0.6.13
bash 启动学习平台.sh
~~~

启动脚本优先使用激活环境的 Python。Windows 直接用完整包启动器，不执行上面的 apt 命令，也不需要另装 Python 2。

## 03 / 数据恢复与文件分离的区别

目录恢复先找分区 / 文件系统，再由 fls 的元数据编号交给 icat。批量工具保留每项原路径、分区起点、命令与 SHA256；失败或预算截断的内容以 .partial 标注，不能算作完整恢复。

PhotoRec 从内容签名雕刻，适用于目录结构不可用时的补充。它不保证恢复原文件名、目录、碎片或被覆盖内容。Windows 镜像分析子进程使用普通用户权限读取附件，不会扫描物理磁盘。

自动分离支持常见 PNG、JPEG、GIF、经典单卷 ZIP、7z、GZIP、BZIP2、XZ、RIFF、SQLite 与 PDF 候选。PNG 检查块边界与 CRC；ZIP 核对中央目录与 EOCD，适用大小范围内再验证 CRC；压缩流通过流结束位置定界。ZIP64、特殊容器、碎片以及 PDF 增量更新需要其他工具或人工复核。

默认每个对象最多验证 64 MiB，导出有总预算、文件数与递归深度限制。分离清单中 offset 属于该行 source，不同层的偏移不能直接相加成原镜像地址。选择导出的压缩对象继续解压，或用综合分析的嵌套附件流程进一步检查。

## 04 / 十六进制与加解密

十六进制查看支持分页、定位和单字节选择；搜索可以使用 HEX、UTF-8 或 UTF-16LE，命中后直接跳回原字节。补丁工具只在新副本上覆盖等长字节，填写预期原值可以防止改错位置；修改之后仍要用格式解析器验证。

编码转换支持文本与完整文件输入。HEX / Base64 表示先还原字节，再进入选定操作；不要把整个二进制载体直接当作 Base64。输出 .bin 保存完整字节，UTF-8、HEX 与 Base64 只是预览。预览截断时改用 .bin 文件继续下一步。

AES 等算法必须明确密钥、模式、IV / nonce、填充，以及适用的 tag。GCM 解密使用认证验证；CBC / ECB / CTR 的可读输出不单独保证正确。凯撒与单字节 XOR 展示有限候选，排序只是线索。MD5 / SHA / NTLM 是摘要，本工具做候选验证，不承诺任意哈希还原。私密参数不写入运行报告，后续复现时重新输入。

PPT 的自定义脚本应先阅读，再按相反顺序还原各层操作。工作台支持码位加减、凯撒与逐字符替换表，未执行恢复出的未知脚本。小鹤双拼一类键盘编码可能有歧义，26 个凯撒候选都不合理时，要回到题目线索判断。

## 05 / 只读挂载

普通目录查看和恢复不要求系统挂载。需要盘符时，先查看准备与命令，再选择 R～Z 空闲盘符。ImDisk 挂载 RAW 分区时字节偏移等于起始扇区乘扇区字节数；VMDK 等虚拟容器可先通过 TSK 直接浏览，或转 RAW 副本。

系统挂载与驱动安装按实际系统权限执行，可能出现 UAC；取消后显示失败原因。程序只请求只读挂载，不提供格式化或写回功能。Windows 不自带 Ext4 文件系统驱动，因此 Ext 镜像优先用 TSK，或在 Kali 用 ro,noload 方式观察，日志恢复前卸载。

挂载后，使用“浏览挂载盘 / 导入文件”把文件复制进任务目录继续分析。程序跳过符号链接和重解析点，仅接受本工作区创建且卷身份未改变的挂载记录。最后用同一工作区卸载，关闭分析报告不会自动卸载盘符。

VeraCrypt 入口处理已知口令、PIM 或 keyfile 的容器；内存中找到的原始 master key 不能直接当成普通 keyfile。随包 VeraCrypt 1.26.29 已移除 TrueCrypt 模式；旧 TrueCrypt 容器请在挂载方式选择“TrueCrypt · 1.25.9 兼容模式”，使用随包的 1.25.9 和 /truecrypt。Kali 需自行准备支持该模式的版本。不能仅凭进程名称确定容器格式。

## 06 / PPT 对照路线

参考材料为用户提供的《磁盘取证》38 页与《内存取证》60 页。下列路线采用其题目线索与推理顺序，并对当前工具、版本和证据边界作出区分。未提供原题镜像时，不把 PPT 截图或合成数据冒充真实题目实测。

'''
    for i,r in enumerate(RECIPES,1):
        text+=f"## 路线 {i:02} / {r['title']}\n\n题意线索：{r['clue']}\n\n参考：{r['source']}。\n\n| 步骤 | 为什么做 | 工具台操作 |\n|---|---|---|\n"
        for n,s in enumerate(r['steps'],1):text+=f"| {n}. {s['title']} | {s['why']} | {names.get(s['action'],s['action'])}"+(f"；Vol2：{names.get(s['v2_action'],s['v2_action'])}" if s.get('v2_action') else '')+' |\n'
        text+='\n验证条件：'+r['check']+'\n\n'
    text+='''## 参考资料与版本依据

- PhotoRec 脚本参数：https://www.cgsecurity.org/testdisk_doc/scripted_run.html
- ImDisk 官方分发、源码与许可：https://www.ltr-data.se/opencode.html
- VeraCrypt Windows 命令：https://veracrypt.io/en/Command%20Line%20Usage%20for%20Windows.html
- Kali extundelete：https://www.kali.org/tools/extundelete/
- Volatility 2 标准插件：https://github.com/volatilityfoundation/volatility/wiki/Command-Reference
- PyCryptodome 算法接口：https://www.pycryptodome.org/

随包来源、版本、许可证和 SHA256 见 TOOL_MANIFEST.json、tools/EXTRA_SOURCES.json 与 licenses/source。EFDD 未分发；mimikatz / pypykatz 与 BitLocker 社区扩展已随包安装，详细命令见 Volatility 社区插件使用指南。
'''
    return text
