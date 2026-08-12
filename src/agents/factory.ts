// 共享 agent 系统工厂：CLI 与 VSCode 唯一真相源。
// toolRegistry 跨会话共享（无状态，外部构建一次）；permissionManager 与 contextManager 按会话独立。

import { ContextManager, type ContextConfig } from "../context/context-manager";
import { ToolRegistry } from "../tools/registry";
import { SubAgent } from "./sub-agent";
import { Scheduler } from "./scheduler";
import { MainAgent } from "./main-agent";
import { ToolExecutor } from "./tool-executor";
import type { PermissionManager } from "../permissions/permission-manager";

export interface AgentSystem {
  mainAgent: MainAgent;
  scheduler: Scheduler;
  contextManager: ContextManager;
  permissionManager: PermissionManager;
  toolExecutor: ToolExecutor;
}

export interface CreateAgentSystemOptions {
  /** 共享工具注册表（外部构建一次，跨会话复用） */
  toolRegistry: ToolRegistry;
  /** 按会话独立的权限管理器 */
  permissionManager: PermissionManager;
  /** MainAgent 最大步数，默认 30 */
  maxSteps?: number;
}

export const DEFAULT_MAIN_MAX_STEPS = 30;
export const DEFAULT_SUB_MAX_STEPS = 8;

export const DEFAULT_CONTEXT_CONFIG: Partial<ContextConfig> = {
  maxContextTokens: 8000,
  summaryThresholdTokens: 4000,
  windowMessages: 10,
};

/**
 * 构建单会话 agent 图：1 主 ContextManager + 5 预设 SubAgent（各自独立 context）+
 * Scheduler（注入共享 toolExecutor）+ 共享 ToolExecutor + MainAgent。
 * 同步返回（无 LLM 调用）。
 */
export function createAgentSystem(
  opts: CreateAgentSystemOptions
): AgentSystem {
  const { toolRegistry, permissionManager } = opts;
  const maxSteps = opts.maxSteps ?? DEFAULT_MAIN_MAX_STEPS;

  const contextManager = new ContextManager(DEFAULT_CONTEXT_CONFIG);

  // 统一执行入口（含权限确认 + 并发限流），供 MainAgent 与所有 SubAgent 共用
  const toolExecutor = new ToolExecutor(toolRegistry, permissionManager);

  const webAgent = new SubAgent(
    {
      id: "web",
      name: "Web安全专家",
      role: "Web攻防专家",
      systemPrompt: `你是 Web 安全专家。精通 HTTP 协议、SQL 注入、XSS、SSRF、SSTI、命令注入、反序列化、文件包含、文件上传等 Web 攻防技术。
当遇到 Web 类题目时，你应该按以下步骤进行：
1. 信息收集：用 http_request 访问目标，用 port_scan 和 dir_bruteforce 探测可见面
2. 漏洞扫描：针对参数使用 sql_injection_test、xss_test、command_injection_test、lfi_rfi_test
3. 高级测试：使用 ssrf_test 检测内网访问、ssti_test 检测模板注入、deserialization_test 检测反序列化、file_upload_test 检测上传漏洞
4. 安全分析：使用 header_analysis 检查安全头、ssl_info 检查 TLS 配置、dns_lookup 解析域名
5. 综合利用：分析所有结果，给出完整的攻击路径和利用建议
请始终使用中文回复。`,
      toolNames: [
        "http_request", "port_scan", "dir_bruteforce", "dns_lookup", "ssl_info",
        "sql_injection_test", "xss_test", "command_injection_test", "lfi_rfi_test",
        "ssrf_test", "ssti_test", "deserialization_test", "file_upload_test",
        "header_analysis",
      ],
      crossCategoryToolNames: [
        // Web 高级
        "waf_cdn_detect", "cors_audit", "jwt_attack", "csrf_audit",
        "xxe_test", "graphql_attack", "csp_audit", "saml_oauth_audit",
        "websocket_audit", "auth_bypass", "race_condition",
        // 数据库联动
        "db_connect_brute", "db_enum", "redis_attack", "nosql_scan",
        "sqlmap_advanced", "sqlite_exploit", "mssql_exploit",
        // Web 题中常出现的编码解码扩展（XSS payload / 参数编码绕过）
        "html_entity_codec", "js_escape_codec", "qp_mime_codec", "ascii_unicode_codec",
        "base_family", "radix_convert",
        // 系统/杂项
        "command_exec", "file_read_real", "file_write_real", "grep_search",
        "web_fetch",
      ],
      contextManager: new ContextManager(),
      toolExecutor,
      maxSteps: DEFAULT_SUB_MAX_STEPS,
    },
    toolRegistry
  );

  const pwnAgent = new SubAgent(
    {
      id: "pwn",
      name: "Pwn专家",
      role: "二进制漏洞挖掘与利用专家",
      systemPrompt: `你是 Pwn 专家。精通二进制漏洞挖掘与利用。
当遇到 Pwn 类题目时，你应该按以下步骤进行：
1. 初步分析：用 binary_analysis 检查文件类型、架构、保护机制（Canary/NX/PIE/RELRO），或直接用 pwn_static_analysis 一次性获取全部静态信息
2. 环境检查：用 pwn_check_env 确认本机 pwntools/qemu/架构支持情况
3. 信息提取：用 extract_strings 提取关键字符串（/bin/sh、flag 格式、系统调用名等），用 pwn_nm 查看完整符号表
4. 漏洞扫描：用 vulnerability_scan 扫描危险函数调用（strcpy/gets/sprintf/system等）
5. 深入反汇编：用 disassemble 或 pwn_objdump 查看完整反汇编/符号/节，用 pwn_radare2 进行交互式分析（strings/find/functions/disasm）
6. 保护机制：用 pwn_checksec 获取专业级 checksec（Canary/NX/PIE/RELRO/Fortify）
7. GOT/PLT：用 elf_got_plt_analysis 分析动态链接，用 hex_view 查看二进制结构
8. ROP：用 pwn_rop_gadget 搜索可用 ROP gadget
9. 利用规划：用 memory_layout 分析栈/堆布局，根据漏洞类型用 exploit_template 生成 pwntools 利用模板
10. 远程交互：用 nc_remote_client 连接远程服务测试，或用 pwn_run_exploit 一步执行完整 pwntools 脚本
11. 策略选择：根据保护机制选择 ret2libc/ROP/ret2shellcode/UAF/格式化字符串等利用方式
请始终使用中文回复。`,
      toolNames: [
        "binary_analysis", "extract_strings", "vulnerability_scan",
        "disassemble", "hex_view", "elf_got_plt_analysis",
        "exploit_template", "nc_remote_client", "memory_layout",
        "pwn_static_analysis", "pwn_check_env", "pwn_run_exploit",
        "pwn_objdump", "pwn_checksec", "pwn_radare2",
        "pwn_rop_gadget", "pwn_nm",
      ],
      crossCategoryToolNames: [
        // Pwn 得到 foothold 后最常用的本地提权枚举
        "suid_cap_audit", "process_service_audit", "kernel_exploit_match",
        "file_permission_audit", "firewall_network_audit", "ssh_crack", "linpeas_report",
        // 容器/内存取证联动
        "container_escape_test", "memory_forensics", "pcap_deep_analyze",
        "command_exec", "file_read_real", "file_write_real", "grep_search",
        "hex_view",
      ],
      contextManager: new ContextManager(),
      toolExecutor,
      maxSteps: DEFAULT_SUB_MAX_STEPS,
    },
    toolRegistry
  );

  const reverseAgent = new SubAgent(
    {
      id: "reverse",
      name: "逆向专家",
      role: "逆向工程与代码分析专家",
      systemPrompt: `你是逆向工程专家。精通二进制逆向分析、代码还原和混淆对抗。
当遇到 Reverse 类题目时，你应该按以下步骤进行：
1. 初步识别：用 binary_analysis 识别文件类型（ELF/PE/Mach-O/DEX）和架构
2. 信息提取：用 extract_strings 提取关键字符串和提示信息
3. 代码分析：用 disassemble 查看反汇编，用 pseudocode_gen 生成伪代码
4. 保护检测：用 packer_detect 检查壳（UPX/VMProtect/PyInstaller等），用 code_deobfuscate 检测混淆
5. 文件对比：用 binary_compare 比较两个文件的差异（补丁分析）
6. 特定分析：APK文件用 apk_analysis，.NET/Java 用 dotnet_decompile，JS代码用 js_deobfuscate
7. 辅助查看：用 hex_view 查看 Hex 视图
请始终使用中文回复。`,
      toolNames: [
        "binary_analysis", "extract_strings", "disassemble",
        "packer_detect", "code_deobfuscate", "binary_compare",
        "apk_analysis", "hex_view", "pseudocode_gen",
        "js_deobfuscate", "dotnet_decompile",
      ],
      crossCategoryToolNames: [
        // Mobile 逆向（APK/Smali/Frida/IPA）
        "apk_deep_analysis", "dex_decompile", "smali_edit", "frida_hook",
        "ipa_analysis", "ssl_pinning_bypass",
        // PWN 进阶反汇编
        "pwn_objdump", "pwn_radare2", "pwn_checksec", "pwn_nm",
        // 编码/密码辅助（含本次新增扩展，解混淆常见 Base/RSA 分析/古典密码）
        "encode_decode", "classical_cipher", "hash_compute", "hash_crack",
        "base_family", "uu_xx_pp_encode", "qp_mime_codec", "html_entity_codec",
        "js_escape_codec", "radix_convert", "punycode_codec", "ascii_unicode_codec",
        "affine_cipher", "atbash_cipher", "vigenere_family", "railfence_cipher",
        "adfgvx_cipher", "columnar_transposition", "baconian_cipher", "playfair_family",
        "rc4_stream", "block_cipher_ext", "rsa_key_parser", "freq_ic_analysis", "pkcs7_padding",
        // 混淆语言家族（BF / Morse / 敲击码 / JSFuck / AAEncode / JJEncode / Malbolge）
        "brainfuck_family", "morse_code", "tap_code", "ctf_obfuscator_hub", "malbolge_run",
        "command_exec", "file_read_real", "file_write_real", "grep_search",
      ],
      contextManager: new ContextManager(),
      toolExecutor,
      maxSteps: DEFAULT_SUB_MAX_STEPS,
    },
    toolRegistry
  );

  const cryptoAgent = new SubAgent(
    {
      id: "crypto",
      name: "密码学专家",
      role: "密码分析与破解专家",
      systemPrompt: `你是密码学专家。精通各种加密算法的分析、破解和数学工具。
当遇到 Crypto 类题目时，你应该按以下步骤进行：
1. 类型判断：识别加密类型（对称/非对称/哈希/古典密码/协议）
2. 编码处理：用 encode_decode 进行 Base64/Hex/URL 等编码转换
3. 哈希分析：用 hash_compute 验证哈希，用 hash_crack 尝试彩虹表破解
4. 古典密码：用 classical_cipher 处理凯撒/维吉尼亚/XOR/栅栏/仿射等古典密码
5. 对称加密：用 aes_encrypt/des_encrypt 处理 AES/DES 的加解密
6. RSA 攻击：用 rsa_tool 基础操作，用 rsa_advanced 进行共模/Wiener/Håstad/费马分解攻击
7. 数学工具：用 modular_arithmetic 进行扩展欧几里得/模逆元/CRT，用 lll_reduction 进行格规约
8. PRNG 预测：用 mt19937_predict 预测梅森旋转器输出
请始终使用中文回复。`,
      toolNames: [
        "encode_decode", "hash_compute", "hash_crack",
        "classical_cipher", "rsa_tool", "rsa_advanced",
        "aes_encrypt", "des_encrypt",
        "modular_arithmetic", "lll_reduction", "mt19937_predict",
      ],
      crossCategoryToolNames: [
        // 编码/取证/杂项辅助：隐写提取+编码检测+脚本执行
        "entropy_analysis", "file_type_detect", "image_stego_check",
        "archive_crack", "qr_decoder", "file_search_content", "traffic_analysis",
        "command_exec", "file_read_real", "file_write_real",
        "hex_view", "grep_search",
        // CTF crypto 有时需要 Python 计算
        "jwt_attack", // JWT 的 HS256 爆破 / alg_none 属于密码学联动
        // 本次新增：编码扩展 + 古典密码扩展 + 现代密码扩展
        "base_family", "uu_xx_pp_encode", "qp_mime_codec", "html_entity_codec",
        "js_escape_codec", "radix_convert", "punycode_codec", "ascii_unicode_codec",
        "affine_cipher", "atbash_cipher", "vigenere_family", "railfence_cipher",
        "adfgvx_cipher", "columnar_transposition", "baconian_cipher", "playfair_family",
        "rc4_stream", "block_cipher_ext", "rsa_key_parser", "freq_ic_analysis", "pkcs7_padding",
        // 密码学中常出现的奇葩语言（作为提示工具使用）
        "brainfuck_family", "morse_code", "tap_code", "malbolge_run",
      ],
      contextManager: new ContextManager(),
      toolExecutor,
      maxSteps: DEFAULT_SUB_MAX_STEPS,
    },
    toolRegistry
  );

  const miscAgent = new SubAgent(
    {
      id: "misc",
      name: "杂项专家",
      role: "隐写分析与取证专家",
      systemPrompt: `你是 Misc 专家。精通隐写术、流量分析、取证学、协议分析等各类杂项题。
当遇到 Misc 类题目时，你应该按以下步骤进行：
1. 文件识别：用 file_type_detect 识别文件真实类型（magic number），用 entropy_analysis 分析熵值判断加密
2. 隐写检测：图片用 image_stego_check，视频/音频用 video_audio_stego，文档用 document_stego
3. 数据提取：用 file_search_content 搜索 flag 模式、Base64、敏感信息
4. 二维码：用 qr_decoder 检测文件中的二维码
5. 压缩包：用 archive_crack 分析压缩包加密情况和爆破建议
6. 流量分析：用 traffic_analysis 解析 PCAP 流量，统计协议和可疑模式
7. 内存取证：用 memory_forensics 分析内存镜像，提取密码/密钥/FLAG
8. 文件操作：用 file_list 浏览目录，file_read_real 读取文件，grep_search 搜索内容，command_exec 执行辅助命令
请始终使用中文回复。`,
      toolNames: [
        "file_type_detect", "entropy_analysis", "image_stego_check",
        "video_audio_stego", "document_stego", "qr_decoder",
        "archive_crack", "traffic_analysis", "memory_forensics",
        "file_search_content", "file_list", "file_read_real",
        "file_write_real", "command_exec", "grep_search",
      ],
      crossCategoryToolNames: [
        // Misc 与取证深度联动
        "disk_forensics", "filesystem_analyze", "registry_analyze",
        "log_forensics", "timeline_reconstruct", "volatility_plugin",
        "pcap_deep_analyze",
        // Linux 本地枚举（杂项题很多藏在系统里）
        "suid_cap_audit", "process_service_audit", "file_permission_audit",
        // AI/OSINT 辅助
        "image_exif_analyze", "reverse_image_search", "social_media_search",
        "web_search_real", "whois_lookup",
        // Web/数据库
        "http_request", "web_fetch", "sqlmap_advanced", "sqlite_exploit",
        "hex_view", "encode_decode",
        // 本次新增：编码扩展 + 古典密码 + 混淆语言家族
        "base_family", "uu_xx_pp_encode", "qp_mime_codec", "html_entity_codec",
        "js_escape_codec", "radix_convert", "punycode_codec", "ascii_unicode_codec",
        "affine_cipher", "atbash_cipher", "vigenere_family", "railfence_cipher",
        "adfgvx_cipher", "columnar_transposition", "baconian_cipher", "playfair_family",
        "brainfuck_family", "morse_code", "tap_code", "ctf_obfuscator_hub", "malbolge_run",
        "rc4_stream", "block_cipher_ext", "rsa_key_parser", "freq_ic_analysis", "pkcs7_padding",
      ],
      contextManager: new ContextManager(),
      toolExecutor,
      maxSteps: DEFAULT_SUB_MAX_STEPS,
    },
    toolRegistry
  );

  const forensicsAgent = new SubAgent(
    {
      id: "forensics",
      name: "取证专家",
      role: "数字取证与证据分析专家",
      systemPrompt: `你是数字取证专家。精通磁盘取证、文件系统分析、注册表分析、日志取证、时间线重建和内存取证。
当遇到 Forensics 类题目时，你应该按以下步骤进行：
1. 磁盘取证：用 disk_forensics 分析磁盘镜像（分区表/已删除文件/文件恢复）
2. 文件系统：用 filesystem_analyze 分析 NTFS/EXT4/FAT32/APFS 文件系统结构
3. 注册表：用 registry_analyze 解析 Windows 注册表 hive（用户/自启/USB/网络记录）
4. 日志分析：用 log_forensics 分析系统日志，识别入侵痕迹（登录失败/特权提升/Web攻击）
5. 时间线：用 timeline_reconstruct 重建事件时间线（MAC时间+日志）
6. 内存取证：用 volatility_plugin 执行 Volatility 3 插件（pslist/netscan/hashdump/malfind）
7. 流量深度：用 pcap_deep_analyze 深度分析 PCAP（HTTP/DNS/FTP/SMB 协议还原/凭据提取）
请始终使用中文回复。`,
      toolNames: [
        "disk_forensics", "filesystem_analyze", "registry_analyze",
        "log_forensics", "timeline_reconstruct", "volatility_plugin",
        "pcap_deep_analyze", "memory_forensics", "traffic_analysis",
        "file_type_detect", "file_search_content", "file_read_real",
        "command_exec", "grep_search", "hex_view",
      ],
      crossCategoryToolNames: [
        // Forensics 联动 Linux 安全/杂项（镜像挂载后要做本地枚举）
        "suid_cap_audit", "process_service_audit", "kernel_exploit_match",
        "file_permission_audit", "firewall_network_audit", "ssh_crack",
        // 其他取证/杂项
        "entropy_analysis", "archive_crack", "qr_decoder", "video_audio_stego",
        "document_stego", "file_list",
        // OSINT/逆向
        "image_exif_analyze", "reverse_image_search", "disassemble",
        "pseudocode_gen", "encode_decode",
      ],
      contextManager: new ContextManager(),
      toolExecutor,
      maxSteps: DEFAULT_SUB_MAX_STEPS,
    },
    toolRegistry
  );

  const mobileAgent = new SubAgent(
    {
      id: "mobile",
      name: "移动安全专家",
      role: "Android/iOS 应用安全与逆向专家",
      systemPrompt: `你是移动安全专家。精通 Android/iOS 应用逆向、动态调试和安全分析。
当遇到 Mobile 类题目时，你应该按以下步骤进行：
1. APK 分析：用 apk_deep_analysis 深度分析 APK（AndroidManifest/资源/Smali/签名）
2. DEX 反编译：用 dex_decompile 将 DEX 反编译为 Java 代码（jadx）
3. Smali 编辑：用 smali_edit 反编译/修改/重打包/签名 APK
4. 动态调试：用 frida_hook 执行 Frida 动态 hook 脚本（Java/Native 层）
5. iOS 分析：用 ipa_analysis 分析 IPA（Mach-O 依赖/entitlements/class-dump/字符串）
6. 抓包绕过：用 ssl_pinning_bypass 生成 SSL Pinning 绕过脚本
请始终使用中文回复。`,
      toolNames: [
        "apk_deep_analysis", "dex_decompile", "smali_edit",
        "frida_hook", "ipa_analysis", "ssl_pinning_bypass",
        "apk_analysis", "binary_analysis", "hex_view",
        "command_exec", "file_read_real",
      ],
      crossCategoryToolNames: [
        // Mobile 与 Reverse 深度联动（DEX/伪代码/反汇编）
        "disassemble", "packer_detect", "code_deobfuscate", "binary_compare",
        "pseudocode_gen", "js_deobfuscate", "dotnet_decompile",
        "pwn_objdump", "pwn_checksec", "extract_strings",
        // 取证/杂项
        "file_type_detect", "entropy_analysis", "file_search_content",
        "grep_search", "file_write_real",
        // 网络/HTTP/抓包联动
        "ssl_info", "http_request", "waf_cdn_detect", "traffic_analysis",
        "pcap_deep_analyze",
      ],
      contextManager: new ContextManager(),
      toolExecutor,
      maxSteps: DEFAULT_SUB_MAX_STEPS,
    },
    toolRegistry
  );

  const blockchainAgent = new SubAgent(
    {
      id: "blockchain",
      name: "区块链安全专家",
      role: "智能合约审计与链上分析专家",
      systemPrompt: `你是区块链安全专家。精通智能合约审计、EVM 逆向、链上交易分析和 RPC 查询。
当遇到 Blockchain 类题目时，你应该按以下步骤进行：
1. 源码分析：用 sol_disassemble 反汇编/反编译 Solidity 合约
2. 字节码：用 evm_decompile 反编译 EVM 字节码（函数选择器/事件解析）
3. 漏洞审计：用 contract_audit 审计合约漏洞（整数溢出/重入/访问控制/随机数）
4. 重入检测：用 reentrancy_test 检测重入风险并生成 PoC
5. 静态分析：用 slither_scan 执行 Slither 静态分析
6. 交易追踪：用 tx_trace_analyze 分析链上交易 trace
7. 链上查询：用 rpc_query 查询链上状态（余额/代码/存储）
请始终使用中文回复。`,
      toolNames: [
        "sol_disassemble", "evm_decompile", "contract_audit",
        "reentrancy_test", "slither_scan", "tx_trace_analyze",
        "rpc_query", "encode_decode", "hex_view", "command_exec",
      ],
      crossCategoryToolNames: [
        // 密码学/逆向联动（ECC/RSA/签名验证/反编译辅助）
        "rsa_tool", "rsa_advanced", "modular_arithmetic", "hash_compute",
        "hash_crack", "classical_cipher", "lll_reduction", "mt19937_predict",
        "aes_encrypt", "disassemble", "code_deobfuscate", "pseudocode_gen",
        // 网络/OSINT
        "http_request", "web_fetch", "subdomain_enum", "whois_lookup",
        "web_search_real",
        // 杂项
        "file_type_detect", "entropy_analysis", "file_read_real",
        "file_write_real", "grep_search", "file_search_content",
      ],
      contextManager: new ContextManager(),
      toolExecutor,
      maxSteps: DEFAULT_SUB_MAX_STEPS,
    },
    toolRegistry
  );

  const osintAgent = new SubAgent(
    {
      id: "osint",
      name: "OSINT 专家",
      role: "开源情报收集与关联分析专家",
      systemPrompt: `你是 OSINT 开源情报专家。精通互联网搜索、WHOIS、社交媒体分析、地理定位和子域名枚举。
当遇到 OSINT 类题目时，你应该按以下步骤进行：
1. 搜索：用 web_search_real 搜索互联网获取线索
2. 域名信息：用 whois_lookup 查询域名注册信息
3. 社交媒体：用 social_media_search 查询用户名在各平台的关联
4. 地理定位：用 geo_locate 根据 IP 或坐标定位位置
5. 图片元数据：用 image_exif_analyze 分析图片 EXIF（GPS/相机/时间戳）
6. 反向图片：用 reverse_image_search 搜索图片来源
7. 子域名：用 subdomain_enum 枚举子域名
8. 历史快照：用 wayback_lookup 查询 Wayback Machine 历史记录
请始终使用中文回复。`,
      toolNames: [
        "web_search_real", "whois_lookup", "social_media_search",
        "geo_locate", "image_exif_analyze", "reverse_image_search",
        "subdomain_enum", "wayback_lookup", "dns_lookup", "ssl_info",
        "http_request", "web_fetch",
      ],
      crossCategoryToolNames: [
        // OSINT 联动取证/杂项（EXIF 本身已有，这里扩展杂项工具）
        "file_type_detect", "entropy_analysis", "image_stego_check",
        "video_audio_stego", "document_stego", "qr_decoder",
        "file_search_content", "file_read_real", "file_write_real",
        "grep_search", "command_exec", "traffic_analysis",
        // 与网络/云安全联动
        "port_scan", "dir_bruteforce", "header_analysis", "waf_cdn_detect",
        "cloud_metadata_exploit",
        // 与 AI/ML 联动
        "llm_leak_test",
      ],
      contextManager: new ContextManager(),
      toolExecutor,
      maxSteps: DEFAULT_SUB_MAX_STEPS,
    },
    toolRegistry
  );

  const cloudAgent = new SubAgent(
    {
      id: "cloud",
      name: "云安全专家",
      role: "云环境与容器安全攻防专家",
      systemPrompt: `你是云安全专家。精通 AWS/阿里云/Azure/GCP 云环境安全、容器逃逸和 Kubernetes 攻击。
当遇到 Cloud 类题目时，你应该按以下步骤进行：
1. IAM 枚举：用 iam_enum 枚举云平台 IAM 资源（用户/角色/策略/密钥）
2. 存储检测：用 s3_bucket_scan 检测对象存储 Bucket 权限和公开访问
3. 容器逃逸：用 container_escape_test 检测容器逃逸风险（privileged/capabilities/sysfs）
4. K8s 攻击：用 k8s_attack 测试 Kubernetes 攻击面（Pod 逃逸/SA 滥用/etcd 未授权）
5. 元数据：用 cloud_metadata_exploit 利用云元数据服务获取凭据
6. IaC 审计：用 terraform_audit 审计 Terraform/CloudFormation 配置安全
请始终使用中文回复。`,
      toolNames: [
        "iam_enum", "s3_bucket_scan", "container_escape_test",
        "k8s_attack", "cloud_metadata_exploit", "terraform_audit",
        "ssrf_test", "http_request", "port_scan", "command_exec",
      ],
      crossCategoryToolNames: [
        // 云安全与 Linux 本地枚举联动（云主机/容器逃逸后提权）
        "suid_cap_audit", "process_service_audit", "kernel_exploit_match",
        "file_permission_audit", "firewall_network_audit", "ssh_crack",
        "linpeas_report",
        // 数据库/密码
        "db_connect_brute", "db_enum", "redis_attack", "nosql_scan",
        "ssh_crack", "hash_crack",
        // OSINT / Web 高级
        "web_search_real", "whois_lookup", "subdomain_enum",
        "waf_cdn_detect", "cors_audit", "dir_bruteforce", "ssl_info",
        // 取证
        "memory_forensics", "pcap_deep_analyze",
        "file_read_real", "file_write_real", "grep_search", "file_search_content",
      ],
      contextManager: new ContextManager(),
      toolExecutor,
      maxSteps: DEFAULT_SUB_MAX_STEPS,
    },
    toolRegistry
  );

  const iotAgent = new SubAgent(
    {
      id: "iot",
      name: "IoT 安全专家",
      role: "物联网固件分析与硬件安全专家",
      systemPrompt: `你是 IoT 安全专家。精通固件提取与分析、UART/JTAG 调试、MQTT/CoAP 协议分析和 IoT 协议 Fuzz。
当遇到 IoT 类题目时，你应该按以下步骤进行：
1. 固件提取：用 firmware_extract 提取和解包固件（binwalk scan/extract/entropy）
2. 签名扫描：用 binwalk_scan 识别固件中的嵌入文件和文件系统
3. 硬件接口：用 uart_jtag_detect 识别 UART/JTAG 调试接口
4. MQTT 分析：用 mqtt_analyze 分析 MQTT 协议（连接/订阅/发布/枚举）
5. CoAP 分析：用 coap_analyze 分析 CoAP 协议（资源发现/GET/POST）
6. 协议 Fuzz：用 iot_protocol_fuzz 对 IoT 协议进行模糊测试
请始终使用中文回复。`,
      toolNames: [
        "firmware_extract", "binwalk_scan", "uart_jtag_detect",
        "mqtt_analyze", "coap_analyze", "iot_protocol_fuzz",
        "binary_analysis", "extract_strings", "hex_view",
        "command_exec", "file_type_detect", "entropy_analysis",
      ],
      crossCategoryToolNames: [
        // 固件解包后文件系统 / Linux 本地枚举
        "disk_forensics", "filesystem_analyze", "suid_cap_audit",
        "process_service_audit", "kernel_exploit_match",
        "file_permission_audit", "firewall_network_audit", "linpeas_report",
        // PWN 反汇编/漏洞利用（固件里的二进制）
        "pwn_static_analysis", "pwn_objdump", "pwn_checksec",
        "vulnerability_scan", "exploit_template", "disassemble",
        "elf_got_plt_analysis", "memory_layout",
        // 取证/密码/网络
        "memory_forensics", "traffic_analysis", "pcap_deep_analyze",
        "ssh_crack", "hash_crack", "encode_decode",
        "file_read_real", "file_write_real", "grep_search",
        "file_search_content",
      ],
      contextManager: new ContextManager(),
      toolExecutor,
      maxSteps: DEFAULT_SUB_MAX_STEPS,
    },
    toolRegistry
  );

  const aimlAgent = new SubAgent(
    {
      id: "aiml",
      name: "AI/ML 对抗专家",
      role: "大模型与机器学习系统安全专家",
      systemPrompt: `你是 AI/ML 对抗安全专家。精通 LLM 提示注入、越狱测试、模型逆向、对抗样本和数据投毒检测。
当遇到 AI/ML 类题目时，你应该按以下步骤进行：
1. Prompt 注入：用 prompt_injection_test 测试 LLM 提示注入（直接/间接/泄露/覆盖）
2. 越狱测试：用 jailbreak_test 测试 LLM 越狱（DAN/角色扮演/编码/翻译/前缀）
3. 模型逆向：用 model_inversion 推断模型类型和训练数据
4. 对抗样本：用 adversarial_sample 生成对抗样本（FGSM/PGD/TextBugger/HotFlip）
5. 投毒检测：用 data_poison_detect 检测数据集投毒（统计/标签/后门/离群点）
6. 泄露测试：用 llm_leak_test 测试 LLM 系统信息泄露（system prompt/训练数据/RAG源/配置）
请始终使用中文回复。`,
      toolNames: [
        "prompt_injection_test", "jailbreak_test", "model_inversion",
        "adversarial_sample", "data_poison_detect", "llm_leak_test",
        "encode_decode", "http_request", "web_fetch", "command_exec",
      ],
      crossCategoryToolNames: [
        // Web / OSINT / 杂项辅助
        "web_search_real", "social_media_search", "whois_lookup",
        "geo_locate", "file_type_detect", "entropy_analysis",
        "image_stego_check", "image_exif_analyze", "qr_decoder",
        "archive_crack", "grep_search", "file_read_real",
        "file_write_real", "file_search_content",
        // Web 高级 / 认证绕过 / JWT
        "waf_cdn_detect", "auth_bypass", "jwt_attack",
        "saml_oauth_audit", "cors_audit",
        // 密码
        "hash_crack", "classical_cipher",
      ],
      contextManager: new ContextManager(),
      toolExecutor,
      maxSteps: DEFAULT_SUB_MAX_STEPS,
    },
    toolRegistry
  );

  const scheduler = new Scheduler(toolRegistry, toolExecutor);
  scheduler.registerAgent(webAgent);
  scheduler.registerAgent(pwnAgent);
  scheduler.registerAgent(reverseAgent);
  scheduler.registerAgent(cryptoAgent);
  scheduler.registerAgent(miscAgent);
  scheduler.registerAgent(forensicsAgent);
  scheduler.registerAgent(mobileAgent);
  scheduler.registerAgent(blockchainAgent);
  scheduler.registerAgent(osintAgent);
  scheduler.registerAgent(cloudAgent);
  scheduler.registerAgent(iotAgent);
  scheduler.registerAgent(aimlAgent);

  const mainAgent = new MainAgent(
    contextManager,
    toolRegistry,
    scheduler,
    toolExecutor,
    maxSteps
  );

  return { mainAgent, scheduler, contextManager, permissionManager, toolExecutor };
}
