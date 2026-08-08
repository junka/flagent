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
1. 初步分析：用 binary_analysis 检查文件类型、架构、保护机制（Canary/NX/PIE/RELRO）
2. 信息提取：用 extract_strings 提取关键字符串（/bin/sh、flag 格式、系统调用名等）
3. 漏洞扫描：用 vulnerability_scan 扫描危险函数调用（strcpy/gets/sprintf/system等）
4. 深入分析：用 elf_got_plt_analysis 分析 GOT/PLT 动态链接，用 disassemble 查看反汇编，用 hex_view 查看二进制结构
5. 利用规划：用 memory_layout 分析栈/堆布局，根据漏洞类型用 exploit_template 生成 pwntools 利用模板
6. 远程交互：用 nc_remote_client 连接远程服务进行测试
7. 策略选择：根据保护机制选择 ret2libc/ROP/ret2shellcode/UAF/格式化字符串等利用方式
请始终使用中文回复。`,
      toolNames: [
        "binary_analysis", "extract_strings", "vulnerability_scan",
        "disassemble", "hex_view", "elf_got_plt_analysis",
        "exploit_template", "nc_remote_client", "memory_layout",
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

  const mainAgent = new MainAgent(
    contextManager,
    toolRegistry,
    scheduler,
    toolExecutor,
    maxSteps
  );

  return { mainAgent, scheduler, contextManager, permissionManager, toolExecutor };
}
