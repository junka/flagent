import { z } from "zod";
import * as fs from "fs";
import { ToolRegistry } from "./registry";

export function createReverseTools(): ToolRegistry {
  const registry = new ToolRegistry();

  registry.register({
    name: "disassemble",
    description: "文本级反汇编：将二进制文件转换为可读的汇编指令（支持 x86/x64 基础指令识别）",
    parameters: z.object({
      path: z.string().describe("二进制文件路径"),
      maxInstructions: z.number().optional().describe("最大指令数，默认 100"),
      offset: z.number().optional().describe("起始偏移，默认 0"),
    }),
    category: "reverse",
    concurrent: true,
    execute: async (args: any) => {
      const { path, maxInstructions = 100, offset = 0 } = args;
      try {
        const buf = fs.readFileSync(path);

        if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
          const bits = buf[4] === 2 ? 64 : 32;
          const instructions = generatePseudoAsm(buf, bits, maxInstructions, offset);
          return `[反汇编] ${path} (ELF ${bits}-bit)\n\n${instructions}`;
        } else if (buf[0] === 0x4d && buf[1] === 0x5a) {
          const peOffset = buf.readUInt32LE(0x3c);
          const magic = buf.readUInt16LE(peOffset + 24);
          const bits = magic === 0x20b ? 64 : 32;
          const instructions = generatePseudoAsm(buf, bits, maxInstructions, offset);
          return `[反汇编] ${path} (PE ${bits}-bit)\n\n${instructions}`;
        } else {
          const hexDump = buf.slice(offset, offset + Math.min(maxInstructions * 16, 256))
            .toString("hex")
            .match(/.{1,2}/g)!
            .map((b, i) => `${(offset + i).toString(16).padStart(8, "0")}: ${b}`)
            .join("\n");
          return `[原始字节] ${path}\n\nHex dump:\n${hexDump}`;
        }
      } catch (err: any) {
        return `[反汇编失败] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "binary_compare",
    description: "二进制文件对比：比较两个文件的差异字节",
    parameters: z.object({
      file1: z.string().describe("文件1 路径"),
      file2: z.string().describe("文件2 路径"),
      maxDiff: z.number().optional().describe("最大差异显示数，默认 50"),
    }),
    category: "reverse",
    concurrent: true,
    execute: async (args: any) => {
      const { file1, file2, maxDiff = 50 } = args;
      try {
        const buf1 = fs.readFileSync(file1);
        const buf2 = fs.readFileSync(file2);
        const minLen = Math.min(buf1.length, buf2.length);
        const diffs: string[] = [];

        for (let i = 0; i < minLen; i++) {
          if (buf1[i] !== buf2[i]) {
            diffs.push(`  @0x${i.toString(16)}: 0x${buf1[i].toString(16).padStart(2, "0")} → 0x${buf2[i].toString(16).padStart(2, "0")}`);
            if (diffs.length >= maxDiff) break;
          }
        }

        const sizeDiff = buf1.length !== buf2.length ? `\n大小差异: ${buf1.length} vs ${buf2.length} (差 ${Math.abs(buf1.length - buf2.length)} 字节)` : "";
        return `[二进制对比]\n${file1} (${buf1.length}B)\n${file2} (${buf2.length}B)${sizeDiff}\n\n差异(${diffs.length}):\n${diffs.join("\n") || "  完全相同"}`;
      } catch (err: any) {
        return `[对比失败] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "apk_analysis",
    description: "APK 基础结构分析：检查 AndroidManifest.xml、classes.dex、资源文件",
    parameters: z.object({
      path: z.string().describe("APK 文件路径 (ZIP格式)"),
    }),
    category: "reverse",
    concurrent: true,
    execute: async (args: any) => {
      const { path } = args;
      try {
        const buf = fs.readFileSync(path);
        const isZip = buf[0] === 0x50 && buf[1] === 0x4b;
        if (!isZip) return `[APK分析] ${path}\n错误: 不是有效的 ZIP/APK 文件`;

        const files = parseZipEntries(buf);
        const apkFiles = [
          "AndroidManifest.xml",
          "classes.dex",
          "classes2.dex",
          "resources.arsc",
          "res/",
          "lib/",
          "META-INF/",
          "assets/",
        ];

        const found = apkFiles.filter((f) => files.includes(f));
        const dexFiles = files.filter((f) => f.endsWith(".dex"));
        const soFiles = files.filter((f) => f.endsWith(".so"));
        const activities = files.filter((f) => f.includes("Activity") || f.includes("activity"));

        return `[APK分析] ${path}\n大小: ${buf.length} 字节\n\n关键文件:\n${apkFiles.map((f) => `  ${found.includes(f) ? "✓" : "✗"} ${f}`).join("\n")}\n\nDEX文件: ${dexFiles.join(", ") || "  (无)"}\nSO库文件: ${soFiles.join(", ") || "  (无)"}\nActivity相关: ${activities.slice(0, 10).join(", ") || "  (无)"}\n\n提示:\n- 使用 apktool 解码: apktool d ${path}\n- 使用 jadx 反编译: jadx-gui ${path}\n- 使用 dex2jar + jd-gui 查看 Java 源码`;
      } catch (err: any) {
        return `[APK分析失败] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "packer_detect",
    description: "检测二进制文件的壳/保护机制",
    parameters: z.object({ path: z.string().describe("二进制文件路径") }),
    category: "reverse",
    concurrent: true,
    execute: async (args: any) => {
      const { path } = args;
      try {
        const buf = fs.readFileSync(path);
        const data = buf.toString("binary");

        const packers = [
          { name: "UPX", signatures: [/UPX!/, /UPX[0-9]/, /This program cannot be run in DOS mode.*UPX/s] },
          { name: "ASPack", signatures: [/ASPack/, /.aspack/] },
          { name: "Themida", signatures: [/Themida/, /themida/, /TMiD/] },
          { name: "VMProtect", signatures: [/VMProtect/, /vmp/, /VMP/] },
          { name: "Enigma", signatures: [/Enigma/, /enigma/] },
          { name: "VMWare ThinApp", signatures: [/ThinApp/, /thinapp/] },
          { name: "PyInstaller", signatures: [/PyInstaller/, /MEIPASS/] },
          { name: "PyArmor", signatures: [/PyArmor/, /pytransform/] },
          { name: "Cx_Freeze", signatures: [/Cx_Freeze/, /cx_Freeze/] },
          { name: "Nuitka", signatures: [/Nuitka/, /__nuitka/] },
          { name: "Electron", signatures: [/Electron/, /electron\/app/] },
          { name: ".NET/Mono", signatures: [/\.dll/, /mscoree/, /System\.Windows/] },
          { name: "Go", signatures: [/runtime\.main/, /main\.init/, /GODEBUG/] },
          { name: "Rust", signatures: [/rustc/, /Cargo/, /panic_unwind/] },
        ];

        const detected: string[] = [];
        for (const p of packers) {
          for (const sig of p.signatures) {
            if (sig.test(data)) {
              detected.push(`  ⚠️ ${p.name}: 检测到特征 "${sig.source}"`);
              break;
            }
          }
        }

        return `[壳检测] ${path}\n\n检测结果:\n${detected.length ? detected.join("\n") : "  ✓ 未检测到已知壳"}`;
      } catch (err: any) {
        return `[检测失败] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "code_deobfuscate",
    description: "代码反混淆：处理常见的混淆技术（控制流平坦化、字符串加密、虚拟机检测等）",
    parameters: z.object({
      path: z.string().describe("二进制文件路径"),
    }),
    category: "reverse",
    concurrent: true,
    execute: async (args: any) => {
      const { path } = args;
      try {
        const buf = fs.readFileSync(path);
        const data = buf.toString("binary");

        const patterns = [
          { name: "控制流平坦化", indicators: [/state = \d+/, /switch\s*\(\s*state/, /dispatcher/, /dispatch/] },
          { name: "自修改代码", indicators: [/VirtualProtect/, /mprotect.*PROT_EXEC/, /self.modif/] },
          { name: "反调试", indicators: [/IsDebuggerPresent/, /CheckRemoteDebuggerPresent/, /ptrace.*PTRACE_TRACEME/, /debugger/] },
          { name: "反虚拟机", indicators: [/VirtualBox/, /VMware/, /VirtualPC/, /QEMU/, /vbox/, /vmx/] },
          { name: "反沙箱", indicators: [/sandbox/, /Sandboxie/, /Cuckoo/, /VirusTotal/] },
          { name: "字符串加密", indicators: [/XOR.*key/, /encrypted.*string/, /decrypt.*str/] },
          { name: "API动态解析", indicators: [/LoadLibrary.*GetProcAddress/, /GetProcAddress/, /dlsym.*RTLD/] },
          { name: "反 Dump", indicators: [/IsProcessInJob/, /QueryWorkingSetEx/, /ZwQuery/] },
        ];

        const detected: string[] = [];
        for (const p of patterns) {
          for (const ind of p.indicators) {
            if (ind.test(data)) {
              detected.push(`  ⚠️ ${p.name}: "${ind.source}"`);
              break;
            }
          }
        }

        return `[混淆检测] ${path}\n\n检测到的混淆技术:\n${detected.length ? detected.join("\n") : "  ✓ 未检测到明显混淆技术"}\n\n建议:\n- 使用 IDA Pro / Ghidra 进行手动分析\n- 动态调试时用 ScyllaHide 绕过反调试\n- 使用 x64dbg/Frida 进行脱壳和去混淆\n- 对于控制流平坦化，使用 D810/D910 或脚本简化`;
      } catch (err: any) {
        return `[检测失败] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "hex_view",
    description: "查看文件的 Hex 视图，可按指定偏移和长度显示",
    parameters: z.object({
      path: z.string().describe("文件路径"),
      offset: z.number().optional().describe("起始偏移，默认 0"),
      length: z.number().optional().describe("显示长度，默认 256"),
    }),
    category: "reverse",
    concurrent: true,
    execute: async (args: any) => {
      const { path, offset = 0, length = 256 } = args;
      try {
        const buf = fs.readFileSync(path);
        const slice = buf.slice(offset, Math.min(offset + length, buf.length));
        const lines: string[] = [];
        for (let i = 0; i < slice.length; i += 16) {
          const line = slice.slice(i, i + 16);
          const hex = Array.from(line).map((b) => b.toString(16).padStart(2, "0")).join(" ");
          const ascii = Array.from(line).map((b) => b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".").join("");
          lines.push(`${(offset + i).toString(16).padStart(8, "0")}: ${hex.padEnd(48)} ${ascii}`);
        }
        return `[Hex视图] ${path} @0x${offset.toString(16)} (${slice.length} 字节)\n\n${lines.join("\n")}`;
      } catch (err: any) {
        return `[查看失败] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "pseudocode_gen",
    description: "伪代码生成：基于汇编模式识别生成可读的 C 风格伪代码",
    parameters: z.object({
      path: z.string().describe("二进制文件路径"),
      offset: z.number().optional().describe("起始偏移，默认 0"),
      length: z.number().optional().describe("分析长度，默认 512"),
    }),
    category: "reverse",
    concurrent: true,
    execute: async (args: any) => {
      const { path, offset = 0, length = 512 } = args;
      try {
        const buf = fs.readFileSync(path);
        const slice = buf.slice(offset, Math.min(offset + length, buf.length));

        const pseudocode: string[] = [];
        pseudocode.push("// === 伪代码分析结果 ===");
        pseudocode.push("// 注意: 自动生成的伪代码仅供参考");
        pseudocode.push("");

        let i = 0;
        while (i < slice.length) {
          const b = slice[i];

          if (b === 0x55 && slice[i + 1] === 0x48 && slice[i + 2] === 0x89 && slice[i + 3] === 0xe5) {
            pseudocode.push("void function_XXX() {");
            pseudocode.push("    // push rbp; mov rbp, rsp (函数序言)");
            i += 4;
            continue;
          }

          if (b === 0x48 && slice[i + 1] === 0x83 && slice[i + 2] === 0xec) {
            const stackSize = slice[i + 3];
            pseudocode.push(`    // sub rsp, ${stackSize} (分配栈空间)`);
            i += 3;
            continue;
          }

          if (b === 0x48 && slice[i + 1] === 0x8b && slice[i + 2] >= 0x48 && slice[i + 2] <= 0x4f) {
            const regs = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
            const regName = regs[slice[i + 2] - 0x48] || "unknown";
            pseudocode.push(`    ${regName} = ...;  // mov reg, imm`);
            i += 2;
            continue;
          }

          if (b === 0xbf) {
            const edi = slice.readUInt32LE(i + 1);
            pseudocode.push(`    arg1 = 0x${edi.toString(16)};  // mov edi, imm (第一个参数)`);
            i += 4;
            continue;
          }

          if (b === 0xbe) {
            const esi = slice.readUInt32LE(i + 1);
            pseudocode.push(`    arg2 = 0x${esi.toString(16)};  // mov esi, imm (第二个参数)`);
            i += 4;
            continue;
          }

          if (b === 0x48 && slice[i + 1] === 0x83 && slice[i + 2] === 0xf8) {
            pseudocode.push(`    if (rax == ${slice[i + 3]}) {  // cmp rax, imm`);
            i += 3;
            continue;
          }

          if (b === 0x74) {
            pseudocode.push("        // je (等于则跳转)");
            i += 1;
            continue;
          }

          if (b === 0x75) {
            pseudocode.push("        // jne (不等于则跳转)");
            i += 1;
            continue;
          }

          if (b === 0x0f && slice[i + 1] >= 0x80 && slice[i + 1] <= 0x8f) {
            pseudocode.push("        // conditional jump (条件跳转)");
            i += 1;
            continue;
          }

          if (b === 0xe8) {
            pseudocode.push("    // call function_XXX (函数调用)");
            i += 4;
            continue;
          }

          if (b === 0xc3) {
            pseudocode.push("    return;  // ret");
            i += 0;
            continue;
          }

          if (b === 0x90) {
            i += 0;
            continue;
          }

          if (b === 0x80 && slice[i + 1] === 0x7d) {
            pseudocode.push(`    if (*(rbp - ${slice[i + 2]}) == ${slice[i + 3]}) {`);
            i += 3;
            continue;
          }

          if (b === 0x48 && slice[i + 1] === 0x89 && slice[i + 2] === 0x7d) {
            pseudocode.push(`    *(rbp - ${slice[i + 3]}) = ...;  // 存储局部变量`);
            i += 3;
            continue;
          }

          i += 1;
        }

        pseudocode.push("}");
        return `[伪代码生成] ${path} @0x${offset.toString(16)}\n\n${pseudocode.join("\n")}\n\n提示: 使用 Ghidra/IDA Pro 获得更准确的反编译结果`;
      } catch (err: any) {
        return `[伪代码生成失败] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "js_deobfuscate",
    description: "JavaScript 反混淆：识别常见混淆技术并简化",
    parameters: z.object({
      code: z.string().describe("要分析的 JavaScript 代码"),
    }),
    category: "reverse",
    concurrent: true,
    execute: async (args: any) => {
      const { code } = args;
      const results: string[] = [];

      const obfuscationPatterns = [
        { pattern: /eval\s*\(/g, name: "eval()", desc: "动态代码执行，可能藏有加密载荷" },
        { pattern: /Function\s*\(/g, name: "Function()", desc: "动态函数创建" },
        { pattern: /\\x[0-9a-fA-F]{2}/g, name: "hex转义", desc: "十六进制转义，需解码" },
        { pattern: /\\u[0-9a-fA-F]{4}/g, name: "unicode转义", desc: "Unicode转义，需解码" },
        { pattern: /atob\s*\(/g, name: "atob()", desc: "Base64解码，可能藏有payload" },
        { pattern: /fromCharCode/g, name: "fromCharCode", desc: "字符编码转换" },
        { pattern: /charCodeAt/g, name: "charCodeAt", desc: "字符编码提取" },
        { pattern: /\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}/g, name: "双重hex", desc: "双重十六进制编码" },
        { pattern: /\[\s*['"][^'"]*['"]\s*\]\s*\[/g, name: "数组索引混淆", desc: "通过数组索引代替直接访问" },
        { pattern: /String\.fromCharCode\s*\(/g, name: "String.fromCharCode", desc: "字符生成" },
        { pattern: /\\s{5,}/g, name: "超长空白", desc: "可能有隐写或编码" },
        { pattern: /0x[0-9a-fA-F]+/g, name: "hex数字", desc: "十六进制数字，需转换" },
      ];

      for (const p of obfuscationPatterns) {
        const matches = code.match(p.pattern);
        if (matches && matches.length > 0) {
          results.push(`  ⚠️ [${p.name}] 出现 ${matches.length} 次 - ${p.desc}`);
        }
      }

      const suggestion: string[] = [];

      if (/eval\s*\(/.test(code) || /Function\s*\(/.test(code)) {
        suggestion.push("1. 使用 jsnice.org 或 beautifier.io 格式化代码");
        suggestion.push("2. 提取 eval/Function 的参数并递归解码");
      }
      if (/\\x[0-9a-fA-F]{2}/g.test(code)) {
        suggestion.push("3. 使用 Python 解码: bytes.fromhex(hex_string).decode()");
      }
      if (/\\u[0-9a-fA-F]{4}/g.test(code)) {
        suggestion.push("4. 使用 Python 解码: codecs.decode(text, 'unicode_escape')");
      }
      if (/atob\s*\(/.test(code)) {
        suggestion.push("5. 解码 atob 参数: echo BASE64 | base64 -d");
      }
      if (/String\.fromCharCode/.test(code)) {
        suggestion.push("6. 提取 fromCharCode 参数并转为字符串");
      }

      const decodedHex = code.replace(/\\x([0-9a-fA-F]{2})/g, (_: string, hex: string) => {
        return String.fromCharCode(parseInt(hex, 16));
      });
      const decodedUnicode = decodedHex.replace(/\\u([0-9a-fA-F]{4})/g, (_: string, unicode: string) => {
        return String.fromCharCode(parseInt(unicode, 16));
      });

      const hasDecoded = decodedUnicode !== code;
      const preview = hasDecoded ? decodedUnicode.slice(0, 500) : code.slice(0, 500);

      return `[JS反混淆分析]\n\n检测到的混淆技术:\n${results.join("\n") || "  (未检测到明显混淆模式)"}\n\n解码预览:\n${preview}${hasDecoded ? "\n  ... (已解码 hex/unicode 转义)" : ""}\n\n建议:\n${suggestion.join("\n") || "  (代码看起来相对清晰)"}`;
    },
  });

  registry.register({
    name: "dotnet_decompile",
    description: ".NET/Java 反编译辅助：识别 IL /MSIL 字节码和特征",
    parameters: z.object({
      path: z.string().describe("文件路径 (.NET DLL/EXE 或 Java CLASS)"),
    }),
    category: "reverse",
    concurrent: true,
    execute: async (args: any) => {
      const { path } = args;
      try {
        const buf = fs.readFileSync(path);
        const header = buf.slice(0, 16).toString("hex");

        const detections: string[] = [];
        detections.push(`文件头: ${header}`);

        if (buf[0] === 0x4d && buf[1] === 0x5a) {
          detections.push("✅ PE 文件 (Windows 可执行文件)");

          if (buf.includes(Buffer.from("mscoree.dll")) || buf.includes(Buffer.from("System.Windows.Forms"))) {
            detections.push("  ⚠️ 检测到 .NET 特征 (mscoree.dll)");
            detections.push("  建议工具: dnSpy, ILSpy, dotPeek");
          }
          if (buf.includes(Buffer.from("System.")) && buf.includes(Buffer.from("mscorlib"))) {
            detections.push("  ⚠️ 确认: .NET 程序集");
          }
        } else if (buf[0] === 0xca && buf[1] === 0xfe && buf[2] === 0xba && buf[3] === 0xbe) {
          detections.push("✅ Java CLASS 文件");
          detections.push("  建议工具: javap, JD-GUI, JADX, CFR");

          if (buf.includes(Buffer.from("java.lang.String"))) detections.push("  检测到 java.lang.String 引用");
          if (buf.includes(Buffer.from("synchronized"))) detections.push("  检测到 synchronized 方法");
        } else if (buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) {
          detections.push("✅ ZIP/JAR 文件");
          if (buf.includes(Buffer.from("META-INF/MANIFEST.MF"))) detections.push("  ⚠️ JAR 包 (含 MANIFEST.MF)");
          if (buf.includes(Buffer.from(".class"))) detections.push("  ⚠️ 包含 .class 文件 - Java 程序");
          detections.push("  建议工具: jar, unzip, JD-GUI");
        }

        const dotnetPatterns = [
          { sig: "System.Web.", desc: "ASP.NET Web 应用" },
          { sig: "System.Windows.Forms.", desc: "WinForms 桌面应用" },
          { sig: "System.Drawing.", desc: "图像处理应用" },
          { sig: "System.Net.", desc: "网络通信应用" },
          { sig: "System.Security.", desc: "安全相关应用" },
          { sig: "System.Runtime.", desc: "运行时相关" },
        ];
        for (const p of dotnetPatterns) {
          if (buf.includes(Buffer.from(p.sig))) {
            detections.push(`  ℹ️ ${p.desc} (${p.sig})`);
          }
        }

        return `[.NET/Java 反编译分析] ${path}\n\n${detections.join("\n")}\n\n推荐工具:\n- .NET: dnSpy, ILSpy, dotPeek, dnEx\n- Java: JD-GUI, JADX, CFR, Procyon\n- 通用: Ghidra, IDA Pro`;
      } catch (err: any) {
        return `[分析失败] ${err.message}`;
      }
    },
  });

  return registry;
}

function generatePseudoAsm(buf: Buffer, bits: number, maxInstructions: number, startOffset: number): string {
  const instructions: string[] = [];
  const data = buf.slice(startOffset);

  for (let i = 0; i < Math.min(maxInstructions * 16, data.length); i++) {
    const b = data[i];
    const offset = startOffset + i;

    if (b === 0x90) {
      instructions.push(`  0x${offset.toString(16).padStart(8, "0")}: nop`);
    } else if (b === 0xcc) {
      instructions.push(`  0x${offset.toString(16).padStart(8, "0")}: int3`);
    } else if (b === 0xc3 || b === 0xcb) {
      instructions.push(`  0x${offset.toString(16).padStart(8, "0")}: ret`);
    } else if (b === 0xcc) {
      continue;
    } else if ((b >= 0xb8 && b <= 0xbf)) {
      const regs = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
      if (i + 4 < data.length) {
        const imm = bits === 64 ? data.readUInt32LE(i + 1) : data.readUInt32LE(i + 1);
        instructions.push(`  0x${offset.toString(16).padStart(8, "0")}: mov ${regs[b - 0xb8]}, 0x${imm.toString(16)}`);
        i += 4;
      }
    } else if (b === 0x48 && bits === 64) {
      const nextByte = data[i + 1];
      if (nextByte >= 0x89 && nextByte <= 0x8b) {
        instructions.push(`  0x${offset.toString(16).padStart(8, "0")}: rex prefix (48 ${nextByte.toString(16)}) ...`);
      } else {
        instructions.push(`  0x${offset.toString(16).padStart(8, "0")}: rex prefix 48 ${nextByte.toString(16)}`);
      }
      i += 1;
    } else if (b === 0x0f) {
      instructions.push(`  0x${offset.toString(16).padStart(8, "0")}: two-byte escape 0f ${data[i + 1]?.toString(16).padStart(2, "0")}`);
      i += 1;
    } else if (b >= 0x70 && b <= 0x7f) {
      const rel8 = data[i + 1];
      const target = offset + 2 + (rel8 > 127 ? rel8 - 256 : rel8);
      const conds = ["jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "jae", "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"];
      instructions.push(`  0x${offset.toString(16).padStart(8, "0")}: ${conds[b - 0x70]} 0x${target.toString(16)}`);
      i += 1;
    } else if (b >= 0xe0 && b <= 0xe2) {
      instructions.push(`  0x${offset.toString(16).padStart(8, "0")}: loop 0x${(offset + 2).toString(16)}`);
    } else if (b === 0xe8) {
      if (i + 4 < data.length) {
        const rel32 = data.readInt32LE(i + 1);
        instructions.push(`  0x${offset.toString(16).padStart(8, "0")}: call 0x${(offset + 5 + rel32).toString(16)}`);
        i += 4;
      }
    } else if (b === 0xe9) {
      if (i + 4 < data.length) {
        const rel32 = data.readInt32LE(i + 1);
        instructions.push(`  0x${offset.toString(16).padStart(8, "0")}: jmp 0x${(offset + 5 + rel32).toString(16)}`);
        i += 4;
      }
    } else if (b === 0x55) {
      instructions.push(`  0x${offset.toString(16).padStart(8, "0")}: push ebp`);
    } else if (b === 0x58) {
      instructions.push(`  0x${offset.toString(16).padStart(8, "0")}: pop eax`);
    } else if (b === 0x89 || b === 0x8b) {
      instructions.push(`  0x${offset.toString(16).padStart(8, "0")}: mov ... (0x${b.toString(16)})`);
    } else if (b === 0x31 || b === 0x33) {
      instructions.push(`  0x${offset.toString(16).padStart(8, "0")}: xor ... (0x${b.toString(16)})`);
    } else if (b === 0x83) {
      instructions.push(`  0x${offset.toString(16).padStart(8, "0")}: add/sub ... (0x83)`);
    } else if (b === 0x50) {
      instructions.push(`  0x${offset.toString(16).padStart(8, "0")}: push eax`);
    } else if (b === 0x68) {
      instructions.push(`  0x${offset.toString(16).padStart(8, "0")}: push imm32`);
      i += 4;
    } else {
      instructions.push(`  0x${offset.toString(16).padStart(8, "0")}: db 0x${b.toString(16).padStart(2, "0")}`);
    }

    if (instructions.length >= maxInstructions) break;
  }

  return instructions.join("\n");
}

function parseZipEntries(buf: Buffer): string[] {
  const entries: string[] = [];
  try {
    const sigEnd = buf.indexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    if (sigEnd === -1) return entries;

    let offset = 0;
    while (offset < buf.length - 4) {
      if (buf[offset] === 0x50 && buf[offset + 1] === 0x4b) {
        if (buf[offset + 2] === 0x01 && buf[offset + 3] === 0x02) {
          const compressedSize = buf.readUInt32LE(offset + 20);
          const uncompressedSize = buf.readUInt32LE(offset + 24);
          const nameLen = buf.readUInt16LE(offset + 28);
          const extraLen = buf.readUInt16LE(offset + 30);
          const commentLen = buf.readUInt16LE(offset + 32);
          const name = buf.slice(offset + 46, offset + 46 + nameLen).toString("utf-8");
          entries.push(name);
          offset += 46 + nameLen + extraLen + commentLen;
        } else if (buf[offset + 2] === 0x03 && buf[offset + 3] === 0x04) {
          const nameLen = buf.readUInt16LE(offset + 26);
          const extraLen = buf.readUInt16LE(offset + 28);
          const name = buf.slice(offset + 30, offset + 30 + nameLen).toString("utf-8");
          const compressedSize = buf.readUInt32LE(offset + 18);
          entries.push(name);
          offset += 30 + nameLen + extraLen + compressedSize;
        } else {
          offset++;
        }
      } else {
        offset++;
      }
    }
  } catch {}
  return entries;
}