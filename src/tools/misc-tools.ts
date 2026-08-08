import { z } from "zod";
import * as fs from "fs";
import * as crypto from "crypto";
import * as child_process from "child_process";
import { ToolRegistry } from "./registry";

export function createMiscTools(): ToolRegistry {
  const registry = new ToolRegistry();

  registry.register({
    name: "file_type_detect",
    description: "文件类型识别：基于 magic number 检测真实文件类型",
    parameters: z.object({ path: z.string().describe("文件路径") }),
    category: "misc",
    concurrent: true,
    execute: async (args: any) => {
      const { path } = args;
      try {
        const buf = fs.readFileSync(path).slice(0, 32);

        const signatures: Array<{ magic: Buffer; type: string; ext: string }> = [
          { magic: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), type: "PNG 图片", ext: ".png" },
          { magic: Buffer.from([0xff, 0xd8, 0xff]), type: "JPEG 图片", ext: ".jpg" },
          { magic: Buffer.from([0x47, 0x49, 0x46, 0x38]), type: "GIF 图片", ext: ".gif" },
          { magic: Buffer.from([0x42, 0x4d]), type: "BMP 图片", ext: ".bmp" },
          { magic: Buffer.from([0x25, 0x50, 0x44, 0x46]), type: "PDF 文档", ext: ".pdf" },
          { magic: Buffer.from([0xd0, 0xcf, 0x11, 0xe0]), type: "OLE 复合文档(Word/Excel旧版)", ext: ".doc/.xls" },
          { magic: Buffer.from([0x50, 0x4b, 0x03, 0x04]), type: "ZIP (可能是JAR/APK/DOCX/XLSX)", ext: ".zip" },
          { magic: Buffer.from([0x7f, 0x45, 0x4c, 0x46]), type: "ELF 可执行文件", ext: ".elf/.so" },
          { magic: Buffer.from([0x4d, 0x5a]), type: "PE 可执行文件", ext: ".exe/.dll" },
          { magic: Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), type: "Mach-O (32-bit)", ext: "" },
          { magic: Buffer.from([0xfe, 0xed, 0xfa, 0xcf]), type: "Mach-O (64-bit)", ext: "" },
          { magic: Buffer.from([0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00]), type: "DEX (Android Dalvik字节码)", ext: ".dex" },
          { magic: Buffer.from([0x78, 0x9c]), type: "Zlib 压缩数据", ext: ".gz" },
          { magic: Buffer.from([0x1f, 0x8b]), type: "Gzip 压缩文件", ext: ".gz" },
          { magic: Buffer.from([0x52, 0x61, 0x72, 0x21]), type: "RAR 压缩文件", ext: ".rar" },
          { magic: Buffer.from([0x5a, 0x57, 0x53, 0x53]), type: "7z 压缩文件", ext: ".7z" },
          { magic: Buffer.from([0x00, 0x00, 0x01, 0xba]), type: "MPEG 视频", ext: ".mpg" },
          { magic: Buffer.from([0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70]), type: "MP4 视频", ext: ".mp4" },
          { magic: Buffer.from([0x49, 0x44, 0x33]), type: "MP3 音频", ext: ".mp3" },
          { magic: Buffer.from([0x66, 0x4c, 0x61, 0x43]), type: "FLAC 音频", ext: ".flac" },
          { magic: Buffer.from([0x77, 0x4f, 0x46, 0x66]), type: "OOXML (DOCX/XLSX/PPTX)", ext: ".docx" },
          { magic: Buffer.from([0x23, 0x21]), type: "Python 脚本", ext: ".py" },
        ];

        for (const sig of signatures) {
          if (buf.slice(0, sig.magic.length).equals(sig.magic)) {
            return `[文件识别] ${path}\n真实类型: ${sig.type}\n建议扩展名: ${sig.ext}\n文件头: ${buf.slice(0, 16).toString("hex")}`;
          }
        }

        return `[文件识别] ${path}\n文件头: ${buf.slice(0, 16).toString("hex")}\n文本预览: ${buf.toString("utf-8", 0, 100)}\n未能识别类型，请手动判断`;
      } catch (err: any) {
        return `[识别失败] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "entropy_analysis",
    description: "文件熵分析：检测文件是否加密/压缩/高熵",
    parameters: z.object({
      path: z.string().describe("文件路径"),
      blockSize: z.number().optional().describe("块大小，默认 256"),
    }),
    category: "misc",
    concurrent: true,
    execute: async (args: any) => {
      const { path, blockSize = 256 } = args;
      try {
        const buf = fs.readFileSync(path);

        function calcEntropy(data: Buffer): number {
          const freq: number[] = new Array(256).fill(0);
          for (const b of data) freq[b]++;
          let entropy = 0;
          for (const f of freq) {
            if (f > 0) {
              const p = f / data.length;
              entropy -= p * Math.log2(p);
            }
          }
          return entropy;
        }

        const blocks: { offset: number; entropy: number }[] = [];
        for (let i = 0; i < buf.length; i += blockSize) {
          const block = buf.slice(i, i + blockSize);
          blocks.push({ offset: i, entropy: calcEntropy(block) });
        }

        const overallEntropy = calcEntropy(buf);
        const avgEntropy = blocks.reduce((s, b) => s + b.entropy, 0) / blocks.length;

        let classification = "未知";
        if (overallEntropy > 7.5) classification = "⚠️ 高度加密/压缩 (熵>7.5)";
        else if (overallEntropy > 6.5) classification = "中等熵 (可能压缩或结构化数据)";
        else if (overallEntropy > 4.0) classification = "低熵 (普通文本/代码)";
        else classification = "极低熵 (重复性高)";

        const highEntropyBlocks = blocks.filter((b) => b.entropy > 7.5);

        return `[熵分析] ${path}\n大小: ${buf.length} 字节\n整体熵: ${overallEntropy.toFixed(4)} bits/byte\n平均熵: ${avgEntropy.toFixed(4)}\n分类: ${classification}\n\n高熵块 (>7.5): ${highEntropyBlocks.length} 个\n${highEntropyBlocks.slice(0, 10).map((b) => `  @0x${b.offset.toString(16)}: ${b.entropy.toFixed(4)}`).join("\n") || "  无"}`;
      } catch (err: any) {
        return `[熵分析失败] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "image_stego_check",
    description: "图片隐写检测：检查 LSB 位是否异常、是否存在附加数据",
    parameters: z.object({ path: z.string().describe("图片文件路径 (PNG/BMP)") }),
    category: "misc",
    concurrent: true,
    execute: async (args: any) => {
      const { path } = args;
      try {
        const buf = fs.readFileSync(path);

        const isPNG = buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47;
        const isBMP = buf[0] === 0x42 && buf[1] === 0x4d;

        if (!isPNG && !isBMP) {
          return `[隐写检测] ${path}\n仅支持 PNG 和 BMP 格式。当前文件: ${buf.slice(0, 8).toString("hex")}`;
        }

        const lsbChanges: number[] = [];
        let lsbChangesInRow = 0;
        let lsbTotal = 0;
        let consecutiveLSBChanges = 0;
        let maxConsecutiveLSB = 0;

        for (let i = 0; i < Math.min(buf.length, 10000); i++) {
          const lsb = buf[i] & 1;
          lsbTotal += lsb;
        }

        const lsbRatio = lsbTotal / Math.min(buf.length, 10000);

        const pngChunks: Array<{ type: string; length: number; offset: number }> = [];
        if (isPNG) {
          let offset = 8;
          while (offset < buf.length - 12) {
            const length = buf.readUInt32BE(offset);
            const type = buf.slice(offset + 4, offset + 8).toString("ascii");
            pngChunks.push({ type, length, offset });
            offset += 12 + length;
            if (type === "IEND") break;
          }

          const idatChunk = pngChunks.find((c) => c.type === "IDAT");
          const iendChunk = pngChunks.find((c) => c.type === "IEND");

          let hasExtraData = false;
          let extraInfo = "";
          if (iendChunk) {
            const afterIEND = buf.slice(iendChunk.offset + 12);
            if (afterIEND.length > 0 && afterIEND.length < 100000) {
              hasExtraData = true;
              extraInfo = `\n⚠️ IEND 后存在 ${afterIEND.length} 字节额外数据！可能藏有隐写内容。`;
            }
          }

          return `[PNG隐写检测] ${path}\n大小: ${buf.length} 字节\n\nPNG Chunk 结构:\n${pngChunks.map((c) => `  ${c.type}: ${c.length}字节 @0x${c.offset.toString(16)}`).join("\n")}\n\nLSB 分析:\n  LSB 为 1 的比例: ${(lsbRatio * 100).toFixed(2)}%\n  (随机数据约 50%，若显著偏离可能存在隐写)\n  建议: 使用 zsteg、stegsolve 等工具进一步分析${extraInfo}`;
        }

        return `[隐写检测] ${path}\nLSB 为 1 的比例: ${(lsbRatio * 100).toFixed(2)}%\n建议: 使用 steghide、zsteg 等工具进一步分析`;
      } catch (err: any) {
        return `[隐写检测失败] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "traffic_analysis",
    description: "网络流量分析：基础 PCAP/流量文件解析（统计协议、会话、可疑模式）",
    parameters: z.object({
      path: z.string().describe("PCAP/流量文件路径"),
      maxPackets: z.number().optional().describe("最大分析包数，默认 1000"),
    }),
    category: "misc",
    concurrent: true,
    execute: async (args: any) => {
      const { path, maxPackets = 1000 } = args;
      try {
        const buf = fs.readFileSync(path);

        if (buf.length < 24) return "[流量分析] 文件太小或不是有效的 PCAP";

        const isPcap = buf[0] === 0xd4 && buf[1] === 0xc3 && buf[2] === 0xb2 && buf[3] === 0xa1 ||
          buf[0] === 0xa1 && buf[1] === 0xb2 && buf[2] === 0xc3 && buf[3] === 0xd4;

        if (!isPcap) {
          return `[流量分析] ${path}\n不是标准 PCAP 格式。文件头: ${buf.slice(0, 16).toString("hex")}`;
        }

        const linkType = buf.readUInt32LE(20);
        const protocols: Record<string, number> = {};
        let packetCount = 0;
        let suspiciousPatterns: string[] = [];

        let offset = 24;
        if (linkType === 1) {
          while (offset < buf.length - 16 && packetCount < maxPackets) {
            const inclLen = buf.readUInt32LE(offset + 8);
            if (offset + 16 + inclLen > buf.length) break;

            const ethType = buf.readUInt16LE(offset + 12 + 14);
            if (ethType === 0x0800) {
              const ipStart = offset + 16 + 14;
              if (ipStart + 20 < buf.length) {
                const protocol = buf[ipStart + 9];
                const protoNames: Record<number, string> = { 1: "ICMP", 6: "TCP", 17: "UDP" };
                const proto = protoNames[protocol] || `IP(${protocol})`;
                protocols[proto] = (protocols[proto] || 0) + 1;

                if (protocol === 6) {
                  const srcPort = buf.readUInt16LE(ipStart + 20);
                  const dstPort = buf.readUInt16LE(ipStart + 22);
                  const commonPorts = [80, 443, 8080, 22, 21, 25, 53, 3306, 6379];
                  if (!commonPorts.includes(srcPort) && !commonPorts.includes(dstPort)) {
                    suspiciousPatterns.push(`  非标准端口: ${srcPort} → ${dstPort}`);
                  }
                }
              }
            }

            offset += 16 + inclLen;
            packetCount++;
          }
        }

        const protoSummary = Object.entries(protocols)
          .sort((a, b) => b[1] - a[1])
          .map(([k, v]) => `  ${k}: ${v} 包`).join("\n");

        return `[流量分析] ${path}\n包数: ${packetCount}\n链路层: ${linkType === 1 ? "Ethernet" : linkType === 113 ? "IPv4" : "其他"}\n\n协议统计:\n${protoSummary || "  (无)"}\n\n可疑模式:\n${suspiciousPatterns.slice(0, 20).join("\n") || "  (无明显异常)"}\n\n建议: 使用 tshark/wireshark 进行详细分析`;
      } catch (err: any) {
        return `[流量分析失败] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "file_search_content",
    description: "在文件中搜索 flag 模式、base64 编码串、常见敏感信息",
    parameters: z.object({
      path: z.string().describe("文件或目录路径"),
      recursive: z.boolean().optional(),
    }),
    category: "misc",
    concurrent: true,
    execute: async (args: any) => {
      const { path, recursive = true } = args;

      const patterns: Array<{ name: string; regex: RegExp }> = [
        { name: "CTF Flag模式", regex: /flag\{[^}]+\}/gi },
        { name: "FLAG模式", regex: /FLAG\{[^}]+\}/gi },
        { name: "ctf{模式", regex: /ctf\{[^}]+\}/gi },
        { name: "Base64串(疑似)", regex: /[A-Za-z0-9+\/]{20,}={0,2}/g },
        { name: "Hex串(疑似)", regex: /\b[0-9a-fA-F]{32,}\b/g },
        { name: "IP地址", regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g },
        { name: "Email", regex: /[\w.-]+@[\w.-]+\.\w+/g },
        { name: "Access Key", regex: /AKIA[0-9A-Z]{16}/g },
        { name: "AWS Secret", regex: /(?=.{40})[A-Za-z0-9\/+=]{40}/g },
      ];

      const results: string[] = [];

      function scanFile(filePath: string) {
        try {
          const content = fs.readFileSync(filePath, "utf-8");
          for (const { name, regex } of patterns) {
            const matches = content.match(regex);
            if (matches && matches.length > 0) {
              results.push(`  [${name}] ${filePath}: ${matches.slice(0, 5).join(", ")}${matches.length > 5 ? `...(+${matches.length - 5})` : ""}`);
            }
          }
        } catch {}
      }

      try {
        const stat = fs.statSync(path);
        if (stat.isDirectory() && recursive) {
          function walk(dir: string) {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            for (const e of entries) {
              const full = `${dir}/${e.name}`;
              if (e.isDirectory() && recursive) walk(full);
              else if (e.isFile()) scanFile(full);
            }
          }
          walk(path);
        } else {
          scanFile(path);
        }

        return `[敏感信息搜索] ${path}\n\n匹配结果(${results.length}):\n${results.slice(0, 50).join("\n") || "  (未发现 flag 模式或敏感信息)"}${results.length > 50 ? `\n... 还有 ${results.length - 50} 条` : ""}`;
      } catch (err: any) {
        return `[搜索失败] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "command_exec",
    description: "执行系统命令（仅用于授权的 CTF 环境）",
    parameters: z.object({
      command: z.string().describe("要执行的命令"),
      timeout: z.number().optional().describe("超时（毫秒），默认 10000"),
      shell: z.string().optional().describe("使用的 shell，默认 /bin/sh"),
    }),
    category: "system",
    requirePermission: true,
    execute: async (args: any) => {
      const { command, timeout = 10000, shell } = args;
      return new Promise((resolve) => {
        child_process.exec(
          command,
          { timeout, shell: shell || (process.platform === "win32" ? "cmd.exe" : "/bin/sh"), maxBuffer: 1024 * 1024 },
          (error: any, stdout: string, stderr: string) => {
            let result = `[命令执行] ${command}\n`;
            if (stdout) result += `STDOUT:\n${stdout}\n`;
            if (stderr) result += `STDERR:\n${stderr}\n`;
            if (error) result += `错误: ${error.message}\n`;
            resolve(result.trim());
          }
        );
      });
    },
  });

  registry.register({
    name: "file_read_real",
    description: "读取本地文件真实内容",
    parameters: z.object({
      path: z.string().describe("文件路径"),
      encoding: z.string().optional().describe("编码，默认 utf-8"),
      maxSize: z.number().optional().describe("最大读取字节数，默认 1048576"),
    }),
    category: "system",
    concurrent: true,
    execute: async (args: any) => {
      const { path, encoding = "utf-8", maxSize = 1048576 } = args;
      try {
        const stat = fs.statSync(path);
        if (stat.size > maxSize) {
          const content = fs.readFileSync(path, { encoding: encoding as BufferEncoding, flag: "r" }).slice(0, maxSize);
          return `[文件读取] ${path} (${stat.size} 字节，已截断至 ${maxSize} 字节)\n\n${content}\n... (已截断)`;
        }
        const content = fs.readFileSync(path, { encoding: encoding as BufferEncoding, flag: "r" });
        return `[文件读取] ${path} (${stat.size} 字节)\n\n${content}`;
      } catch (err: any) {
        return `[文件读取失败] ${path}: ${err.message}`;
      }
    },
  });

  registry.register({
    name: "file_write_real",
    description: "写入本地文件",
    parameters: z.object({
      path: z.string().describe("目标文件路径"),
      content: z.string().describe("要写入的内容"),
      append: z.boolean().optional().describe("是否追加写入，默认 false"),
    }),
    category: "system",
    requirePermission: true,
    execute: async (args: any) => {
      const { path, content, append = false } = args;
      try {
        if (append) {
          fs.appendFileSync(path, content, "utf-8");
        } else {
          fs.writeFileSync(path, content, "utf-8");
        }
        const stat = fs.statSync(path);
        return `[文件写入成功] ${path} (${stat.size} 字节)${append ? " [追加模式]" : ""}`;
      } catch (err: any) {
        return `[文件写入失败] ${path}: ${err.message}`;
      }
    },
  });

  registry.register({
    name: "file_list",
    description: "列出目录内容",
    parameters: z.object({
      path: z.string().optional().describe("目录路径，默认当前目录"),
      showHidden: z.boolean().optional().describe("显示隐藏文件，默认 false"),
    }),
    category: "system",
    concurrent: true,
    execute: async (args: any) => {
      const { path = ".", showHidden = false } = args;
      try {
        const entries = fs.readdirSync(path, { withFileTypes: true });
        const items = entries
          .filter((e) => showHidden || !e.name.startsWith("."))
          .map((e) => {
            const stat = fs.statSync(`${path}/${e.name}`);
            const type = e.isDirectory() ? "[DIR] " : "[FILE]";
            const size = e.isDirectory() ? "" : `${stat.size}字节`;
            const time = stat.mtime.toISOString().split("T")[0];
            return `  ${type} ${e.name} ${size.padEnd(15)} ${time}`;
          });
        return `[目录列表] ${path}\n共 ${items.length} 项:\n${items.join("\n")}`;
      } catch (err: any) {
        return `[列表失败] ${path}: ${err.message}`;
      }
    },
  });

  registry.register({
    name: "grep_search",
    description: "在文件中搜索字符串（类似 grep）",
    parameters: z.object({
      path: z.string().describe("文件或目录路径"),
      pattern: z.string().describe("搜索字符串或正则"),
      recursive: z.boolean().optional().describe("是否递归搜索目录，默认 true"),
      ignoreCase: z.boolean().optional().describe("忽略大小写，默认 true"),
    }),
    category: "system",
    concurrent: true,
    execute: async (args: any) => {
      const { path, pattern, recursive = true, ignoreCase = true } = args;
      try {
        const results: string[] = [];
        const regex = new RegExp(pattern, ignoreCase ? "i" : "");

        function searchFile(filePath: string) {
          const content = fs.readFileSync(filePath, "utf-8");
          const lines = content.split("\n");
          for (let i = 0; i < lines.length; i++) {
            if (regex.test(lines[i])) {
              results.push(`  ${filePath}:${i + 1}: ${lines[i].trim().slice(0, 100)}`);
            }
          }
        }

        function walkDir(dir: string) {
          const entries = fs.readdirSync(dir, { withFileTypes: true });
          for (const entry of entries) {
            const fullPath = `${dir}/${entry.name}`;
            if (entry.isDirectory() && recursive) {
              walkDir(fullPath);
            } else if (entry.isFile()) {
              try { searchFile(fullPath); } catch {}
            }
          }
        }

        const stat = fs.statSync(path);
        if (stat.isDirectory()) {
          walkDir(path);
        } else {
          searchFile(path);
        }

        return `[Grep搜索] "${pattern}" in ${path}\n找到 ${results.length} 处匹配:\n${results.slice(0, 50).join("\n") || "  (无匹配)"}${results.length > 50 ? `\n... 还有 ${results.length - 50} 处` : ""}`;
      } catch (err: any) {
        return `[搜索失败] ${path}: ${err.message}`;
      }
    },
  });

  registry.register({
    name: "video_audio_stego",
    description: "视频/音频隐写检测：分析帧间差异、音频波形异常",
    parameters: z.object({
      path: z.string().describe("视频或音频文件路径"),
    }),
    category: "misc",
    concurrent: true,
    execute: async (args: any) => {
      const { path } = args;
      try {
        const buf = fs.readFileSync(path);

        if (buf.length < 16) return "[隐写检测] 文件太小";

        const header = buf.slice(0, 16).toString("hex");
        const findings: string[] = [];

        if (buf[0] === 0x49 && buf[1] === 0x44 && buf[2] === 0x33) {
          findings.push("✅ MP3 音频文件");
          const id3Size = (buf[6] << 21) | (buf[7] << 14) | (buf[8] << 7) | buf[9];
          findings.push(`  ID3 标签大小: ${id3Size} 字节`);

          if (buf.includes(Buffer.from("APIC"))) findings.push("  ⚠️ 检测到 APIC (内嵌图片) - 可能藏有隐写");
          if (buf.includes(Buffer.from("TXXX"))) findings.push("  ⚠️ 检测到 TXXX (自定义标签) - 可能藏有数据");
          if (buf.includes(Buffer.from("COMM"))) findings.push("  ℹ️ 检测到 COMM (注释)");

          const audioData = buf.slice(id3Size + 10);
          const lsbRatio = audioData.reduce((s, b) => s + (b & 1), 0) / audioData.length;
          findings.push(`  LSB 比例: ${(lsbRatio * 100).toFixed(2)}% (随机≈50%)`);

          if (lsbRatio > 0.55 || lsbRatio < 0.45) {
            findings.push("  ⚠️ LSB 比例异常，可能存在音频隐写");
          }
        } else if (buf[0] === 0x00 && buf[1] === 0x00 && buf[2] === 0x00 && buf[3] === 0x18) {
          findings.push("✅ MP4 视频文件");

          const ftypBox = buf.slice(4, 8).toString("ascii");
          findings.push(`  ftyp box: ${ftypBox}`);

          if (buf.includes(Buffer.from("moov"))) findings.push("  ℹ️ moov box 存在 (元数据)");
          if (buf.includes(Buffer.from("mdat"))) findings.push("  ℹ️ mdat box 存在 (媒体数据)");
          if (buf.includes(Buffer.from("stbl"))) findings.push("  ℹ️ stbl box 存在 (采样表)");

          const moovOffset = buf.indexOf(Buffer.from("moov"));
          const mdatOffset = buf.indexOf(Buffer.from("mdat"));
          if (moovOffset >= 0 && mdatOffset >= 0 && moovOffset < mdatOffset) {
            findings.push("  ⚠️ moov 在 mdat 前 - 正常布局");
          }
          if (mdatOffset >= 0) {
            const afterMdat = buf.slice(mdatOffset + 4);
            if (afterMdat.length > 0 && afterMdat.length < 100000) {
              findings.push(`  ⚠️ mdat 后存在 ${afterMdat.length} 字节数据 - 可能藏有隐写!`);
            }
          }
        } else if (buf[0] === 0x52 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x46) {
          findings.push("✅ RIFF/WAV 音频文件");
          findings.push(`  文件头: RIFF${buf.slice(8, 12).toString("ascii")}`);

          if (buf.includes(Buffer.from("data"))) {
            const dataOffset = buf.indexOf(Buffer.from("data"));
            const dataBuf = buf.slice(dataOffset + 8);
            const lsbRatio = dataBuf.slice(0, Math.min(dataBuf.length, 50000)).reduce((s, b) => s + (b & 1), 0) / Math.min(dataBuf.length, 50000);
            findings.push(`  data 段 LSB 比例: ${(lsbRatio * 100).toFixed(2)}%`);
            if (lsbRatio > 0.55 || lsbRatio < 0.45) {
              findings.push("  ⚠️ LSB 比例异常，可能存在 WAV 隐写");
            }
          }
        } else {
          findings.push(`[未知格式] 头部: ${header}`);
          findings.push("  支持的格式: MP3, MP4, WAV");
        }

        return `[视频/音频隐写检测] ${path}\n\n${findings.join("\n")}\n\n建议:\n- 使用 Audacity 分析音频波形\n- 使用 ffmpeg 提取视频帧\n- 使用 steghide/spectrogram 工具`;
      } catch (err: any) {
        return `[检测失败] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "archive_crack",
    description: "压缩包爆破：对 ZIP/RAR/7z 压缩包进行弱密码爆破",
    parameters: z.object({
      path: z.string().describe("压缩包文件路径"),
      passwordList: z.array(z.string()).optional().describe("自定义密码列表"),
      maxLength: z.number().optional().describe("暴力破解最大长度, 默认 6"),
    }),
    category: "misc",
    concurrent: true,
    execute: async (args: any) => {
      const { path, passwordList, maxLength = 6 } = args;

      try {
        const buf = fs.readFileSync(path);
        if (buf[0] !== 0x50 || buf[1] !== 0x4b) {
          return "[压缩包爆破] 仅支持 ZIP 格式 (检测文件头不是 ZIP)";
        }

        const weaknesses: string[] = [];
        weaknesses.push(`ZIP 文件大小: ${buf.length} 字节`);

        if (buf.includes(Buffer.from([0x50, 0x4b, 0x01, 0x02]))) {
          weaknesses.push("  包含中央目录记录");

          const centralDirSig = Buffer.from([0x50, 0x4b, 0x01, 0x02]);
          let offset = buf.indexOf(centralDirSig);
          const fileCount = 0;
          while (offset !== -1) {
            const compMethod = buf.readUInt16LE(offset + 8);
            const flagBits = buf.readUInt16LE(offset + 6);
            const encrypted = flagBits & 0x1;
            if (encrypted) weaknesses.push(`  ⚠️ 检测到加密文件 (压缩方法: ${compMethod})`);
            offset = buf.indexOf(centralDirSig, offset + 1);
          }
        }

        const commonPasswords = passwordList || [
          "123456", "password", "12345678", "1234", "54321", "flag",
          "ctf", "admin", "test", "123", "12345", "111111", "000000",
          "qwerty", "abc123", "letmein", "welcome", "monkey", "dragon",
          "master", "shadow", "princess", "football", "baseball",
          "iloveyou", "trustno1", "sunshine", "princess", "michael",
        ];

        weaknesses.push(`\n常用密码字典 (${commonPasswords.length} 个):`);
        commonPasswords.slice(0, 15).forEach((p: string, i: number) => {
          weaknesses.push(`  [${i + 1}] ${p}`);
        });
        if (commonPasswords.length > 15) weaknesses.push(`  ... 还有 ${commonPasswords.length - 15} 个`);

        weaknesses.push(`\n暴力破解建议 (最长 ${maxLength} 位):`);
        weaknesses.push(`  字符集1: [0-9] (${Math.pow(10, maxLength)} 组合)`);
        weaknesses.push(`  字符集2: [a-z] (${Math.pow(26, maxLength)} 组合)`);
        weaknesses.push(`  字符集3: [a-zA-Z0-9] (${Math.pow(62, maxLength)} 组合)`);

        return `[压缩包爆破分析] ${path}\n\n${weaknesses.join("\n")}\n\n推荐工具:\n- John the Ripper: john --wordlist=rockyou.txt hash.txt\n- Hashcat: hashcat -m 17200 hash.txt rockyou.txt\n- fcrackzip: fcrackzip -u -p zipfile.zip\n- zip2john: zip2john zipfile.zip > hash.txt`;
      } catch (err: any) {
        return `[爆破失败] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "qr_decoder",
    description: "二维码检测：从文件中提取可能的二维码区域信息",
    parameters: z.object({
      path: z.string().describe("图片文件路径 (PNG/JPG)"),
    }),
    category: "misc",
    concurrent: true,
    execute: async (args: any) => {
      const { path } = args;
      try {
        const buf = fs.readFileSync(path);

        if (buf.length < 16) return "[二维码检测] 文件太小";

        const detections: string[] = [];
        detections.push(`文件大小: ${buf.length} 字节`);

        if (buf[0] === 0x89 && buf[1] === 0x50) {
          detections.push("✅ PNG 文件");
        } else if (buf[0] === 0xff && buf[1] === 0xd8) {
          detections.push("✅ JPEG 文件");
        } else {
          detections.push("⚠️ 非标准图片格式");
        }

        const qrPatterns: Array<{ pattern: Uint8Array; name: string }> = [];
        qrPatterns.push({ pattern: Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), name: "定位图案检测" });
        qrPatterns.push({ pattern: Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), name: "全白方块" });
        qrPatterns.push({ pattern: Buffer.from([0xff, 0x00, 0xff]), name: "交替黑白" });

        for (const qp of qrPatterns) {
          let pos = -1;
          let count = 0;
          while ((pos = buf.indexOf(qp.pattern as Uint8Array, pos + 1)) !== -1 && count < 5) {
            count++;
            detections.push(`  ℹ️ 检测到"${qp.name}" @0x${pos.toString(16)}`);
          }
        }

        const qrData = [
          "QR码特征:",
          "  • 3个定位图案 (大角方块)",
          "  • 1个对齐图案 (小方块)",
          "  • 定时图案 (交替黑白)",
          "  • 数据编码区 (不规则黑白块)",
        ];
        detections.push(qrData.join("\n"));

        if (buf.includes(Buffer.from("QR_CODE")) || buf.includes(Buffer.from("qr_code"))) {
          detections.push("  ✅ 元数据中包含 QR_CODE 标识");
        }

        const hasQRMarkers = buf.includes(Buffer.from([0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00]));
        if (hasQRMarkers) detections.push("  ⚠️ 检测到疑似 QR 码定位图案模式");

        return `[二维码检测] ${path}\n\n${detections.join("\n")}\n\n推荐解码工具:\n- zbarimg: zbarimg image.png\n- opencv: cv2.QRCodeDetector()\n- 在线: https://www.qr-scanner.io/\n- 命令行: convert image.png -colorspace Gray output.pgm && zxing output.pgm`;
      } catch (err: any) {
        return `[检测失败] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "document_stego",
    description: "文档隐写检测：检查 PDF/DOCX 文档中的隐藏内容",
    parameters: z.object({
      path: z.string().describe("文档文件路径 (PDF/DOCX/XLSX)"),
    }),
    category: "misc",
    concurrent: true,
    execute: async (args: any) => {
      const { path } = args;
      try {
        const buf = fs.readFileSync(path);
        const detections: string[] = [];

        if (buf[0] === 0x25 && buf[1] === 0x50 && buf[2] === 0x44 && buf[3] === 0x46) {
          detections.push("✅ PDF 文档");

          const objCount = (buf.toString("latin1").match(/\/Type\s*\/Page[^s]/g) || []).length;
          detections.push(`  页数: ${objCount}`);

          const embeddedFiles = ["EmbeddedFiles", "EmbeddedFile", "/F", "/EF"];
          for (const ef of embeddedFiles) {
            if (buf.includes(Buffer.from(ef))) {
              detections.push(`  ⚠️ 检测到嵌入文件引用: ${ef}`);
            }
          }

          const jsKeywords = ["javascript", "JavaScript", "/JS", "/JavaScript", "/OpenAction"];
          for (const kw of jsKeywords) {
            if (buf.includes(Buffer.from(kw))) {
              detections.push(`  ⚠️ 检测到 JavaScript: ${kw} (可能有恶意行为)`);
            }
          }

          const stegoIndicators = [
            { sig: Buffer.from("w4P="), name: "Base64 编码数据" },
            { sig: Buffer.from("AA=="), name: "Base64 结尾标记" },
            { sig: Buffer.from("stream\r\n"), name: "PDF Stream (可能压缩/编码数据)" },
            { sig: Buffer.from("FlateDecode"), name: "FlateDecode 压缩流" },
          ];
          for (const si of stegoIndicators) {
            if (buf.includes(si.sig)) {
              detections.push(`  ℹ️ ${si.name} - 可能包含隐藏数据`);
            }
          }

          const longStrings = buf.toString("latin1").match(/[\x20-\x7e]{50,}/g);
          if (longStrings) {
            const suspicious = longStrings.filter((s) => /[=+/]{20,}/.test(s) || /[A-Za-z0-9+/]{30,}={0,2}/.test(s));
            if (suspicious.length > 0) {
              detections.push(`  ⚠️ 检测到 ${suspicious.length} 个疑似 Base64 长字符串`);
              suspicious.slice(0, 3).forEach((s) => detections.push(`    ${s.slice(0, 80)}...`));
            }
          }
        } else if (buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) {
          detections.push("✅ ZIP 格式文档 (DOCX/XLSX/PPTX)");

          if (buf.includes(Buffer.from("[Content_Types].xml"))) {
            detections.push("  ℹ️ 包含 [Content_Types].xml (标准 Office)");
          }
          if (buf.includes(Buffer.from("META-INF"))) {
            detections.push("  ⚠️ 包含 META-INF (可能有宏/VBA)");
          }
          if (buf.includes(Buffer.from("docProps/vbaProject"))) {
            detections.push("  ⚠️⚠️ 包含 VBA 宏项目 - 高度可疑!");
          }
          if (buf.includes(Buffer.from("ActiveX"))) {
            detections.push("  ⚠️ 包含 ActiveX 控件 - 可能有风险");
          }
          if (buf.includes(Buffer.from("externalData"))) {
            detections.push("  ⚠️ 包含 externalData - 可能外联");
          }
          if (buf.includes(Buffer.from("oleObject"))) {
            detections.push("  ⚠️ 包含 oleObject - OLE 嵌入对象");
          }

          const customXml = buf.includes(Buffer.from("customXml"));
          if (customXml) detections.push("  ℹ️ 包含 customXml (自定义 XML 数据)");
        } else if (buf[0] === 0xd0 && buf[1] === 0xcf) {
          detections.push("✅ OLE 复合文档 (旧版 DOC/XLS/PPT)");
          if (buf.includes(Buffer.from("Macro"))) detections.push("  ⚠️ 包含 VBA 宏");
          if (buf.includes(Buffer.from("ObjectPool"))) detections.push("  ⚠️ 包含对象池");
        } else {
          detections.push(`[未知文档格式] 头部: ${buf.slice(0, 4).toString("hex")}`);
        }

        return `[文档隐写检测] ${path}\n\n${detections.join("\n")}\n\n建议:\n- PDF: 使用 pdfinfo, peepdf, pdf-parser.py\n- DOCX: 使用 oleid, oletools, olevba\n- 通用: 使用 binwalk, foremost, zsteg`;
      } catch (err: any) {
        return `[检测失败] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "memory_forensics",
    description: "内存取证分析：基于内存镜像文件提取关键信息",
    parameters: z.object({
      path: z.string().describe("内存镜像文件路径"),
      profile: z.string().optional().describe("内存画像 (Linux/Windows/Mac), 默认自动检测"),
    }),
    category: "misc",
    concurrent: true,
    execute: async (args: any) => {
      const { path, profile } = args;
      try {
        const buf = fs.readFileSync(path);
        const detections: string[] = [];

        if (buf.length < 1024) return "[内存取证] 文件太小，不是有效的内存镜像";

        detections.push(`内存镜像大小: ${(buf.length / 1024 / 1024).toFixed(2)} MB`);

        const headerStrings = [
          { sig: "Linux", pattern: Buffer.from("Linux version") },
          { sig: "Windows", pattern: Buffer.from("Microsoft Windows") },
          { sig: "Mac", pattern: Buffer.from("Darwin") },
          { sig: "Windows", pattern: Buffer.from("win32") },
          { sig: "Linux", pattern: Buffer.from("GNU/Linux") },
        ];
        for (const hs of headerStrings) {
          if (buf.includes(hs.pattern)) {
            detections.push(`  ✅ 检测到操作系统: ${hs.sig}`);
          }
        }

        const keyArtifacts = [
          { name: "密码", patterns: [Buffer.from("password"), Buffer.from("Password"), Buffer.from("passwd")] },
          { name: "密钥", patterns: [Buffer.from("BEGIN RSA"), Buffer.from("BEGIN PRIVATE"), Buffer.from("secret_key")] },
          { name: "IP地址", patterns: [Buffer.from("0x")] },
          { name: "进程列表", patterns: [Buffer.from("PID"), Buffer.from("process")] },
          { name: "网络连接", patterns: [Buffer.from("ESTABLISHED"), Buffer.from("LISTENING"), Buffer.from("TCP")] },
          { name: "用户名", patterns: [Buffer.from("root"), Buffer.from("admin"), Buffer.from("Administrator")] },
          { name: "FLAG", patterns: [Buffer.from("flag{"), Buffer.from("FLAG{"), Buffer.from("ctf{")] },
          { name: "URL", patterns: [Buffer.from("http://"), Buffer.from("https://")] },
        ];

        for (const ka of keyArtifacts) {
          let count = 0;
          for (const p of ka.patterns) {
            const chunkSize = 10 * 1024 * 1024;
            for (let off = 0; off < buf.length && count < 3; off += chunkSize) {
              if (buf.slice(off, off + chunkSize).includes(p)) {
                count++;
                detections.push(`  ℹ️ [${ka.name}] 检测到相关数据 (示例: ${p.toString("ascii").slice(0, 30)})`);
                break;
              }
            }
          }
        }

        const profileGuesses = profile || (
          buf.includes(Buffer.from("Linux")) ? "Linux" :
          buf.includes(Buffer.from("Windows")) ? "Windows" :
          buf.includes(Buffer.from("Darwin")) ? "Mac" : "未知"
        );

        return `[内存取证分析] ${path}\n推测系统: ${profileGuesses}\n\n${detections.join("\n")}\n\n推荐工具:\n- Volatility 3: vol -f mem.raw windows.pslist\n- Volatility 2.6: volatility -f mem.raw --profile=Win10x64 pslist\n- LiME: lime 内存获取框架\n- Magnet: magnet_for_memory 快速提取`;
      } catch (err: any) {
        return `[取证失败] ${err.message}`;
      }
    },
  });

  return registry;
}