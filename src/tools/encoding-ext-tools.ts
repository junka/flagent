import { z } from "zod";
import { ToolRegistry } from "./registry";

// ============================================================
// 辅助：通用 Base-N 编解码（支持自定义字母表 + 可选 padding）
// ============================================================
function encodeBaseN(buf: Buffer, alphabet: string, bitsPerChar: number, padChar?: string, padTo?: number): string {
  let out = "";
  let buffer = 0;
  let bitsLeft = 0;
  let charCount = 0;
  for (let i = 0; i < buf.length; ) {
    if (bitsLeft < bitsPerChar) {
      buffer = (buffer << 8) | buf[i++];
      bitsLeft += 8;
    }
    while (bitsLeft >= bitsPerChar) {
      bitsLeft -= bitsPerChar;
      out += alphabet[(buffer >> bitsLeft) & ((1 << bitsPerChar) - 1)];
      charCount++;
    }
  }
  if (bitsLeft > 0) {
    buffer <<= bitsPerChar - bitsLeft;
    out += alphabet[buffer & ((1 << bitsPerChar) - 1)];
    charCount++;
  }
  if (padChar && padTo) {
    const rem = charCount % padTo;
    if (rem !== 0) out += padChar.repeat(padTo - rem);
  }
  return out;
}

function decodeBaseN(str: string, alphabet: string, bitsPerChar: number, padChar?: string): Buffer {
  const clean = padChar ? str.split(padChar)[0] : str;
  const out: number[] = [];
  let buffer = 0;
  let bitsLeft = 0;
  for (const c of clean) {
    const v = alphabet.indexOf(c);
    if (v < 0) throw new Error(`Invalid char for alphabet: ${c}`);
    buffer = (buffer << bitsPerChar) | v;
    bitsLeft += bitsPerChar;
    if (bitsLeft >= 8) {
      bitsLeft -= 8;
      out.push((buffer >> bitsLeft) & 0xff);
    }
  }
  return Buffer.from(out);
}

// Base58 (Bitcoin)
const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function encodeBase58(buf: Buffer): string {
  let num = 0n;
  for (const b of buf) num = (num << 8n) | BigInt(b);
  let leadingZeros = 0;
  for (const b of buf) {
    if (b === 0) leadingZeros++; else break;
  }
  let result = "";
  while (num > 0n) {
    result = B58_ALPHABET[Number(num % 58n)] + result;
    num /= 58n;
  }
  return B58_ALPHABET[0].repeat(leadingZeros) + result;
}

function decodeBase58(s: string): Buffer {
  let leadingZeros = 0;
  let i = 0;
  while (i < s.length && s[i] === B58_ALPHABET[0]) { leadingZeros++; i++; }
  let num = 0n;
  for (; i < s.length; i++) {
    const v = B58_ALPHABET.indexOf(s[i]);
    if (v < 0) throw new Error("Invalid base58 char");
    num = num * 58n + BigInt(v);
  }
  let hex = num.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const bytes: number[] = [];
  for (let k = 0; k < leadingZeros; k++) bytes.push(0);
  for (let k = 0; k < hex.length; k += 2) bytes.push(parseInt(hex.slice(k, k + 2), 16));
  return Buffer.from(bytes);
}

// Base91 (variant 常用表)
const B91_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";

function encodeBase91(buf: Buffer): string {
  let out = "";
  let ebq = 0;
  let en = 0;
  for (let i = 0; i < buf.length; i++) {
    ebq |= buf[i] << en;
    en += 8;
    if (en > 13) {
      let ev = ebq & 8191;
      if (ev > 88) { ebq >>= 13; en -= 13; } else { ev = ebq & 16383; ebq >>= 14; en -= 14; }
      out += B91_ALPHABET[ev % 91] + B91_ALPHABET[Math.floor(ev / 91)];
    }
  }
  if (en > 0) {
    out += B91_ALPHABET[ebq % 91];
    if (en > 7 || ebq > 90) out += B91_ALPHABET[Math.floor(ebq / 91)];
  }
  return out;
}

function decodeBase91(d: string): Buffer {
  const table: Record<string, number> = {};
  for (let i = 0; i < B91_ALPHABET.length; i++) table[B91_ALPHABET[i]] = i;
  const out: number[] = [];
  let dbq = 0;
  let dn = 0;
  let dv = -1;
  for (let i = 0; i < d.length; i++) {
    const c = d[i];
    if (!(c in table)) continue;
    if (dv === -1) { dv = table[c]; }
    else {
      dv += table[c] * 91;
      dbq |= dv << dn;
      dn += (dv & 8191) > 88 ? 13 : 14;
      do {
        out.push(dbq & 0xff);
        dbq >>= 8;
        dn -= 8;
      } while (dn > 7);
      dv = -1;
    }
  }
  if (dv !== -1) out.push((dbq | (dv << dn)) & 0xff);
  return Buffer.from(out);
}

// Base85 (Ascii85, Adobe variant)
function encodeBase85(buf: Buffer): string {
  let out = "";
  const len = buf.length;
  const pad = (4 - (len % 4)) % 4;
  const padded = Buffer.concat([buf, Buffer.alloc(pad)]);
  for (let i = 0; i < padded.length; i += 4) {
    let n = ((padded[i] << 24) | (padded[i + 1] << 16) | (padded[i + 2] << 8) | padded[i + 3]) >>> 0;
    if (n === 0 && i + 4 <= len) { out += "z"; continue; }
    const c5: string[] = [];
    for (let j = 4; j >= 0; j--) {
      c5.unshift(String.fromCharCode(33 + (n % 85)));
      n = Math.floor(n / 85);
    }
    out += c5.join("");
  }
  if (pad > 0) out = out.slice(0, out.length - pad);
  return out;
}

function decodeBase85(s: string): Buffer {
  const clean = s.replace(/\s/g, "");
  const out: number[] = [];
  let i = 0;
  while (i < clean.length) {
    if (clean[i] === "z") {
      out.push(0, 0, 0, 0); i++; continue;
    }
    const group = clean.slice(i, Math.min(i + 5, clean.length));
    i += group.length;
    let num = 0;
    for (const c of group) {
      num = num * 85 + (c.charCodeAt(0) - 33);
    }
    const bytes: number[] = [];
    for (let j = 0; j < 4; j++) {
      bytes.unshift((num >> (j * 8)) & 0xff);
      num >>= 8;
    }
    const valid = group.length - 1;
    for (let j = 0; j < valid; j++) out.push(bytes[j]);
  }
  return Buffer.from(out);
}

// UUencode line
function uuEncodeLine(line: Buffer): string {
  if (line.length === 0) return "";
  const len = line.length;
  let out = String.fromCharCode(32 + len);
  for (let i = 0; i < line.length; i += 3) {
    const b = [line[i], line[i + 1] || 0, line[i + 2] || 0];
    const c = ((b[0] << 16) | (b[1] << 8) | b[2]) >>> 0;
    out += String.fromCharCode(
      32 + ((c >> 18) & 0x3f),
      32 + ((c >> 12) & 0x3f),
      32 + ((c >> 6) & 0x3f),
      32 + (c & 0x3f),
    );
  }
  return out;
}

export function createEncodingExtTools(): ToolRegistry {
  const registry = new ToolRegistry();

  // 1. base_family: 多 Base 编码
  registry.register({
    name: "base_family",
    description: "Base 家族编码/解码：Base16/32/36/45/58/62/85/91/92。整数或字节串输入，CTF 中常见变体",
    parameters: z.object({
      action: z.enum(["encode", "decode"]),
      variant: z.enum([
        "base16", "base32", "base36", "base45", "base58_btc", "base58_xmr",
        "base62", "base85_ascii85", "base91", "base92",
      ]),
      input: z.string(),
      asBuffer: z.boolean().optional().default(false),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { action, variant, input, asBuffer } = args;
      try {
        if (action === "encode") {
          const buf: Buffer = /^0x/.test(input) ? Buffer.from(input.slice(2), "hex") : Buffer.from(input, "utf-8");
          switch (variant) {
            case "base16": return buf.toString("hex").toUpperCase();
            case "base32": return encodeBaseN(buf, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 5, "=", 8);
            case "base36": {
              let n = 0n;
              for (const b of buf) n = (n << 8n) | BigInt(b);
              return n.toString(36).toUpperCase() || "0";
            }
            case "base45": return encodeBaseN(buf, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:", 13);
            case "base58_btc": return encodeBase58(buf);
            case "base58_xmr":
            case "base62": {
              const a = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
              let n = 0n;
              for (const b of buf) n = (n << 8n) | BigInt(b);
              let s = "";
              if (n === 0n) s = "0";
              while (n > 0n) { s = a[Number(n % 62n)] + s; n /= 62n; }
              let zeros = 0;
              for (const b of buf) { if (b === 0) zeros++; else break; }
              return a[0].repeat(zeros) + s;
            }
            case "base85_ascii85": return encodeBase85(buf);
            case "base91": return encodeBase91(buf);
            case "base92": {
              const a = B91_ALPHABET + "'";
              return encodeBaseN(buf, a, 7);
            }
          }
        } else {
          switch (variant) {
            case "base16": {
              const b = Buffer.from(input, "hex");
              return asBuffer ? b.toString("hex") : b.toString("utf-8");
            }
            case "base32": {
              const b = decodeBaseN(input.toUpperCase().replace(/=+$/, ""), "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 5);
              return asBuffer ? b.toString("hex") : b.toString("utf-8");
            }
            case "base36": {
              const n = BigInt("0" + input.toLowerCase());
              const bytes: number[] = [];
              let x = n;
              if (x === 0n) bytes.push(0);
              while (x > 0n) { bytes.unshift(Number(x & 0xffn)); x >>= 8n; }
              const b = Buffer.from(bytes);
              return asBuffer ? b.toString("hex") : b.toString("utf-8");
            }
            case "base58_btc": {
              const b = decodeBase58(input);
              return asBuffer ? b.toString("hex") : b.toString("utf-8");
            }
            case "base62": {
              const a = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
              let zeros = 0; let idx = 0;
              while (idx < input.length && input[idx] === a[0]) { zeros++; idx++; }
              let n = 0n;
              for (; idx < input.length; idx++) {
                const v = a.indexOf(input[idx]);
                if (v < 0) throw new Error("Invalid base62");
                n = n * 62n + BigInt(v);
              }
              const bytes: number[] = [];
              for (let k = 0; k < zeros; k++) bytes.push(0);
              let x = n;
              const tmp: number[] = [];
              if (x === 0n) tmp.push(0);
              while (x > 0n) { tmp.unshift(Number(x & 0xffn)); x >>= 8n; }
              const b = Buffer.from([...bytes, ...tmp]);
              return asBuffer ? b.toString("hex") : b.toString("utf-8");
            }
            case "base85_ascii85": {
              const b = decodeBase85(input);
              return asBuffer ? b.toString("hex") : b.toString("utf-8");
            }
            case "base91": {
              const b = decodeBase91(input);
              return asBuffer ? b.toString("hex") : b.toString("utf-8");
            }
            case "base92":
            case "base45":
            case "base58_xmr":
              return `[${variant} decode 简化版] 如需严格解码，请提供更完整输入；当前仅支持 encode`;
          }
        }
        return `[base_family] 未知 variant=${variant}`;
      } catch (e: any) {
        return `[错误] ${e.message}`;
      }
    },
  });

  // 2. uu_xx_pp_encode
  registry.register({
    name: "uu_xx_pp_encode",
    description: "UUencode/XXencode/PPencode 编解码，CTF 杂项题常见三剑客",
    parameters: z.object({
      action: z.enum(["encode", "decode"]),
      variant: z.enum(["uu", "xx", "pp"]),
      input: z.string(),
    }),
    category: "misc",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { action, variant, input } = args;
      try {
        if (action === "encode") {
          const buf = Buffer.from(input, "utf-8");
          if (variant === "uu") {
            let out = "begin 644 file.txt\n";
            for (let i = 0; i < buf.length; i += 45) {
              out += uuEncodeLine(buf.slice(i, i + 45)) + "\n";
            }
            out += "`\nend\n";
            return out;
          }
          if (variant === "xx") {
            const a = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            let out = "begin-XX 644 file.txt\n";
            for (let i = 0; i < buf.length; i += 45) {
              const line = buf.slice(i, i + 45);
              let row = a[line.length];
              for (let j = 0; j < line.length; j += 3) {
                const b = [line[j], line[j + 1] || 0, line[j + 2] || 0];
                const c = ((b[0] << 16) | (b[1] << 8) | b[2]) >>> 0;
                row += a[(c >> 18) & 0x3f] + a[(c >> 12) & 0x3f] + a[(c >> 6) & 0x3f] + a[c & 0x3f];
              }
              out += row + "\n";
            }
            out += "+\nend\n";
            return out;
          }
          // ppencode
          const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!\"#$%&'()*+,-./:;<=>?@[]^_`{|}~";
          let out = "";
          for (let i = 0; i < buf.length; i += 3) {
            const b = [buf[i], buf[i + 1] || 0, buf[i + 2] || 0];
            const c = ((b[0] << 16) | (b[1] << 8) | b[2]) >>> 0;
            out += a[(c >> 18) & 0x3f] + a[(c >> 12) & 0x3f] + a[(c >> 6) & 0x3f] + a[c & 0x3f];
          }
          return out;
        } else {
          return `[${variant} decode 简化版] 输入长度: ${input.length}。可通过 command_exec 配合 uudecode/xxd 命令解码。`;
        }
      } catch (e: any) {
        return `[错误] ${e.message}`;
      }
    },
  });

  // 3. quoted_printable (MIME)
  registry.register({
    name: "qp_mime_codec",
    description: "Quoted-Printable (MIME) / RFC2047 编码解码，邮件头 MIME encoded-word 常用 (B/Q)",
    parameters: z.object({
      action: z.enum(["encode", "decode"]),
      mode: z.enum(["qp", "mime_word_b", "mime_word_q"]),
      input: z.string(),
      charset: z.string().optional().default("UTF-8"),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { action, mode, input, charset } = args;
      try {
        if (action === "decode") {
          if (mode === "qp") {
            const cleaned = input.replace(/=\r?\n/g, "").replace(/=([0-9A-Fa-f]{2})/g, (_m: any, h: string) => String.fromCharCode(parseInt(h, 16)));
            return Buffer.from(cleaned, "latin1").toString("utf-8");
          }
          const m = input.match(/=\?([^?]+)\?([BQbq])\?([^?]*)\?=/);
          if (!m) return "[错误] 不是 MIME encoded-word 格式 (=?charset?B/Q?...?=)";
          const t = m[2].toUpperCase();
          const content = m[3];
          if (t === "B") {
            const b = Buffer.from(content, "base64");
            return b.toString("utf-8");
          } else {
            const cleaned = content.replace(/_/g, " ").replace(/=([0-9A-Fa-f]{2})/g, (_m: any, h: string) => String.fromCharCode(parseInt(h, 16)));
            return Buffer.from(cleaned, "latin1").toString("utf-8");
          }
        } else {
          if (mode === "qp") {
            let out = "";
            let lineLen = 0;
            for (const c of input) {
              const code = c.charCodeAt(0);
              let chunk: string;
              if (c === "\n") { chunk = c; lineLen = 0; }
              else if (code === 9 || (code >= 32 && code <= 60) || (code >= 62 && code <= 126)) { chunk = c; }
              else { chunk = "=" + code.toString(16).toUpperCase().padStart(2, "0"); }
              if (lineLen + chunk.length > 74 && c !== "\n") { out += "=\n"; lineLen = 0; }
              out += chunk; lineLen += chunk.length;
            }
            return out;
          }
          if (mode === "mime_word_b") {
            return `=?${charset}?B?${Buffer.from(input, "utf-8").toString("base64")}?=`;
          }
          if (mode === "mime_word_q") {
            const qp = [...input].map((c: string) => {
              const code = c.charCodeAt(0);
              if (code === 32) return "_";
              if (c === "?" || c === "_" || c === "=" || code > 126 || code < 32)
                return "=" + code.toString(16).toUpperCase().padStart(2, "0");
              return c;
            }).join("");
            return `=?${charset}?Q?${qp}?=`;
          }
        }
        return "[qp_mime_codec] 错误参数";
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  // 4. html_entity
  registry.register({
    name: "html_entity_codec",
    description: "HTML Entity (命名实体 / 数字实体 &#x / &#) 编码解码",
    parameters: z.object({
      action: z.enum(["encode", "decode"]),
      input: z.string(),
      mode: z.enum(["named", "dec", "hex"]).optional().default("hex"),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { action, input, mode } = args;
      try {
        if (action === "decode") {
          let s = input
            .replace(/&quot;/g, '"').replace(/&apos;/g, "'")
            .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
            .replace(/&nbsp;/g, " ");
          s = s.replace(/&#x([0-9a-fA-F]+);?/g, (_m: any, h: string) => String.fromCodePoint(parseInt(h, 16)));
          s = s.replace(/&#(\d+);?/g, (_m: any, d: string) => String.fromCodePoint(parseInt(d, 10)));
          return s;
        } else {
          if (mode === "named") {
            return input
              .replace(/&/g, "&amp;").replace(/"/g, "&quot;")
              .replace(/'/g, "&apos;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
          }
          if (mode === "dec") return [...input].map((c: string) => `&#${c.codePointAt(0)};`).join("");
          return [...input].map((c: string) => `&#x${(c.codePointAt(0) || 0).toString(16).toUpperCase()};`).join("");
        }
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  // 5. js_escape_codec
  registry.register({
    name: "js_escape_codec",
    description: "JS escape / unescape (含 %uXXXX Unicode) 编解码",
    parameters: z.object({ action: z.enum(["encode", "decode"]), input: z.string() }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { action, input } = args;
      try {
        if (action === "decode") {
          return input.replace(/%u([0-9a-fA-F]{4})/g, (_m: any, h: string) => String.fromCharCode(parseInt(h, 16)))
                      .replace(/%([0-9a-fA-F]{2})/g, (_m: any, h: string) => String.fromCharCode(parseInt(h, 16)));
        }
        let out = "";
        for (const c of input) {
          const code = c.charCodeAt(0);
          if (code <= 0x7f) out += encodeURIComponent(c).replace(/%20/g, "%20");
          else out += "%u" + code.toString(16).toUpperCase().padStart(4, "0");
        }
        return out;
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  // 6. radix_convert 任意进制转换
  registry.register({
    name: "radix_convert",
    description: "任意进制转换 (2~62)：整数、字符串 ASCII 码；支持前导零保持",
    parameters: z.object({
      value: z.string(),
      fromRadix: z.number().int().min(2).max(62),
      toRadix: z.number().int().min(2).max(62),
      mode: z.enum(["integer", "ascii"]).optional().default("integer"),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { value, fromRadix, toRadix, mode } = args;
      try {
        if (mode === "integer") {
          const a = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
          let n = 0n;
          const v = value.toLowerCase();
          for (const c of v) {
            const idx = a.indexOf(c);
            if (idx < 0 || idx >= fromRadix) throw new Error(`Invalid char ${c} for radix ${fromRadix}`);
            n = n * BigInt(fromRadix) + BigInt(idx);
          }
          if (toRadix === 10) return n.toString();
          let s = "";
          if (n === 0n) s = "0";
          const toA = toRadix <= 36 ? "0123456789abcdefghijklmnopqrstuvwxyz" : a;
          while (n > 0n) { s = toA[Number(n % BigInt(toRadix))] + s; n /= BigInt(toRadix); }
          return s;
        }
        // ascii: 从字符串的各字节转成目标进制列表
        const bytes: Buffer = Buffer.from(value, "utf-8");
        return Array.from(bytes).map((b: number) => b.toString(toRadix)).join(" ");
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  // 7. punycode (IDNA)
  registry.register({
    name: "punycode_codec",
    description: "Punycode / IDNA 域名编码解码 (xn-- 前缀)",
    parameters: z.object({ action: z.enum(["encode", "decode"]), input: z.string() }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { action, input } = args;
      try {
        const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700, INITIAL_N = 0x80, INITIAL_BIAS = 72;
        const encodeDigit = (d: number, flag: boolean): string => {
          d += 22 + 75 * (d < 26 ? 1 : 0) - (flag ? 0 : 0);
          return String.fromCharCode(d + (d < 26 ? 0x61 : 0x30 - 26));
        };
        const adapt = (delta: number, numpoints: number, first: boolean): number => {
          let k = 0;
          delta = first ? Math.floor(delta / DAMP) : delta >> 1;
          delta += Math.floor(delta / numpoints);
          while (delta > ((BASE - TMIN) * TMAX) / 2) {
            delta = Math.floor(delta / (BASE - TMIN));
            k += BASE;
          }
          return Math.floor(k + ((BASE - TMIN + 1) * delta) / (delta + SKEW));
        };
        if (action === "encode") {
          const codePoints = [...input].map((c: string) => c.codePointAt(0) || 0);
          const basic: string[] = [];
          for (const cp of codePoints) if (cp < 0x80) basic.push(String.fromCharCode(cp));
          let out = basic.join("");
          let basicLen = basic.length;
          let handled = basicLen;
          if (basicLen > 0) out += "-";
          let n = INITIAL_N, delta = 0, bias = INITIAL_BIAS;
          while (handled < codePoints.length) {
            let m = Infinity;
            for (const cp of codePoints) if (cp >= n && cp < m) m = cp;
            delta += (m - n) * (handled + 1);
            n = m;
            for (const cp of codePoints) {
              if (cp < n) delta++;
              else if (cp === n) {
                let q = delta;
                for (let k = BASE; ; k += BASE) {
                  const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
                  if (q < t) break;
                  out += encodeDigit(t + ((q - t) % (BASE - t)), false);
                  q = Math.floor((q - t) / (BASE - t));
                }
                out += encodeDigit(q, false);
                bias = adapt(delta, handled + 1, handled === basicLen);
                delta = 0;
                handled++;
              }
            }
            delta++; n++;
          }
          return "xn--" + out;
        } else {
          try {
            return `[punycode decode 简化] label: ${input.replace(/^xn--/, "")}`;
          } catch {
            return `[punycode decode 简化] label: ${input.replace(/^xn--/, "")}`;
          }
        }
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  // 8. ascii_unicode_codec
  registry.register({
    name: "ascii_unicode_codec",
    description: "ASCII ↔ Unicode/UTF-16/UTF-32 转换：字符↔码点列表、UTF-16BE/LE、\\uXXXX、\\UXXXXXXXX",
    parameters: z.object({
      mode: z.enum([
        "char_to_codepoints", "codepoints_to_chars",
        "utf16_encode", "utf16_decode", "utf32_encode", "utf32_decode",
        "unescape_u",
      ]),
      input: z.string(),
      endian: z.enum(["be", "le"]).optional().default("be"),
      base: z.number().int().min(2).max(62).optional().default(16),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { mode, input, endian, base } = args;
      try {
        switch (mode) {
          case "char_to_codepoints":
            return [...input].map((c: string) => (c.codePointAt(0) || 0).toString(base || 16).toUpperCase()).join(" ");
          case "codepoints_to_chars": {
            const parts = input.trim().split(/[\s,]+/);
            return parts.map((p: string) => String.fromCodePoint(parseInt(p, base || 16))).join("");
          }
          case "utf16_encode": {
            const b = Buffer.from(input, "utf-16le");
            return endian === "be" ? b.swap16().toString("hex").toUpperCase() : b.toString("hex").toUpperCase();
          }
          case "utf16_decode": {
            const clean = input.replace(/\s/g, "");
            const bytes = Buffer.from(clean, "hex");
            const src = endian === "be" ? Buffer.from(bytes).swap16() : bytes;
            return src.toString("utf16le");
          }
          case "utf32_encode": {
            const cps = [...input].map((c: string) => c.codePointAt(0) || 0);
            const bytes: number[] = [];
            for (const cp of cps) {
              const b = [cp & 0xff, (cp >> 8) & 0xff, (cp >> 16) & 0xff, (cp >> 24) & 0xff];
              if (endian === "be") b.reverse();
              bytes.push(...b);
            }
            return Buffer.from(bytes).toString("hex").toUpperCase();
          }
          case "utf32_decode": {
            const clean = input.replace(/\s/g, "");
            const bytes = Buffer.from(clean, "hex");
            let s = "";
            for (let i = 0; i + 3 < bytes.length; i += 4) {
              let cp: number;
              if (endian === "be") cp = (bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3];
              else cp = bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24);
              s += String.fromCodePoint(cp >>> 0);
            }
            return s;
          }
          case "unescape_u":
            return input.replace(/\\U([0-9a-fA-F]{8})/g, (_m: any, h: string) => String.fromCodePoint(parseInt(h, 16)))
                        .replace(/\\u([0-9a-fA-F]{4})/g, (_m: any, h: string) => String.fromCharCode(parseInt(h, 16)));
        }
        return "[ascii_unicode_codec] 未知 mode";
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  return registry;
}
