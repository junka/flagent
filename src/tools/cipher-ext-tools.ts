import { z } from "zod";
import { ToolRegistry } from "./registry";

function mod(a: number, b: number): number { return ((a % b) + b) % b; }
function modInv(a: number, n: number): number {
  let t = 0, newT = 1, r = n, newR = a;
  while (newR !== 0) {
    const q = Math.floor(r / newR);
    [t, newT] = [newT, t - q * newT];
    [r, newR] = [newR, r - q * newR];
  }
  if (r > 1) throw new Error("No modular inverse");
  return mod(t, n);
}

const ALPHA_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALPHA_ARR = Array.from(ALPHA_UPPER);

export function createCipherExtTools(): ToolRegistry {
  const registry = new ToolRegistry();

  registry.register({
    name: "affine_cipher",
    description: "仿射密码 (Affine Cipher)：E(x)=(ax+b) mod 26，D(x)=a⁻¹(x-b) mod 26，支持 bruteforce",
    parameters: z.object({
      action: z.enum(["encrypt", "decrypt", "bruteforce"]),
      text: z.string(),
      a: z.number().int().min(1).max(25).optional(),
      b: z.number().int().min(0).max(25).optional(),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { action, text, a, b } = args;
      try {
        const enc = (s: string, aV: number, bV: number): string => s.replace(/[A-Za-z]/g, (c: string) => {
          const isUp = c === c.toUpperCase();
          const x = c.toUpperCase().charCodeAt(0) - 65;
          const y = mod(aV * x + bV, 26);
          const r = String.fromCharCode(65 + y);
          return isUp ? r : r.toLowerCase();
        });
        const dec = (s: string, aV: number, bV: number): string => {
          const inv = modInv(aV, 26);
          return s.replace(/[A-Za-z]/g, (c: string) => {
            const isUp = c === c.toUpperCase();
            const y = c.toUpperCase().charCodeAt(0) - 65;
            const x = mod(inv * (y - bV), 26);
            const r = String.fromCharCode(65 + x);
            return isUp ? r : r.toLowerCase();
          });
        };
        if (action === "encrypt") return enc(text, a || 5, b || 8);
        if (action === "decrypt") return dec(text, a || 5, b || 8);
        const validA = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];
        const lines: string[] = [];
        for (const aV of validA) {
          for (let bV = 0; bV < 26; bV++) {
            lines.push(`a=${aV},b=${bV}: ${dec(text, aV, bV).slice(0, 80)}`);
          }
        }
        return lines.join("\n");
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  registry.register({
    name: "atbash_cipher",
    description: "埃特巴什码 (Atbash)：A↔Z B↔Y ...，经典单表替换，自身互逆",
    parameters: z.object({ text: z.string() }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { text } = args;
      return text.replace(/[A-Za-z]/g, (c: string) => {
        const base = c <= "Z" ? 65 : 97;
        return String.fromCharCode(25 - (c.charCodeAt(0) - base) + base);
      });
    },
  });

  registry.register({
    name: "vigenere_family",
    description: "维吉尼亚家族：Vigenere / Beaufort / Variant Beaufort / Gronsfeld(数字密钥) / Autokey / Running Key，含 brute-force 常见词",
    parameters: z.object({
      action: z.enum(["encrypt", "decrypt", "kasiski_guess"]),
      variant: z.enum(["vigenere", "beaufort", "variant_beaufort", "gronsfeld", "autokey", "running_key"]),
      text: z.string(),
      key: z.string().optional(),
      maxKeyLen: z.number().int().min(3).max(20).optional().default(8),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { action, variant, text, key, maxKeyLen } = args;
      try {
        const plainCharsetLen = [...text].filter((c: string) => /[A-Za-z]/.test(c)).length;
        const getKeyStream = (len: number): number[] => {
          if (!key) return [];
          let ks: string = key;
          if (variant === "autokey") {
            ks = (key + text.replace(/[^A-Za-z]/g, "")).slice(0, len);
          } else if (variant === "running_key") {
            ks = key.slice(0, len);
          } else {
            ks = key.repeat(Math.ceil(len / key.length)).slice(0, len);
          }
          if (variant === "gronsfeld") {
            return [...ks].map((c: string) => parseInt(c, 10));
          }
          return [...ks.toUpperCase()].map((c: string) => c.charCodeAt(0) - 65);
        };
        const combine = (x: number, k: number): number => {
          switch (variant) {
            case "vigenere": case "autokey": case "running_key": case "gronsfeld": return mod(x + k, 26);
            case "beaufort": return mod(k - x, 26);
            case "variant_beaufort": return mod(x - k, 26);
          }
          return x;
        };
        const uncombine = (y: number, k: number): number => {
          switch (variant) {
            case "vigenere": case "autokey": case "running_key": case "gronsfeld": return mod(y - k, 26);
            case "beaufort": return mod(k - y, 26);
            case "variant_beaufort": return mod(y + k, 26);
          }
          return y;
        };
        if (action === "encrypt" || action === "decrypt") {
          if (!key) return "[错误] encrypt/decrypt 需要 key";
          const ks = getKeyStream(plainCharsetLen);
          if (ks.length === 0) return "[错误] 空 key";
          let ki = 0;
          return text.replace(/[A-Za-z]/g, (c: string) => {
            const isUp = c === c.toUpperCase();
            const x = c.toUpperCase().charCodeAt(0) - 65;
            const r = action === "encrypt" ? combine(x, ks[ki++]) : uncombine(x, ks[ki++]);
            const ch = String.fromCharCode(65 + r);
            return isUp ? ch : ch.toLowerCase();
          });
        }
        const up = text.toUpperCase().replace(/[^A-Z]/g, "");
        const freqAnalysis = (s: string): number[] => {
          const freq = Array(26).fill(0);
          for (const c of s) freq[c.charCodeAt(0) - 65]++;
          return freq;
        };
        const englishFreq = [.0817, .015, .0278, .0425, .127, .0223, .0202, .0609, .0697, .0015, .0077, .0403, .0241, .0675, .0751, .0193, .001, .0599, .0633, .0906, .0276, .0098, .0236, .0015, .0197, .0007];
        const guessKey = (length: number): string => {
          let k = "";
          for (let i = 0; i < length; i++) {
            const col: string[] = [];
            for (let j = i; j < up.length; j += length) col.push(up[j]);
            const f = freqAnalysis(col.join(""));
            let bestShift = 0; let bestScore = -Infinity;
            for (let k2 = 0; k2 < 26; k2++) {
              let sc = 0;
              for (let c = 0; c < 26; c++) sc += englishFreq[c] * (f[(c + k2) % 26] / col.length);
              if (sc > bestScore) { bestScore = sc; bestShift = k2; }
            }
            k += String.fromCharCode(65 + bestShift);
          }
          return k;
        };
        const out: string[] = [`长度 字符数=${up.length}`];
        for (let L = 3; L <= Math.min(maxKeyLen || 8, Math.floor(up.length / 4)); L++) {
          const k = guessKey(L);
          const ksArr = k.repeat(Math.ceil(up.length / L)).slice(0, up.length).split("").map((c: string) => c.charCodeAt(0) - 65);
          let dec = "";
          for (let j = 0; j < Math.min(up.length, 80); j++) {
            dec += String.fromCharCode(65 + uncombine(up.charCodeAt(j) - 65, ksArr[j]));
          }
          out.push(`keyLen=${L} 猜测key=${k} → ${dec}`);
        }
        return out.join("\n");
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  registry.register({
    name: "railfence_cipher",
    description: "栅栏密码 (Rail Fence)：支持任意行数 + 可选 W 形偏移；encrypt / decrypt / bruteforce",
    parameters: z.object({
      action: z.enum(["encrypt", "decrypt", "bruteforce"]),
      text: z.string(),
      rails: z.number().int().min(2).max(20).optional().default(3),
      offset: z.number().int().min(0).max(100).optional().default(0),
      maxRails: z.number().int().min(2).max(20).optional().default(10),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { action, text, rails, offset, maxRails } = args;
      try {
        const buildOrder = (n: number, r: number, off: number): number[] => {
          const period = 2 * (r - 1);
          const order: number[] = [];
          for (let i = 0; i < n; i++) {
            const k = (i + off) % period;
            order.push(k < r ? k : period - k);
          }
          return order;
        };
        if (action === "encrypt") {
          const order = buildOrder(text.length, rails, offset || 0);
          const rows: string[] = Array(rails).fill("");
          for (let i = 0; i < text.length; i++) rows[order[i]] += text[i];
          return rows.join("");
        }
        if (action === "decrypt") {
          const n = text.length;
          const order = buildOrder(n, rails, offset || 0);
          const count: number[] = Array(rails).fill(0);
          for (const r of order) count[r]++;
          let idx = 0;
          const chunks: string[] = [];
          for (let r = 0; r < rails; r++) { chunks.push(text.slice(idx, idx + count[r])); idx += count[r]; }
          const ptr = Array(rails).fill(0);
          let out = "";
          for (let i = 0; i < n; i++) {
            const r = order[i];
            out += chunks[r][ptr[r]++];
          }
          return out;
        }
        const lines: string[] = [];
        for (let R = 2; R <= (maxRails || 10); R++) {
          for (let off = 0; off < Math.min(R + 2, 4); off++) {
            try {
              const n = text.length;
              const order = buildOrder(n, R, off);
              const count: number[] = Array(R).fill(0);
              for (const r of order) count[r]++;
              let idx2 = 0;
              const chunks: string[] = [];
              for (let r = 0; r < R; r++) { chunks.push(text.slice(idx2, idx2 + count[r])); idx2 += count[r]; }
              const ptr = Array(R).fill(0);
              let out = "";
              for (let i = 0; i < n; i++) out += chunks[order[i]][ptr[order[i]]++];
              lines.push(`rails=${R}, offset=${off} → ${out.slice(0, 80)}`);
            } catch { /* skip */ }
          }
        }
        return lines.join("\n");
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  registry.register({
    name: "adfgvx_cipher",
    description: "ADFGX/ADFGVX 一战密码：Polybius + 列置换。mode=adfgx (5x5) / adfgvx (6x6)，带 key 与列替换字 key2",
    parameters: z.object({
      action: z.enum(["encrypt", "decrypt"]),
      mode: z.enum(["adfgx", "adfgvx"]),
      text: z.string(),
      polybiusKey: z.string(),
      columnKey: z.string(),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { action, mode, text, polybiusKey, columnKey } = args;
      try {
        const isVX = mode === "adfgvx";
        const size = isVX ? 6 : 5;
        const labels = isVX ? ["A", "D", "F", "G", "V", "X"] : ["A", "D", "F", "G", "X"];
        if (polybiusKey.length !== size * size) throw new Error(`Polybius key 长度应为 ${size * size}`);
        const orderMap = (k: string): number[] => {
          const pairs = [...k].map((c: string, i: number) => ({ c, i }));
          pairs.sort((a: any, b: any) => a.c.localeCompare(b.c));
          const order: number[] = new Array(k.length);
          for (let r = 0; r < pairs.length; r++) order[(pairs[r] as any).i] = r;
          return order;
        };
        if (action === "encrypt") {
          const idx: Record<string, string> = {};
          for (let r = 0; r < size; r++) for (let c = 0; c < size; c++) {
            idx[polybiusKey[r * size + c].toUpperCase()] = labels[r] + labels[c];
          }
          let step1 = "";
          for (const ch of text.toUpperCase()) {
            if (idx[ch]) step1 += idx[ch];
          }
          const cols = columnKey.length;
          const rows = Math.ceil(step1.length / cols);
          const grid: string[][] = Array.from({ length: rows }, () => new Array(cols).fill(""));
          for (let i = 0; i < step1.length; i++) {
            grid[Math.floor(i / cols)][i % cols] = step1[i];
          }
          const order = orderMap(columnKey);
          const outCols: string[] = new Array(cols).fill("");
          for (let i = 0; i < cols; i++) {
            const colIdx = order.indexOf(i);
            for (let r = 0; r < rows; r++) outCols[i] += grid[r][colIdx];
          }
          return outCols.join("");
        } else {
          const cols = columnKey.length;
          const rows = Math.ceil(text.length / cols);
          const fullLen = rows * cols;
          const padded = (text + "?".repeat(Math.max(0, fullLen - text.length)));
          const order = orderMap(columnKey);
          const colLens: number[] = new Array(cols).fill(rows);
          const shortCols = fullLen - text.length;
          for (let c = cols - shortCols; c < cols; c++) colLens[c] = rows - 1;
          const columns: string[] = [];
          let idx = 0;
          for (let outI = 0; outI < cols; outI++) {
            const ci = order.indexOf(outI);
            columns.push(padded.slice(idx, idx + colLens[ci]));
            idx += colLens[ci];
          }
          const grid: string[][] = Array.from({ length: rows }, () => new Array(cols).fill(""));
          for (let outI = 0; outI < cols; outI++) {
            const ci = order.indexOf(outI);
            for (let r = 0; r < columns[outI].length; r++) grid[r][ci] = columns[outI][r];
          }
          let step1 = "";
          for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++) {
            if (grid[r][c] !== "?") step1 += grid[r][c];
          }
          const reverse: Record<string, string> = {};
          for (let r = 0; r < size; r++) for (let c = 0; c < size; c++) {
            reverse[labels[r] + labels[c]] = polybiusKey[r * size + c];
          }
          let out = "";
          for (let i = 0; i + 1 < step1.length; i += 2) {
            const pair = step1[i] + step1[i + 1];
            out += reverse[pair] || "?";
          }
          return out;
        }
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  registry.register({
    name: "columnar_transposition",
    description: "列移位密码：列换位 (Incomplete Columnar Transposition)，encrypt / decrypt / 猜测 columns=2~12",
    parameters: z.object({
      action: z.enum(["encrypt", "decrypt", "bruteforce"]),
      text: z.string(),
      key: z.string().optional(),
      columns: z.number().int().min(2).max(30).optional().default(5),
      padding: z.string().optional().default("X"),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { action, text, key, columns, padding } = args;
      try {
        const orderMap = (k: string): number[] => {
          const pairs = [...k].map((c: string, i: number) => ({ c, i }));
          pairs.sort((a: any, b: any) => a.c.localeCompare(b.c));
          const order: number[] = new Array(k.length);
          for (let r = 0; r < pairs.length; r++) order[(pairs[r] as any).i] = r;
          return order;
        };
        const cols = key ? key.length : (columns || 5);
        if (action === "encrypt") {
          const pad = padding || "X";
          const padded = text + pad.repeat(Math.max(0, cols - (text.length % cols)) % cols);
          const rows = Math.ceil(padded.length / cols);
          const grid: string[][] = Array.from({ length: rows }, () => new Array(cols).fill(""));
          for (let i = 0; i < padded.length; i++) grid[Math.floor(i / cols)][i % cols] = padded[i];
          const order = key ? orderMap(key) : Array.from({ length: cols }, (_v, i: number) => i);
          let out = "";
          for (let o = 0; o < cols; o++) {
            const ci = order.indexOf(o);
            for (let r = 0; r < rows; r++) out += grid[r][ci];
          }
          return out;
        }
        if (action === "decrypt") {
          const rows = Math.ceil(text.length / cols);
          const fullLen = rows * cols;
          const missing = fullLen - text.length;
          const padded = text + "?".repeat(missing);
          const order = key ? orderMap(key) : Array.from({ length: cols }, (_v, i: number) => i);
          const colLens: number[] = new Array(cols).fill(rows);
          for (let c = cols - missing; c < cols; c++) colLens[c] = rows - 1;
          const columns: string[] = [];
          let idx = 0;
          for (let o = 0; o < cols; o++) {
            const ci = order.indexOf(o);
            columns.push(padded.slice(idx, idx + colLens[ci]));
            idx += colLens[ci];
          }
          let out = "";
          for (let r = 0; r < rows; r++) {
            for (let c = 0; c < cols; c++) {
              const o = order[c];
              const col = columns[o];
              if (r < col.length) out += col[r];
            }
          }
          return out.replace(/\?+$/, "");
        }
        const results: string[] = [];
        for (let C = 2; C <= Math.min(12, Math.floor(text.length / 3)); C++) {
          const rows = Math.ceil(text.length / C);
          const columns_arr: string[] = [];
          let idx = 0;
          for (let c = 0; c < C; c++) {
            const remainingLen = text.length - idx;
            const take = Math.ceil(remainingLen / (C - c));
            columns_arr.push(text.slice(idx, idx + take));
            idx += take;
          }
          let s = "";
          for (let r = 0; r < rows; r++) {
            for (let c = 0; c < C; c++) if (r < columns_arr[c].length) s += columns_arr[c][r];
          }
          results.push(`cols=${C} → ${s.slice(0, 80)}`);
        }
        return results.join("\n");
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  registry.register({
    name: "baconian_cipher",
    description: "培根密码 (Baconian)：标准 24 字母表和 26 字母表，支持 AB 编码 / 01 / 大小写藏字提取 + 编码",
    parameters: z.object({
      action: z.enum(["encode", "decode", "extract_case"]),
      text: z.string(),
      variant: z.enum(["standard24", "full26"]).optional().default("standard24"),
      zeroCh: z.string().optional().default("A"),
      oneCh: z.string().optional().default("B"),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { action, text, variant, zeroCh, oneCh } = args;
      try {
        const letters24 = ["A","B","C","D","E","F","G","H","I/J","K","L","M","N","O","P","Q","R","S","T","U/V","W","X","Y","Z"];
        const letters26 = ALPHA_ARR;
        const letters = variant === "standard24" ? letters24 : letters26;
        const bin2Let: Record<string, string> = {};
        const let2Bin: Record<string, string> = {};
        for (let i = 0; i < letters.length; i++) {
          const b = i.toString(2).padStart(5, "0");
          bin2Let[b] = letters[i];
          for (const l of letters[i].split("/")) let2Bin[l] = b;
        }
        if (action === "encode") {
          return [...text.toUpperCase()].map((c: string) => let2Bin[c] || c)
            .map((b: string) => b.replace(/0/g, zeroCh || "A").replace(/1/g, oneCh || "B")).join(" ");
        }
        if (action === "decode") {
          const clean = text.toUpperCase()
            .split(/[\s,;]+/).join("")
            .split("").filter((c: string) => c === "A" || c === "B" || c === zeroCh || c === oneCh || c === "0" || c === "1").join("");
          const norm = clean.split("").map((c: string) => (c === "B" || c === oneCh || c === "1") ? "1" : "0").join("");
          let out = "";
          for (let i = 0; i + 4 < norm.length; i += 5) {
            out += bin2Let[norm.slice(i, i + 5)] || "?";
          }
          return out;
        }
        const seq = [...text].map((c: string) => {
          if (!/[a-zA-Z]/.test(c)) return "";
          return c === c.toUpperCase() ? "1" : "0";
        }).join("");
        let out = "";
        for (let i = 0; i + 4 < seq.length; i += 5) {
          out += bin2Let[seq.slice(i, i + 5)] || "?";
        }
        return `提取到 0/1 序列=${seq}\n培根解密=${out}`;
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  registry.register({
    name: "playfair_family",
    description: "棋盘密码家族：Playfair 5x5 (J=I) / Bifid 5x5 / Foursquare 5x5x4，CTF 常考",
    parameters: z.object({
      variant: z.enum(["playfair", "bifid", "foursquare"]),
      action: z.enum(["encrypt", "decrypt"]),
      key: z.string(),
      text: z.string(),
      period: z.number().int().min(2).max(50).optional().default(5),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { variant, action, key, text, period } = args;
      try {
        const build5x5 = (k: string, skipLetter = "J"): { table: string[]; pos: Record<string, [number, number]> } => {
          const used = new Set<string>();
          const order: string[] = [];
          for (const c of (k + ALPHA_UPPER).toUpperCase()) {
            if (!/[A-Z]/.test(c)) continue;
            const ch = c === skipLetter ? "I" : c;
            if (!used.has(ch)) { used.add(ch); order.push(ch); }
          }
          const table = order.slice(0, 25);
          const pos: Record<string, [number, number]> = {};
          for (let i = 0; i < 25; i++) pos[table[i]] = [Math.floor(i / 5), i % 5];
          return { table, pos };
        };
        if (variant === "playfair") {
          const { table, pos } = build5x5(key, "J");
          const digraphs: [string, string][] = [];
          const up = text.toUpperCase().replace(/J/g, "I").replace(/[^A-Z]/g, "");
          for (let i = 0; i < up.length;) {
            const a = up[i++];
            let b = up[i++] || "X";
            if (a === b) { b = "X"; i--; }
            digraphs.push([a, b]);
          }
          const handle = (a: string, b: string, enc: boolean): [string, string] => {
            let [r1, c1] = pos[a];
            let [r2, c2] = pos[b];
            if (r1 === r2) {
              c1 = mod(c1 + (enc ? 1 : -1), 5);
              c2 = mod(c2 + (enc ? 1 : -1), 5);
            } else if (c1 === c2) {
              r1 = mod(r1 + (enc ? 1 : -1), 5);
              r2 = mod(r2 + (enc ? 1 : -1), 5);
            } else {
              [c1, c2] = [c2, c1];
            }
            return [table[r1 * 5 + c1], table[r2 * 5 + c2]];
          };
          return digraphs.map(([a, b]) => handle(a, b, action === "encrypt").join("")).join("");
        }
        if (variant === "bifid") {
          const { table, pos } = build5x5(key, "J");
          const up = text.toUpperCase().replace(/J/g, "I").replace(/[^A-Z]/g, "");
          if (action === "encrypt") {
            const rows: number[] = [], cols: number[] = [];
            for (const c of up) { const [r, c1] = pos[c]; rows.push(r); cols.push(c1); }
            const flat: number[] = [];
            const N = up.length;
            const per = period || 5;
            for (let s = 0; s < N; s += per) {
              const end = Math.min(s + per, N);
              const seg = [...rows.slice(s, end), ...cols.slice(s, end)];
              for (let k = 0; k < seg.length; k += 2) flat.push(seg[k] * 5 + seg[k + 1]);
            }
            return flat.map((i: number) => table[i]).join("");
          } else {
            const indices = [...up].map((c: string) => pos[c][0] * 5 + pos[c][1]);
            const rows: number[] = [], cols: number[] = [];
            const per = period || 5;
            for (let s = 0; s < indices.length; s += per) {
              const end = Math.min(s + per, indices.length);
              const seg = indices.slice(s, end);
              const flat: number[] = [];
              for (const i of seg) { flat.push(Math.floor(i / 5), i % 5); }
              const half = flat.length / 2;
              for (let k = 0; k < half; k++) { rows.push(flat[k]); cols.push(flat[k + half]); }
            }
            return rows.map((r: number, i: number) => table[r * 5 + cols[i]]).join("");
          }
        }
        if (variant === "foursquare") {
          const keys = (key || ",").split(",").map((s: string) => s.trim());
          const k1 = keys[0] || "";
          const k2 = keys[1] || "";
          const Q0 = build5x5("", "J");
          const QR = build5x5(k1, "J");
          const QL = build5x5(k2, "J");
          const DR = Q0;
          const pairFn = (a: string, b: string, enc: boolean): [string, string] => {
            if (enc) {
              const [r1, c1] = Q0.pos[a];
              const [r2, c2] = Q0.pos[b];
              return [QR.table[r1 * 5 + c2], QL.table[r2 * 5 + c1]];
            } else {
              const [r1, c1] = QR.pos[a];
              const [r2, c2] = QL.pos[b];
              return [DR.table[r1 * 5 + c1], DR.table[r2 * 5 + c2]];
            }
          };
          const up = text.toUpperCase().replace(/J/g, "I").replace(/[^A-Z]/g, "");
          const pairs: string[] = [];
          for (let i = 0; i + 1 < up.length; i += 2) {
            const [x, y] = pairFn(up[i], up[i + 1], action === "encrypt");
            pairs.push(x, y);
          }
          return pairs.join("");
        }
        return "[playfair_family] 未知 variant";
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  return registry;
}
