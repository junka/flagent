import { z } from "zod";
import { ToolRegistry } from "./registry";
import * as crypto from "crypto";

function pemToJwk(pem: string, pubOnly: boolean): any {
  try {
    const key = pubOnly ? crypto.createPublicKey(pem) : crypto.createPrivateKey(pem);
    return key.export({ format: "jwk" });
  } catch (e: any) { return { error: String(e) }; }
}

const ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALPHA_ARR = Array.from(ALPHA);

export function createCryptoExtTools(): ToolRegistry {
  const registry = new ToolRegistry();

  registry.register({
    name: "rc4_stream",
    description: "RC4 / RC4-drop[N] 流密码：密钥(hex/str) + 明文(hex/str) → 密文，可 drop 丢弃前 N 字节弱化版本",
    parameters: z.object({
      mode: z.enum(["encrypt", "decrypt"]),
      key: z.string(),
      keyFormat: z.enum(["utf8", "hex", "base64"]).optional().default("utf8"),
      input: z.string(),
      inputFormat: z.enum(["utf8", "hex", "base64"]).optional().default("utf8"),
      outputFormat: z.enum(["hex", "base64", "utf8"]).optional().default("hex"),
      dropN: z.number().int().min(0).max(65535).optional().default(0),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { key, keyFormat, input, inputFormat, outputFormat, dropN } = args;
      try {
        const kBuf: Buffer = keyFormat === "hex" ? Buffer.from(key, "hex")
          : keyFormat === "base64" ? Buffer.from(key, "base64") : Buffer.from(key, "utf-8");
        const ptBuf: Buffer = inputFormat === "hex" ? Buffer.from(input, "hex")
          : inputFormat === "base64" ? Buffer.from(input, "base64") : Buffer.from(input, "utf-8");
        const S = new Uint8Array(256);
        for (let i = 0; i < 256; i++) S[i] = i;
        let j = 0;
        for (let i = 0; i < 256; i++) {
          j = (j + S[i] + kBuf[i % kBuf.length]) & 0xff;
          const tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        }
        let i = 0; j = 0;
        let dropped = 0;
        while (dropped < (dropN || 0)) {
          i = (i + 1) & 0xff;
          j = (j + S[i]) & 0xff;
          const tmp = S[i]; S[i] = S[j]; S[j] = tmp;
          dropped++;
        }
        const out = Buffer.alloc(ptBuf.length);
        for (let k = 0; k < ptBuf.length; k++) {
          i = (i + 1) & 0xff;
          j = (j + S[i]) & 0xff;
          const tmp = S[i]; S[i] = S[j]; S[j] = tmp;
          const stream = S[(S[i] + S[j]) & 0xff];
          out[k] = ptBuf[k] ^ stream;
        }
        if (outputFormat === "utf8") return out.toString("utf-8");
        if (outputFormat === "base64") return out.toString("base64");
        return out.toString("hex").toUpperCase();
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  registry.register({
    name: "block_cipher_ext",
    description: "分组密码扩展：DES / 3DES-EDE (单/双/三密钥) / Blowfish，支持 ECB/CBC/CFB/OFB + IV + PKCS#5/7 填充",
    parameters: z.object({
      cipher: z.enum(["des-ecb", "des-cbc", "des-cfb", "des-ofb",
                      "des-ede", "des-ede3", "des-ede-cbc", "des-ede3-cbc", "blowfish"]),
      mode: z.enum(["encrypt", "decrypt"]),
      key: z.string(),
      keyFormat: z.enum(["utf8", "hex", "base64"]).optional().default("hex"),
      iv: z.string().optional(),
      ivFormat: z.enum(["utf8", "hex", "base64"]).optional().default("hex"),
      input: z.string(),
      inputFormat: z.enum(["utf8", "hex", "base64"]).optional().default("hex"),
      outputFormat: z.enum(["hex", "base64", "utf8"]).optional().default("hex"),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { cipher, mode, key, keyFormat, iv, ivFormat, input, inputFormat, outputFormat } = args;
      try {
        const kBuf: Buffer = keyFormat === "hex" ? Buffer.from(key, "hex")
          : keyFormat === "base64" ? Buffer.from(key, "base64") : Buffer.from(key, "utf-8");
        const iBuf: Buffer = inputFormat === "hex" ? Buffer.from(input, "hex")
          : inputFormat === "base64" ? Buffer.from(input, "base64") : Buffer.from(input, "utf-8");
        const ivBuf: Buffer | undefined = iv
          ? (ivFormat === "hex" ? Buffer.from(iv, "hex")
              : ivFormat === "base64" ? Buffer.from(iv, "base64") : Buffer.from(iv, "utf-8"))
          : undefined;
        let algo: string = cipher;
        if (cipher === "blowfish") algo = "bf-cbc";
        const zeroIv = Buffer.alloc(0);
        if (mode === "encrypt") {
          const c = ivBuf
            ? crypto.createCipheriv(algo, kBuf, ivBuf)
            : crypto.createCipheriv(algo, kBuf, zeroIv);
          const parts = [c.update(iBuf), c.final()];
          const out = Buffer.concat(parts);
          return outputFormat === "utf8" ? out.toString("utf-8")
            : outputFormat === "base64" ? out.toString("base64") : out.toString("hex").toUpperCase();
        } else {
          const c = ivBuf
            ? crypto.createDecipheriv(algo, kBuf, ivBuf)
            : crypto.createDecipheriv(algo, kBuf, zeroIv);
          const parts = [c.update(iBuf), c.final()];
          const out = Buffer.concat(parts);
          return outputFormat === "utf8" ? out.toString("utf-8")
            : outputFormat === "base64" ? out.toString("base64") : out.toString("hex").toUpperCase();
        }
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  registry.register({
    name: "rsa_key_parser",
    description: "RSA PEM/Base64 公钥/私钥解析，导出 n,e,d,p,q (JWK)；给出简单攻击提示 (低 e / 近因子 / 共模)",
    parameters: z.object({
      input: z.string(),
      format: z.enum(["pem", "pkcs1_pem", "der_base64", "n_e"]).optional().default("pem"),
      n: z.string().optional(),
      e: z.string().optional(),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { input, format, n, e } = args;
      try {
        let jwk: any;
        const fromB64u = (s: string): bigint => {
          const h = Buffer.from(s, "base64url").toString("hex");
          return BigInt("0x" + (h || "0"));
        };
        const toHex = (bn: bigint): string => {
          let h = bn.toString(16);
          if (h.length % 2) h = "0" + h;
          return h.toUpperCase();
        };
        if (format === "n_e") {
          if (!n || !e) return "[错误] n_e 格式请同时提供 n,e";
          const parseBig = (s: string): bigint => {
            if (/^[0-9]+$/.test(s)) return BigInt(s);
            return BigInt(s.startsWith("0x") ? s : "0x" + s);
          };
          const bn = parseBig(n);
          const be = parseBig(e);
          jwk = {
            kty: "RSA",
            n: Buffer.from(toHex(bn), "hex").toString("base64url"),
            e: Buffer.from(toHex(be), "hex").toString("base64url"),
          };
        } else {
          jwk = pemToJwk(input, true);
        }
        if (!jwk || jwk.error) return JSON.stringify(jwk);
        const bn = jwk.n ? fromB64u(jwk.n) : 0n;
        const be = jwk.e ? fromB64u(jwk.e) : 0n;
        const bd = jwk.d ? fromB64u(jwk.d) : undefined;
        const bp = jwk.p ? fromB64u(jwk.p) : undefined;
        const bq = jwk.q ? fromB64u(jwk.q) : undefined;
        const bits = bn.toString(2).length;
        const hints: string[] = [`位数 ≈ ${bits} bit`];
        if (be <= 3n) hints.push("低 e 攻击: e≤3 可用 RSA 低加密指数 (Coppersmith / 直接开方)");
        if (be === 65537n) hints.push("e=65537 常规值");
        if (bp && bq) {
          const diff = bp > bq ? bp - bq : bq - bp;
          if (diff < 1n << BigInt(Math.floor(bits / 4))) hints.push("p,q 相近 → Fermat 因式分解可行");
        }
        try { if (bn % 2n === 0n) hints.push("n 是偶数！公钥错误或可直接恢复 p=2"); } catch {}
        return JSON.stringify({
          kty: jwk.kty,
          n_dec: String(bn),
          n_hex: "0x" + toHex(bn),
          e_dec: String(be),
          e_hex: "0x" + toHex(be),
          d_dec: bd ? String(bd) : undefined,
          p_dec: bp ? String(bp) : undefined,
          q_dec: bq ? String(bq) : undefined,
          bits, hints,
        }, null, 2);
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  registry.register({
    name: "freq_ic_analysis",
    description: "文本频率分析：英文字母频率表、IC (Index of Coincidence)、Kasiski 重复子串、按密钥长度分组的 IC 值",
    parameters: z.object({
      input: z.string(),
      modes: z.array(z.enum(["freq", "ic", "kasiski", "grouped_ic"])).optional().default(["freq", "ic"]),
      maxKeyLen: z.number().int().min(2).max(30).optional().default(12),
      minRepLen: z.number().int().min(3).max(10).optional().default(3),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { input, modes, maxKeyLen, minRepLen } = args;
      try {
        const up = input.toUpperCase().replace(/[^A-Z]/g, "");
        const result: any = { length: up.length };
        const runModes: string[] = modes || [];
        if (runModes.includes("freq")) {
          const freq = Array(26).fill(0);
          for (const c of up) freq[c.charCodeAt(0) - 65]++;
          result.freq = ALPHA_ARR.map((ch: string, i: number) => ({
            letter: ch,
            count: freq[i],
            pct: (100 * freq[i] / Math.max(1, up.length)).toFixed(2) + "%",
          }));
        }
        const ic = (s: string): number => {
          const f = Array(26).fill(0);
          for (const c of s) f[c.charCodeAt(0) - 65]++;
          const n = s.length;
          if (n < 2) return 0;
          let sum = 0;
          for (const v of f) sum += v * (v - 1);
          return sum / (n * (n - 1));
        };
        if (runModes.includes("ic")) result.ic = ic(up);
        if (runModes.includes("kasiski")) {
          const reps: Record<string, number[]> = {};
          for (let L = minRepLen || 3; L <= 6; L++) {
            for (let i = 0; i + L <= up.length; i++) {
              const w = up.slice(i, i + L);
              if (!reps[w]) reps[w] = [];
              reps[w].push(i);
            }
          }
          const diffs: number[] = [];
          for (const w in reps) {
            const pos = reps[w];
            if (pos.length >= 2) {
              for (let i = 1; i < pos.length; i++) diffs.push(pos[i] - pos[i - 1]);
            }
          }
          const gcdAll = (arr: number[]): number => arr.reduce((a, b) => {
            while (b) { const t = a % b; a = b; b = t; } return a;
          }, 0);
          const g = diffs.length ? gcdAll(diffs) : 0;
          result.kasiski = { topFactors: {} as Record<number, number>, gcd: g, diffs: diffs.slice(0, 20) };
          for (const d of diffs.slice(0, 200)) {
            for (let k = 2; k <= Math.min(maxKeyLen || 12, 30); k++) if (d % k === 0) {
              result.kasiski.topFactors[k] = (result.kasiski.topFactors[k] || 0) + 1;
            }
          }
        }
        if (runModes.includes("grouped_ic")) {
          const gic: Record<number, number> = {};
          for (let L = 2; L <= (maxKeyLen || 12); L++) {
            const groups: string[] = new Array(L).fill("");
            for (let i = 0; i < up.length; i++) groups[i % L] += up[i];
            const avg = groups.reduce((s: number, g: string) => s + ic(g), 0) / L;
            gic[L] = +avg.toFixed(4);
          }
          result.grouped_ic = gic;
        }
        return JSON.stringify(result, null, 2);
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  registry.register({
    name: "pkcs7_padding",
    description: "PKCS#5/PKCS#7 padding 追加/去除/检查：用于分组密码 CTF",
    parameters: z.object({
      action: z.enum(["pad", "unpad", "validate"]),
      input: z.string(),
      blockSize: z.number().int().min(1).max(256).optional().default(16),
      format: z.enum(["utf8", "hex", "base64"]).optional().default("hex"),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { action, input, blockSize, format } = args;
      try {
        const buf: Buffer = format === "hex" ? Buffer.from(input, "hex")
          : format === "base64" ? Buffer.from(input, "base64") : Buffer.from(input, "utf-8");
        if (action === "pad") {
          const bs = blockSize || 16;
          const need = bs - (buf.length % bs);
          return Buffer.concat([buf, Buffer.alloc(need, need)]).toString("hex").toUpperCase();
        }
        if (action === "unpad") {
          const last = buf[buf.length - 1];
          if (last < 1 || last > (blockSize || 16)) return "[错误] 无效填充字节";
          const start = buf.length - last;
          for (let i = start; i < buf.length; i++) if (buf[i] !== last) return "[错误] 填充不一致";
          const res = buf.slice(0, start);
          return format === "utf8" ? res.toString("utf-8") : res.toString("hex").toUpperCase();
        }
        const last = buf[buf.length - 1];
        if (last < 1 || last > (blockSize || 16)) return JSON.stringify({ valid: false, reason: `填充字节=${last} 超范围` });
        const start = buf.length - last;
        for (let i = start; i < buf.length; i++) if (buf[i] !== last) return JSON.stringify({ valid: false, reason: "填充区域不一致" });
        return JSON.stringify({ valid: true, padLen: last });
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  return registry;
}
