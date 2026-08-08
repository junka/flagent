import { z } from "zod";
import * as crypto from "crypto";
import { ToolRegistry } from "./registry";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function encodeBase32(input: Buffer): string {
  let output = "";
  const len = input.length;
  let i = 0;
  while (i < len) {
    let remaining = len - i;
    let buffer = 0;
    let bitsLeft = 0;
    const charsNeeded = Math.ceil((remaining * 8) / 5);
    let j = 0;
    while (j < charsNeeded) {
      if (bitsLeft < 5) {
        if (i < len) {
          buffer <<= 8;
          buffer |= input[i++];
          bitsLeft += 8;
        } else {
          buffer <<= (5 - bitsLeft);
          bitsLeft = 5;
        }
      }
      const shift = bitsLeft - 5;
      output += BASE32_ALPHABET[(buffer >> shift) & 0x1f];
      bitsLeft -= 5;
      j++;
    }
    const totalBits = len * 8;
    const outputBits = charsNeeded * 5;
    const padChars = (8 - (charsNeeded % 8)) % 8;
    if (padChars > 0 && totalBits % 40 !== 0) {
      output += "=".repeat(padChars);
    }
    return output;
  }
  return output;
}

function decodeBase32(input: string): Buffer {
  const cleanInput = input.replace(/=+$/, "").toUpperCase();
  const output: number[] = [];
  let buffer = 0;
  let bitsLeft = 0;
  for (const c of cleanInput) {
    const val = BASE32_ALPHABET.indexOf(c);
    if (val === -1) throw new Error("Invalid base32 character: " + c);
    buffer = (buffer << 5) | val;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      bitsLeft -= 8;
      output.push((buffer >> bitsLeft) & 0xff);
    }
  }
  return Buffer.from(output);
}

export function createCryptoTools(): ToolRegistry {
  const registry = new ToolRegistry();

  registry.register({
    name: "encode_decode",
    description: "编码/解码：base64/hex/url/rot13/base32",
    parameters: z.object({
      action: z.enum(["encode", "decode"]),
      encoding: z.enum(["base64", "hex", "url", "rot13", "base32"]),
      text: z.string(),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any) => {
      const { action, encoding, text } = args;
      try {
        let result: string;
        switch (encoding) {
          case "base64":
            result = action === "encode"
              ? Buffer.from(text).toString("base64")
              : Buffer.from(text, "base64").toString("utf-8");
            break;
          case "hex":
            result = action === "encode"
              ? Buffer.from(text).toString("hex")
              : Buffer.from(text, "hex").toString("utf-8");
            break;
          case "url":
            result = action === "encode" ? encodeURIComponent(text) : decodeURIComponent(text);
            break;
          case "rot13":
            result = text.replace(/[a-zA-Z]/g, (c: string) => {
              const code = c.charCodeAt(0);
              const base = code >= 65 && code <= 90 ? 65 : 97;
              return String.fromCharCode(((code - base + 13) % 26) + base);
            });
            break;
          case "base32":
            result = action === "encode"
              ? encodeBase32(Buffer.from(text))
              : decodeBase32(text).toString("utf-8");
            break;
          default:
            result = text;
        }
        return `[${action}_${encoding}] 输入: ${text}\n输出: ${result}`;
      } catch (err: any) {
        return `[错误] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "hash_compute",
    description: "哈希计算：MD5/SHA1/SHA256/SHA512/SHA3",
    parameters: z.object({
      text: z.string(),
      algorithm: z.enum(["md5", "sha1", "sha256", "sha512", "sha3"]),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any) => {
      const { text, algorithm } = args;
      const alg = algorithm === "sha3" ? "sha3-256" : algorithm;
      const hash = crypto.createHash(alg).update(text).digest("hex");
      return `[${algorithm.toUpperCase()}] 输入: ${text}\n${hash}`;
    },
  });

  registry.register({
    name: "hash_crack",
    description: "哈希破解：彩虹表 + 常用密码字典爆破",
    parameters: z.object({
      hash: z.string().describe("哈希值"),
      algorithm: z.enum(["md5", "sha1", "sha256"]),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any) => {
      const { hash, algorithm } = args;
      const commonPasswords = [
        "password", "123456", "1234567", "test", "guest", "admin", "root",
        "hello", "charlie", "donald", "shadow", "letmein", "master",
        "monkey", "dragon", "baseball", "football", "superman", "batman",
        "trustno1", "sunshine", "princess", "qwerty", "solo", "pass",
        "1234", "12345", "12345678", "123456789", "iloveyou", "loveme",
        "whatever", "friend", "noah", "password1", "abc123", "111111",
        "000000", "123123", "696969", "mustang", "michael", "jennifer",
      ];

      for (const pwd of commonPasswords) {
        const computed = crypto.createHash(algorithm).update(pwd).digest("hex");
        if (computed === hash.toLowerCase()) {
          return `[哈希破解] ${algorithm.toUpperCase()}: ${hash}\n找到: ${pwd}`;
        }
      }

      return `[哈希破解] ${algorithm.toUpperCase()}: ${hash}\n未在常见字典中找到。建议使用在线彩虹表: https://crackstation.net/`;
    },
  });

  registry.register({
    name: "rsa_tool",
    description: "RSA 加解密/签名：支持公钥加密、私钥解密、私钥签名、公钥验签",
    parameters: z.object({
      action: z.enum(["encrypt", "decrypt", "sign", "verify", "generate_keys"]),
      key: z.string().optional().describe("密钥（PEM格式），generate_keys时不需要"),
      text: z.string().optional().describe("要加密/解密/签名的文本"),
      bits: z.number().optional().describe("密钥位数(generate_keys时)，默认 2048"),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any) => {
      const { action, key, text, bits = 2048 } = args;

      if (action === "generate_keys") {
        const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
          modulusLength: bits,
          publicKeyEncoding: { type: "spki", format: "pem" },
          privateKeyEncoding: { type: "pkcs8", format: "pem" },
        });
        return `[RSA密钥生成] ${bits} 位\n\n公钥:\n${publicKey}\n\n私钥:\n${privateKey}`;
      }

      if (!key) return "[错误] 需要提供密钥";

      try {
        if (action === "encrypt") {
          const encrypted = crypto.publicEncrypt(key, Buffer.from(text!));
          return `[RSA加密] 密文:\n${encrypted.toString("base64")}`;
        } else if (action === "decrypt") {
          const decrypted = crypto.privateDecrypt(key, Buffer.from(text!, "base64"));
          return `[RSA解密] 明文:\n${decrypted.toString("utf-8")}`;
        } else if (action === "sign") {
          const sign = crypto.createSign("SHA256");
          sign.update(text!);
          const signature = sign.sign(key, "base64");
          return `[RSA签名] 签名:\n${signature}`;
        } else if (action === "verify") {
          return "[RSA验签] 请提供公钥、原文和签名";
        }
      } catch (err: any) {
        return `[RSA错误] ${err.message}`;
      }
      return "[RSA] 未知操作";
    },
  });

  registry.register({
    name: "classical_cipher",
    description: "古典密码加密/解密：凯撒/维吉尼亚/XOR/栅栏railfence",
    parameters: z.object({
      cipher: z.enum(["caesar", "vigenere", "xor", "railfence"]),
      action: z.enum(["encrypt", "decrypt"]),
      text: z.string(),
      key: z.union([z.string(), z.number()]).describe("密钥（caesar:数字位移; vigenere:字母密钥; xor:任意密钥; railfence:栅栏数）"),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any) => {
      const { cipher, action, text } = args;
      const key = String(args.key);
      const shift = action === "encrypt" ? 1 : -1;

      try {
        if (cipher === "caesar") {
          const s = parseInt(key) * shift;
          const result = text.replace(/[a-zA-Z]/g, (c: string) => {
            const code = c.charCodeAt(0);
            const base = code >= 65 && code <= 90 ? 65 : 97;
            return String.fromCharCode(((code - base + s) % 26 + 26) % 26 + base);
          });
          return `[Caesar ${action}] key=${key}\n结果: ${result}`;
        }

        if (cipher === "vigenere") {
          let result = "";
          let ki = 0;
          for (const c of text) {
            if (/[a-zA-Z]/.test(c)) {
              const code = c.charCodeAt(0);
              const base = code >= 65 && code <= 90 ? 65 : 97;
              const keyBase = key[ki % key.length].charCodeAt(0) - (/[A-Z]/.test(key[ki % key.length]) ? 65 : 97);
              result += String.fromCharCode(((code - base + keyBase * shift) % 26 + 26) % 26 + base);
              ki++;
            } else {
              result += c;
            }
          }
          return `[Vigenere ${action}] key=${key}\n结果: ${result}`;
        }

        if (cipher === "xor") {
          let result = "";
          for (let i = 0; i < text.length; i++) {
            result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
          }
          return `[XOR ${action}] key=${key}\n结果: ${result}\nHex: ${Buffer.from(result).toString("hex")}`;
        }

        if (cipher === "railfence") {
          const rails = parseInt(key);
          if (action === "encrypt") {
            const rows: string[][] = Array.from({ length: rails }, () => []);
            let dir = 1, row = 0;
            for (const c of text) {
              rows[row].push(c);
              row += dir;
              if (row === 0 || row === rails - 1) dir = -dir;
            }
            return `[Railfence ${action}] rails=${key}\n结果: ${rows.map((r) => r.join("")).join("")}`;
          } else {
            const n = text.length;
            const cycle = 2 * rails - 2;
            const positions: number[] = [];
            for (let r = 0; r < rails; r++) {
              const step1 = cycle - 2 * r;
              const step2 = 2 * r;
              if (step1 === 0) {
                let pos = r;
                while (pos < n) {
                  positions.push(pos);
                  pos += step2;
                }
              } else if (step2 === 0) {
                let pos = r;
                while (pos < n) {
                  positions.push(pos);
                  pos += step1;
                }
              } else {
                let pos = r;
                while (pos < n) {
                  positions.push(pos);
                  pos += step1;
                  if (pos < n) {
                    positions.push(pos);
                    pos += step2;
                  }
                }
              }
            }
            const resultArr: string[] = new Array(n);
            for (let i = 0; i < n; i++) {
              resultArr[positions[i]] = text[i];
            }
            return `[Railfence ${action}] rails=${key}\n结果: ${resultArr.join("")}`;
          }
        }
      } catch (err: any) {
        return `[错误] ${err.message}`;
      }
      return "[密码] 未知操作";
    },
  });

  registry.register({
    name: "aes_encrypt",
    description: "AES 对称加密/解密（CBC/GCM模式）",
    parameters: z.object({
      action: z.enum(["encrypt", "decrypt"]),
      mode: z.enum(["cbc", "gcm"]).optional().describe("加密模式，默认 cbc"),
      text: z.string(),
      key: z.string().describe("密钥（16/24/32字节，或hex）"),
      iv: z.string().optional().describe("IV (hex)，encrypt时自动生成"),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any) => {
      const { action, mode = "cbc", text, key: keyStr, iv: ivStr } = args;

      try {
        const keyBytes = keyStr.length <= 32
          ? Buffer.alloc(32, keyStr)
          : Buffer.from(keyStr, "hex");

        if (action === "encrypt") {
          const iv = crypto.randomBytes(16);
          if (mode === "cbc") {
            const cipher = crypto.createCipheriv("aes-256-cbc", keyBytes, iv);
            cipher.setAutoPadding(true);
            let encrypted = cipher.update(text, "utf-8", "hex");
            encrypted += cipher.final("hex");
            return `[AES-256-CBC加密]\nIV: ${iv.toString("hex")}\n密文: ${encrypted}\n完整: ${iv.toString("hex")}:${encrypted}`;
          } else {
            const cipher = crypto.createCipheriv("aes-256-gcm", keyBytes, iv);
            let encrypted = cipher.update(text, "utf-8", "hex");
            encrypted += cipher.final("hex");
            const tag = cipher.getAuthTag();
            return `[AES-256-GCM加密]\nIV: ${iv.toString("hex")}\n密文: ${encrypted}\nTag: ${tag.toString("hex")}`;
          }
        } else {
          if (!ivStr) return "[错误] 解密需要 IV";
          const iv = Buffer.from(ivStr, "hex");
          if (mode === "cbc") {
            const [ivPart, encPart] = text.split(":");
            const realIv = ivPart ? Buffer.from(ivPart, "hex") : iv;
            const enc = Buffer.from(encPart || text, "hex");
            const decipher = crypto.createDecipheriv("aes-256-cbc", keyBytes, realIv);
            decipher.setAutoPadding(true);
            let decrypted = decipher.update(enc);
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            return `[AES解密] 明文: ${decrypted.toString("utf-8")}`;
          } else {
            const decipher = crypto.createDecipheriv("aes-256-gcm", keyBytes, iv);
            let decrypted = decipher.update(Buffer.from(text, "hex"));
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            return `[AES解密] 明文: ${decrypted.toString("utf-8")}`;
          }
        }
      } catch (err: any) {
        return `[AES错误] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "des_encrypt",
    description: "DES 加密/解密（ECB/CBC模式）",
    parameters: z.object({
      action: z.enum(["encrypt", "decrypt"]),
      mode: z.enum(["ecb", "cbc"]).optional(),
      text: z.string(),
      key: z.string().describe("8字节密钥"),
      iv: z.string().optional().describe("8字节IV (CBC模式)"),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any) => {
      const { action, mode = "ecb", text, key, iv } = args;
      try {
        if (mode === "ecb") {
          const cipher = crypto.createCipheriv("des-ecb", key, "");
          cipher.setAutoPadding(true);
          if (action === "encrypt") {
            let enc = cipher.update(text, "utf-8", "hex");
            enc += cipher.final("hex");
            return `[DES-ECB加密] 密文: ${enc}`;
          } else {
            const deciph = crypto.createDecipheriv("des-ecb", key, "");
            deciph.setAutoPadding(true);
            let dec = deciph.update(Buffer.from(text, "hex"));
            dec = Buffer.concat([dec, deciph.final()]);
            return `[DES-ECB解密] 明文: ${dec.toString("utf-8")}`;
          }
        } else {
          if (!iv) return "[错误] CBC 模式需要 IV";
          const cipher = crypto.createCipheriv("des-cbc", key, iv);
          cipher.setAutoPadding(true);
          if (action === "encrypt") {
            let enc = cipher.update(text, "utf-8", "hex");
            enc += cipher.final("hex");
            return `[DES-CBC加密] 密文: ${enc}`;
          } else {
            const deciph = crypto.createDecipheriv("des-cbc", key, iv);
            deciph.setAutoPadding(true);
            let dec = deciph.update(Buffer.from(text, "hex"));
            dec = Buffer.concat([dec, deciph.final()]);
            return `[DES-CBC解密] 明文: ${dec.toString("utf-8")}`;
          }
        }
      } catch (err: any) {
        return `[DES错误] ${err.message}`;
      }
    },
  });

  registry.register({
    name: "modular_arithmetic",
    description: "模运算工具箱：扩展欧几里得、模逆元、中国剩余定理(CRT)",
    parameters: z.object({
      operation: z.enum(["gcd", "mod_inverse", "crt"]).describe("运算类型"),
      a: z.number().optional().describe("参数 a"),
      b: z.number().optional().describe("参数 b (gcd/mod_inverse 时使用)"),
      modulus: z.number().optional().describe("模数 (mod_inverse 时使用)"),
      residues: z.array(z.number()).optional().describe("CRT: 余数数组"),
      moduli: z.array(z.number()).optional().describe("CRT: 模数数组"),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any) => {
      const { operation, a, b, modulus, residues, moduli } = args;

      function extendedGCD(a: number, b: number): [number, number, number] {
        if (a === 0) return [b, 0, 1];
        let old_r = a, r = b;
        let old_s = 1, s = 0;
        let old_t = 0, t = 1;
        while (r !== 0) {
          const q = Math.floor(old_r / r);
          [old_r, r] = [r, old_r - q * r];
          [old_s, s] = [s, old_s - q * s];
          [old_t, t] = [t, old_t - q * t];
        }
        return [old_r, old_s, old_t];
      }

      function modInverse(a: number, m: number): number | null {
        const [g, x] = extendedGCD(((a % m) + m) % m, m);
        if (g !== 1) return null;
        return ((x % m) + m) % m;
      }

      if (operation === "gcd") {
        const aVal = a ?? 0;
        const bVal = b ?? 0;
        const [g, x, y] = extendedGCD(Math.abs(aVal), Math.abs(bVal));
        return `[扩展欧几里得] a=${aVal}, b=${bVal}\nGCD = ${g}\nx = ${x}, y = ${y}\n验证: ${aVal}*(${x}) + ${bVal}*(${y}) = ${aVal * x + bVal * y}`;
      }

      if (operation === "mod_inverse") {
        const aVal = a ?? 0;
        const m = modulus ?? b ?? 0;
        const inv = modInverse(aVal, m);
        if (inv === null) return `[模逆元] ${aVal} 在模 ${m} 下不可逆 (GCD(${aVal}, ${m}) ≠ 1)`;
        return `[模逆元] ${aVal}^(-1) mod ${m} = ${inv}\n验证: ${aVal} * ${inv} mod ${m} = ${(aVal * inv) % m}`;
      }

      if (operation === "crt") {
        if (!residues || !moduli || residues.length !== moduli.length) {
          return "[CRT错误] 余数数组和模数数组必须长度相等";
        }
        let M = 1;
        for (const m of moduli) M *= m;
        let x = 0;
        for (let i = 0; i < residues.length; i++) {
          const Mi = M / moduli[i];
          const yi = modInverse(Mi, moduli[i]);
          if (yi === null) return `[CRT错误] 模数 ${moduli[i]} 不可逆`;
          x = (x + residues[i] * Mi * yi) % M;
        }
        return `[中国剩余定理 CRT]\n余数: [${residues.join(", ")}]\n模数: [${moduli.join(", ")}]\n解: x = ${x} (mod ${M})\n验证: ${residues.map((r: number, i: number) => `x mod ${moduli[i]} = ${x % moduli[i]} ≡ ${r}`).join("\n")}`;
      }

      return "[错误] 未知操作";
    },
  });

  registry.register({
    name: "lll_reduction",
    description: "LLL 格规约算法（简化版）：用于密码分析中的格攻击辅助",
    parameters: z.object({
      basis: z.array(z.array(z.number())).describe("格基向量 (二维数组)"),
      delta: z.number().optional().describe("Lovász 条件参数 (0.5-1.0), 默认 0.75"),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any) => {
      const { basis, delta = 0.75 } = args;

      const n = basis.length;
      if (n === 0) return "[LLL] 空基";

      const B: number[][] = basis.map((v: number[]) => [...v]);

      function dot(u: number[], v: number[]): number {
        return u.reduce((s, x, i) => s + x * v[i], 0);
      }
      function norm(v: number[]): number {
        return Math.sqrt(dot(v, v));
      }
      function sub(u: number[], v: number[]): number[] {
        return u.map((x, i) => x - v[i]);
      }
      function scale(s: number, v: number[]): number[] {
        return v.map((x) => x * s);
      }

      let iterations = 0;
      const maxIter = 1000;

      while (iterations < maxIter) {
        iterations++;
        let swapped = false;

        for (let k = 1; k < n; k++) {
          const bk = B[k];
          const bkPrev = B[k - 1];
          const nk = norm(bk);
          const nkPrev = norm(bkPrev);

          if (nk < delta * delta * nkPrev) {
            [B[k], B[k - 1]] = [B[k - 1], B[k]];
            swapped = true;
            break;
          }

          const mu = dot(bk, bkPrev) / dot(bkPrev, bkPrev);
          if (Math.abs(mu) > 0.5) {
            B[k] = sub(bk, scale(Math.round(mu), bkPrev));
            swapped = true;
            break;
          }
        }

        if (!swapped) break;
      }

      const result = B.map((v: number[], i: number) => {
        const simplified = v.map((x: number) => {
          if (Math.abs(x) < 1e-10) return 0;
          return Math.round(x * 1000) / 1000;
        });
        return `  b${i} = [${simplified.join(", ")}] (范数≈${norm(v).toFixed(4)})`;
      });

      return `[LLL 规约] 迭代次数: ${iterations}\n参数 δ: ${delta}\n\n规约结果:\n${result.join("\n")}\n\n应用场景:\n- RSA 小私钥攻击 (Boneh-Durfee)\n- Coppersmith 方法辅助\n- NTRU/Lattice 密码分析`;
    },
  });

  registry.register({
    name: "mt19937_predict",
    description: "MT19937 (mersenne twister) 预测器：根据连续输出预测后续随机数",
    parameters: z.object({
      outputs: z.array(z.number()).describe("连续的 MT19937 输出值 (至少624个完整输出或部分输出)"),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any) => {
      const { outputs } = args;

      function untemper(y: number): number {
        let x = y;
        x = x ^ (x >>> 18);
        x = x ^ ((x << 15) & 0xefc60000);
        x = x ^ ((x << 7) & 0x9d2c5680);
        x = x ^ ((x << 11) & 0xbed60000);
        x = x ^ (x >>> 22);
        return x >>> 0;
      }

      function temper(x: number): number {
        let y = x;
        y = y ^ (y >>> 11);
        y = y ^ ((y << 7) & 0x9d2c5680);
        y = y ^ ((y << 15) & 0xefc60000);
        y = y ^ (y >>> 18);
        return y >>> 0;
      }

      if (outputs.length < 624) {
        return `[MT19937预测] 需要至少 624 个连续输出才能完全重建状态\n当前: ${outputs.length} 个\n\n如果只有部分输出:\n- 可利用已知输出缩小搜索空间\n- 考虑使用时间种子攻击 (如果知道生成时间)`;
      }

      const state = outputs.slice(0, 624).map(untemper);

      function generateTwister(state: number[]): number[] {
        const newState = [...state];
        for (let i = 0; i < 624; i++) {
          const y = (newState[i] & 0x80000000) + (newState[(i + 1) % 624] & 0x7fffffff);
          newState[i] = newState[(i + 397) % 624] ^ (y >>> 1) ^ (y & 1 ? 0x9908b0df : 0);
        }
        return newState;
      }

      const newState = generateTwister(state);
      const predicted = newState.slice(0, 20).map(temper);

      const firstDiff = newState.map((v, i) => v !== state[i]).filter(Boolean).length;

      return `[MT19937状态重建成功]\n\n原始状态: 624 个元素已恢复\n新状态差异: ${firstDiff} 个元素 (应为 624)\n\n预测接下来 20 个随机数:\n${predicted.map((v, i) => `  [${i}] ${v}`).join("\n")}\n\n提示:\n- 如果只能看到输出的部分位，可使用位运算逐位恢复\n- 常见应用: PHP mt_rand(), Python random.random() 预测\n- 624个32位输出 = 19968 位状态完全确定`;
    },
  });

  registry.register({
    name: "rsa_advanced",
    description: "RSA 高级攻击：共模攻击、Wiener攻击、低加密指数广播攻击",
    parameters: z.object({
      attackType: z.enum(["common_modulus", "wiener", "hastad", "fermat"]).describe("攻击类型"),
      c1: z.string().optional().describe("密文1 (hex)"),
      c2: z.string().optional().describe("密文2 (hex, 用于共模)"),
      n: z.string().optional().describe("模数 n (hex)"),
      n1: z.string().optional().describe("模数 n1 (hastad)"),
      n2: z.string().optional().describe("模数 n2 (hastad)"),
      n3: z.string().optional().describe("模数 n3 (hastad)"),
      e: z.string().optional().describe("公钥指数 e (hex)"),
      e1: z.string().optional().describe("指数 e1 (hastad)"),
      e2: z.string().optional().describe("指数 e2 (hastad)"),
      e3: z.string().optional().describe("指数 e3 (hastad)"),
      p: z.string().optional().describe("素数 p (费马分解)"),
      q: z.string().optional().describe("素数 q (费马分解)"),
    }),
    category: "crypto",
    concurrent: true,
    execute: async (args: any) => {
      const { attackType } = args;

      function egcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
        if (a === 0n) return [b, 0n, 1n];
        let old_r = a, r = b;
        let old_s = 1n, s = 0n;
        let old_t = 0n, t = 1n;
        while (r !== 0n) {
          const q = old_r / r;
          [old_r, r] = [r, old_r - q * r];
          [old_s, s] = [s, old_s - q * s];
          [old_t, t] = [t, old_t - q * t];
        }
        return [old_r, old_s, old_t];
      }
      function modinv(a: bigint, m: bigint): bigint {
        const [g, x] = egcd(a % m, m);
        if (g !== 1n) throw new Error("不可逆");
        return ((x % m) + m) % m;
      }

      if (attackType === "common_modulus") {
        const c1 = BigInt("0x" + (args.c1 || "0"));
        const c2 = BigInt("0x" + (args.c2 || "0"));
        const n = BigInt("0x" + (args.n || "0"));
        const e = BigInt("0x" + (args.e || "65537"));
        const p = gcd(c1, c2);
        if (p === 1n) return "[共模攻击] GCD(c1, c2) = 1, 无法直接分解 n (可能使用了不同的随机填充)";
        const q = n / p;
        const phi = (p - 1n) * (q - 1n);
        const d = modinv(e, phi);
        const m = modPow(c1, d, n);
        return `[共模攻击成功!]\np = ${p}\nq = ${q}\n私钥 d = ${d}\n明文 m = ${m}`;
      }

      if (attackType === "wiener") {
        const n = BigInt("0x" + (args.n || "0"));
        const e = BigInt("0x" + (args.e || "0"));
        const result = wienerAttack(e, n);
        return result
          ? `[Wiener攻击成功!]\nd = ${result}\n条件: d < n^0.25 / 3`
          : "[Wiener攻击失败] 尝试其他方法 (Boneh-Durfee, Coppersmith)";
      }

      if (attackType === "hastad") {
        const c1 = BigInt("0x" + (args.c1 || "0"));
        const c2 = BigInt("0x" + (args.c2 || "0"));
        const c3 = BigInt("0x" + (args.c3 || "0"));
        const n1 = BigInt("0x" + (args.n1 || "0"));
        const n2 = BigInt("0x" + (args.n2 || "0"));
        const n3 = BigInt("0x" + (args.n3 || "0"));
        const result = hastadAttack(c1, c2, c3, n1, n2, n3);
        return result
          ? `[Håstad广播攻击成功!]\n明文 = ${result}`
          : "[Håstad攻击失败] 检查参数或模数是否互质";
      }

      if (attackType === "fermat") {
        const n = BigInt("0x" + (args.n || "0"));
        const result = fermatFactor(n);
        if (result) {
          const [p, q] = result;
          return `[费马分解成功!]\np = ${p}\nq = ${q}\n验证: p*q = ${p * q} = ${n}`;
        }
        return "[费马分解失败] p 和 q 差距太大，尝试其他方法";
      }

      return "[错误] 未知攻击类型";

      function gcd(a: bigint, b: bigint): bigint {
        while (b) [a, b] = [b, a % b];
        return a;
      }
      function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
        let result = 1n;
        base = base % mod;
        while (exp > 0n) {
          if (exp & 1n) result = (result * base) % mod;
          exp >>= 1n;
          base = (base * base) % mod;
        }
        return result;
      }
      function wienerAttack(e: bigint, n: bigint): bigint | null {
        const continued: bigint[] = [];
        let r0 = e, r1 = n;
        while (r1 !== 0n) {
          const q = r0 / r1;
          continued.push(q);
          [r0, r1] = [r1, r0 - q * r1];
        }
        for (let k = 1; k < continued.length; k++) {
          if (k % 2 === 0) continue;
          let num = 1n, den = 0n;
          for (let i = k; i >= 0; i--) {
            [num, den] = [den + continued[i] * num, num];
          }
          const d = den;
          if (d <= 0n) continue;
          const kBig = BigInt(k);
          const phi = (e * d - 1n) / kBig;
          if (e * d % kBig !== 0n) continue;
          const a = n - phi + 1n;
          if (a % 2n !== 0n) continue;
          const b = a / 2n;
          const disc = b * b - 4n * n;
          if (disc < 0n) continue;
          const sq = sqrtBig(disc);
          if (sq === null) continue;
          if ((b + sq) % 2n !== 0n) continue;
          return d;
        }
        return null;
      }
      function sqrtBig(n: bigint): bigint | null {
        if (n < 0n) return null;
        if (n < 2n) return n;
        let x = n;
        let y = (x + 1n) / 2n;
        let iterations = 0;
        while (y < x && iterations < 200) { x = y; y = (x + n / x) / 2n; iterations++; }
        return x * x === n ? x : null;
      }
      function isqrtBig(n: bigint): bigint {
        if (n < 0n) return 0n;
        if (n < 2n) return n;
        let x = n;
        let y = (x + 1n) / 2n;
        let iterations = 0;
        while (y < x && iterations < 200) { x = y; y = (x + n / x) / 2n; iterations++; }
        return x;
      }
      function hastadAttack(c1: bigint, c2: bigint, c3: bigint, n1: bigint, n2: bigint, n3: bigint): bigint | null {
        const N = n1 * n2 * n3;
        const m1 = N / n1, m2 = N / n2, m3 = N / n3;
        const y1 = modinv(m1, n1), y2 = modinv(m2, n2), y3 = modinv(m3, n3);
        const C = (c1 * m1 * y1 + c2 * m2 * y2 + c3 * m3 * y3) % N;
        const e = 3n;
        let m = approxRoot(C, e);
        if (m === null) return null;
        return m;
      }
      function approxRoot(n: bigint, e: bigint): bigint | null {
        let x = 1n;
        for (let i = 0; i < 100; i++) {
          x = (x + n / (x ** (e - 1n))) / e;
          if (x ** e <= n && (x + 1n) ** e > n) break;
        }
        return x ** e === n ? x : null;
      }
      function fermatFactor(n: bigint): [bigint, bigint] | null {
        let a = isqrtBig(n);
        if (a * a < n) a = a + 1n;
        for (let i = 0; i < 100000; i++) {
          const b2 = a * a - n;
          if (b2 < 0n) { a += 1n; continue; }
          const b = sqrtBig(b2);
          if (b !== null) {
            const p = a - b, q = a + b;
            if (p * q === n) return [p, q];
          }
          a += 1n;
        }
        return null;
      }
    },
  });

  return registry;
}