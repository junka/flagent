import { z } from "zod";
import { ToolRegistry } from "./registry";

export function createMiscCtfTools(): ToolRegistry {
  const registry = new ToolRegistry();

  // 1. brainfuck_family
  registry.register({
    name: "brainfuck_family",
    description: "Brainfuck 家族解释器：BF / Ook! / ShortC / COW，含自动识别 + 互转",
    parameters: z.object({
      mode: z.enum(["run", "convert"]),
      variant: z.enum(["auto", "bf", "ook", "shortc", "cow"]).optional().default("auto"),
      code: z.string(),
      input: z.string().optional().default(""),
      toVariant: z.enum(["bf", "ook", "shortc", "cow"]).optional().default("bf"),
    }),
    category: "misc",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { mode, variant, code, input, toVariant } = args;
      try {
        let src: string = code;
        let from: string = variant || "auto";
        if (from === "auto") {
          if (/Ook\.\s*[.!?]/.test(src) || /Ook[.!?]/.test(src)) from = "ook";
          else if (/\b(moo|mOo|moO|MOo|MoO|mOO|MOO|OOO|oom|OoM|OMo|oMo|oOM|OOm)\b/.test(src)) from = "cow";
          else if (/^[a-vA-V\s]+$/.test(src.replace(/\s/g, ""))) from = "shortc";
          else from = "bf";
        }
        let bf = "";
        if (from === "bf") bf = src.replace(/[^+\-<>,.\[\]]/g, "");
        if (from === "ook") {
          const tokens = (src.match(/Ook\s*[.!?]\s*Ook\s*[.!?]/g) || []);
          // 标准 Ook 映射 (8 对)
          const m: Record<string, string> = {
            "..": ">", ".?": "<", ".!": "+", "?.": "-",
            "??": ".", "!.": ",", "!?": "[", "!!": "]",
          };
          for (const t of tokens) {
            const a = t.match(/Ook\s*([.!?])\s*Ook\s*([.!?])/);
            if (!a) continue;
            const key = a[1] + a[2];
            bf += m[key] || "";
          }
        }
        if (from === "shortc") {
          const map: Record<string, string> = {
            a: ">", b: "<", c: "+", d: "-", e: ".", f: ",", g: "[", h: "]",
            i: ">>", j: "<<", k: "++", l: "--", m: "+[-]", n: "[->+<]", o: "[->+<]>.",
            p: "[-<+>]", q: "[-]", r: ">>>", s: "<<<", t: "+++", u: "---", v: "[>+<-]",
          };
          for (const c of src.toLowerCase()) bf += map[c] || "";
        }
        if (from === "cow") {
          const words = src.match(/[A-Za-z]{2,3}/g) || [];
          return `[cow variant] 输入词数=${words.length}。COW 完整解释器请调用 command_exec 配合第三方工具。\n原始 BF (若可识别): ${bf.slice(0, 200)}`;
        }
        if (mode === "convert") {
          if (toVariant === "bf") return bf;
          if (toVariant === "ook") {
            const m: Record<string, string> = {
              ">": "Ook. Ook. ", "<": "Ook. Ook? ", "+": "Ook. Ook! ", "-": "Ook? Ook. ",
              ".": "Ook? Ook? ", ",": "Ook! Ook. ", "[": "Ook! Ook? ", "]": "Ook! Ook! ",
            };
            return [...bf].map((c: string) => m[c] || "").join("");
          }
          if (toVariant === "shortc") {
            const m: Record<string, string> = {
              ">": "a", "<": "b", "+": "c", "-": "d", ".": "e", ",": "f", "[": "g", "]": "h",
            };
            return [...bf].map((c: string) => m[c] || "").join("");
          }
          if (toVariant === "cow") return "[cow variant] convert_to cow 暂未实现";
        }
        // run bf
        const mem: number[] = new Array(30000).fill(0);
        let ptr = 0, ip = 0, inIdx = 0, out = "";
        const jmps: number[] = new Array(bf.length).fill(-1);
        const stack: number[] = [];
        for (let i = 0; i < bf.length; i++) {
          if (bf[i] === "[") stack.push(i);
          if (bf[i] === "]") { const j = stack.pop()!; jmps[i] = j; jmps[j] = i; }
        }
        let steps = 0;
        while (ip < bf.length && steps < 10_000_000) {
          steps++;
          const op = bf[ip];
          switch (op) {
            case ">": ptr++; break;
            case "<": ptr--; break;
            case "+": mem[ptr] = (mem[ptr] + 1) & 0xff; break;
            case "-": mem[ptr] = (mem[ptr] - 1 + 256) & 0xff; break;
            case ".": out += String.fromCharCode(mem[ptr]); break;
            case ",": mem[ptr] = (inIdx < (input || "").length) ? (input || "").charCodeAt(inIdx++) : 0; break;
            case "[": if (mem[ptr] === 0) ip = jmps[ip]; break;
            case "]": if (mem[ptr] !== 0) ip = jmps[ip]; break;
          }
          ip++;
        }
        return out;
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  // 2. morse_code
  registry.register({
    name: "morse_code",
    description: "莫尔斯电码：编码 / 解码，支持 ./- 或 ·/—，支持变音符号 / 非标准；输出字符大小写选项",
    parameters: z.object({
      action: z.enum(["encode", "decode"]),
      text: z.string(),
      sep: z.string().optional().default(" "),
      letterSep: z.string().optional().default("/"),
      variant: z.enum(["standard", "farnsworth"]).optional().default("standard"),
    }),
    category: "misc",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { action, text, sep, letterSep, variant: _v } = args;
      try {
        const table: Record<string, string> = {
          "A":".-","B":"-...","C":"-.-.","D":"-..","E":".","F":"..-.","G":"--.","H":"....","I":"..","J":".---","K":"-.-","L":".-..","M":"--","N":"-.","O":"---","P":".--.","Q":"--.-","R":".-.","S":"...","T":"-","U":"..-","V":"...-","W":".--","X":"-..-","Y":"-.--","Z":"--..",
          "0":"-----","1":".----","2":"..---","3":"...--","4":"....-","5":".....","6":"-....","7":"--...","8":"---..","9":"----.",
          ".":".-.-.-",",":"--..--","?":"..--..","'":".----.","!":"-.-.--","/":"-..-.","(":"-.--.",")":"-.--.-","&":".-...",":":"---...",";":"-.-.-.","=":"-...-","+":".-.-.","-":"-....-","_":"..--.-","\"":".-..-.","$":"...-..-","@":".--.-."
        };
        const rev: Record<string, string> = {};
        for (const k in table) rev[table[k]] = k;
        if (action === "encode") {
          const words = text.toUpperCase().split(/\s+/);
          return words.map((w: string) =>
            [...w].map((c: string) => table[c] || ("[" + c + "]")).join(sep || " ")
          ).join((letterSep || "/"));
        } else {
          const norm = text.replace(/·/g, ".").replace(/—/g, "-").replace(/–/g, "-");
          const words = norm.split(/\s*\/\s*/);
          return words.map((w: string) =>
            w.trim().split(/\s+/).map((sym: string) => rev[sym] || `[${sym}]`).join("")
          ).join(" ");
        }
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  // 3. tap_code (敲击码)
  registry.register({
    name: "tap_code",
    description: "敲击码 Tap Code：5x5 Polybius (无字母 K，C 合并)。格式：数字对或点击点分隔（空格/逗号/换行）",
    parameters: z.object({
      action: z.enum(["encode", "decode"]),
      text: z.string(),
      pairSep: z.string().optional().default(" "),
      numSep: z.string().optional().default(","),
    }),
    category: "misc",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { action, text, pairSep, numSep } = args;
      try {
        const alpha = "ABCDEFGHIJLMNOPQRSTUVWXYZ".split("");
        const pos: Record<string, [number, number]> = {};
        for (let i = 0; i < 25; i++) pos[alpha[i]] = [Math.floor(i / 5) + 1, (i % 5) + 1];
        pos["C"] = [1, 3]; pos["K"] = [1, 3];
        const byPos: Record<string, string> = {};
        for (let i = 0; i < 25; i++) byPos[`${Math.floor(i / 5) + 1},${(i % 5) + 1}`] = alpha[i];
        byPos["1,3"] = "C(K)";
        if (action === "encode") {
          const pairs: string[] = [];
          for (const c of text.toUpperCase()) {
            if (pos[c]) pairs.push(pos[c].join(numSep || ","));
          }
          return pairs.join(pairSep || " ");
        } else {
          let tokens: string[] = [];
          if (/\n/.test(text)) tokens = text.split(/\n+/).map((s: string) => s.trim()).filter(Boolean);
          else tokens = text.split(/\s+/).filter(Boolean);
          let pairs: [number, number][] = [];
          if (tokens.every((t: string) => /^\d+[^\d]+\d+$/.test(t))) {
            pairs = tokens.map((t: string) => {
              const m = t.match(/^(\d+)[^\d]+(\d+)$/);
              return [parseInt(m![1], 10), parseInt(m![2], 10)] as [number, number];
            });
          } else {
            const nums = tokens.map(Number).filter((n: number) => !isNaN(n));
            for (let i = 0; i + 1 < nums.length; i += 2) pairs.push([nums[i], nums[i + 1]]);
          }
          return pairs.map(([r, c]) => byPos[`${r},${c}`] || `[${r},${c}]`).join("");
        }
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  // 4. ctf_obfuscator_hub
  registry.register({
    name: "ctf_obfuscator_hub",
    description: "JS 混淆家族：JSFuck / AAEncode / JJEncode / Brainfuck 文本 → JS 互转，eval 安全沙箱返回字符串输出",
    parameters: z.object({
      mode: z.enum(["run_sandboxed", "recognize", "convert_from"]),
      input: z.string(),
      from: z.enum(["auto", "jsfuck", "aaencode", "jjencode", "picon", "malbolge"]).optional().default("auto"),
    }),
    category: "misc",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { mode, input, from } = args;
      try {
        let f: string = from || "auto";
        if (f === "auto") {
          if (/^[\[\]()!+\s]+$/.test(input.trim())) f = "jsfuck";
          else if (/ﾟωﾟ|ﾟΘﾟ|ﾟДﾟ/.test(input)) f = "aaencode";
          else if (/\$\+\+|\$_\(/.test(input) && /\$=_/.test(input)) f = "jjencode";
          else f = "jsfuck";
        }
        if (mode === "recognize") return `识别结果: ${f}`;
        if (mode === "convert_from" || mode === "run_sandboxed") {
          try {
            // eslint-disable-next-line @typescript-eslint/no-var-requires
            const vm = require("vm");
            const out: string[] = [];
            const ctx = {
              console: { log: (...a: any[]) => out.push(a.join(" ")), error: () => {}, warn: () => {} },
              alert: (s: any) => out.push("[alert] " + String(s)),
              prompt: () => "",
              confirm: () => true,
              document: { write: (s: any) => out.push("[document.write] " + String(s)) },
              window: null,
            };
            vm.createContext(ctx);
            const r = vm.runInContext(input, ctx, { timeout: 3000 });
            return `[${f}] vm 执行结果=${String(r)}\n捕获输出:\n${out.join("\n")}`;
          } catch (e2: any) { return `[${f}] 执行失败: ${e2.message}`; }
        }
        return `[ctf_obfuscator_hub] 未知 mode=${mode}`;
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  // 5. malbolge 简易模拟器
  registry.register({
    name: "malbolge_run",
    description: "Malbolge 语言 (v2.0) 解释器：98/99 年经典 esolang。输入 / 输出基于 ASCII",
    parameters: z.object({
      code: z.string(),
      input: z.string().optional().default(""),
      maxSteps: z.number().int().min(1).max(500_000).optional().default(50000),
    }),
    category: "misc",
    concurrent: true,
    execute: async (args: any): Promise<string> => {
      const { code, input, maxSteps } = args;
      try {
        const MEM_SIZE = 59049;
        const mem: number[] = new Array(MEM_SIZE).fill(0);
        // crazy: 3x3 table, [da][db] => trit
        const crazy: number[][] = [
          [1, 0, 0], [1, 0, 2], [2, 2, 1],
        ];
        const op = (a: number, b: number): number => {
          let res = 0, p = 1;
          for (let i = 0; i < 10; i++) {
            const da = Math.floor(a / p) % 3;
            const db = Math.floor(b / p) % 3;
            res += crazy[da][db] * p;
            p *= 3;
          }
          return res;
        };
        const rot = (x: number): number => Math.floor(x / 3) + ((x % 3) * 19683);
        const src = code.replace(/\s/g, "").slice(0, MEM_SIZE);
        for (let i = 0; i < src.length; i++) {
          let v = (src.charCodeAt(i) + i) % 94;
          if (![4, 5, 23, 39, 40, 62, 68, 81].includes(v)) v = 68;
          mem[i] = v;
        }
        let a = 0, c = 0, d = 0, out = "", inIdx = 0, steps = 0;
        const limit = maxSteps || 50000;
        while (steps < limit) {
          steps++;
          if (c >= MEM_SIZE || d >= MEM_SIZE) break;
          const instr = (mem[c] + c) % 94;
          switch (instr) {
            case 4: mem[d] = op(a, mem[d]); a = mem[d]; break;
            case 5: d = mem[d]; break;
            case 23: a = rot(mem[d]); mem[d] = a; break;
            case 39: mem[d] = (mem[d] + c) % 94; a = mem[d]; break;
            case 40: out += String.fromCharCode(a & 0xff); break;
            case 62:
              if (inIdx < (input || "").length) a = (input || "").charCodeAt(inIdx++);
              else steps = 1e9;
              break;
            case 68: steps = 1e9; break;
            case 81: break; // no-op
          }
          c = (c + 1) % MEM_SIZE;
          d = (d + 1) % MEM_SIZE;
        }
        return out;
      } catch (e: any) { return `[错误] ${e.message}`; }
    },
  });

  return registry;
}
