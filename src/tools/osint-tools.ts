import { z } from "zod";
import * as fs from "fs";
import * as child_process from "child_process";
import { ToolRegistry } from "./registry";

export function createOsintTools(): ToolRegistry {
  const registry = new ToolRegistry();

  // ============================================================
  // 1. web_search_real - 真实互联网搜索（DuckDuckGo HTML 接口）
  // ============================================================
  registry.register({
    name: "web_search_real",
    description: "真实互联网搜索（使用 DuckDuckgo/Google/Bing，无需 API Key）",
    parameters: z.object({
      query: z.string().describe("搜索关键词"),
      max_results: z.number().min(3).max(20).optional().describe("最大返回结果数（3-20），默认 5"),
      search_engine: z.enum(["duckduckgo", "google", "bing"]).optional().describe("搜索引擎: duckduckgo|google|bing，默认 duckduckgo"),
    }),
    category: "osint",
    concurrent: true,
    execute: async (args: any) => {
      const { query, max_results = 5, search_engine = "duckduckgo" } = args;
      try {
        const results: Array<{ title: string; url: string; snippet: string }> = [];

        if (search_engine === "duckduckgo") {
          // 用 curl 调用 DuckDuckGo HTML 搜索（无 API key 需要）
          const searchUrl = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`;
          const html = child_process.execSync(
            `curl -s -A "Mozilla/5.0 (compatible; Flagent-OSINT/1.0)" "${searchUrl}"`,
            { timeout: 15000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
          );

          // 解析搜索结果（标题/URL/摘要），DuckDuckGo HTML 以 <div class="result ..."> 分隔
          const blocks = html.split(/<div class="result[^"]*">/);
          for (let i = 1; i < blocks.length && results.length < max_results; i++) {
            const block = blocks[i];
            const linkMatch = block.match(/<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/i);
            const snippetMatch = block.match(/<a[^>]*class="result__snippet"[^>]*>([\s\S]*?)<\/a>/i);
            if (linkMatch) {
              const title = decodeHtml(linkMatch[2].replace(/<[^>]+>/g, "").trim());
              let url = linkMatch[1];
              // DuckDuckGo 使用跳转链接，提取真实 URL
              const uddgMatch = url.match(/uddg=([^&]+)/);
              if (uddgMatch) {
                url = decodeURIComponent(uddgMatch[1]);
              } else if (url.startsWith("//")) {
                url = "https:" + url;
              }
              const snippet = snippetMatch ? decodeHtml(snippetMatch[1].replace(/<[^>]+>/g, "").trim()) : "";
              results.push({ title, url, snippet });
            }
          }
        } else if (search_engine === "google") {
          // Google 需浏览器交互或 API Key，返回搜索 URL 指引
          return `[web_search_real] 关键词: "${query}"\n引擎: google\n\n⚠️ Google 搜索需要浏览器交互或 API Key，无法直接抓取\n建议:\n  1. 手动访问: https://www.google.com/search?q=${encodeURIComponent(query)}\n  2. 或改用 search_engine=duckduckgo 直接获取结果`;
        } else if (search_engine === "bing") {
          const searchUrl = `https://www.bing.com/search?q=${encodeURIComponent(query)}`;
          const html = child_process.execSync(
            `curl -s -A "Mozilla/5.0 (compatible; Flagent-OSINT/1.0)" "${searchUrl}"`,
            { timeout: 15000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
          );
          // Bing 结果块: <li class="b_algo">
          const blocks = html.split(/<li class="b_algo">/);
          for (let i = 1; i < blocks.length && results.length < max_results; i++) {
            const block = blocks[i];
            const linkMatch = block.match(/<h2>\s*<a[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>\s*<\/h2>/i);
            const snippetMatch = block.match(/<p[^>]*>([\s\S]*?)<\/p>/i);
            if (linkMatch) {
              const title = decodeHtml(linkMatch[2].replace(/<[^>]+>/g, "").trim());
              const snippet = snippetMatch ? decodeHtml(snippetMatch[1].replace(/<[^>]+>/g, "").trim()) : "";
              results.push({ title, url: linkMatch[1], snippet });
            }
          }
        }

        if (results.length === 0) {
          return `[web_search_real] 关键词: "${query}" (引擎: ${search_engine})\n\n未找到结果或页面解析失败`;
        }

        const formatted = results.map((r, i) =>
          `  ${i + 1}. ${r.title}\n     URL: ${r.url}\n     摘要: ${r.snippet || "(无)"}`
        ).join("\n\n");

        return `[web_search_real] 关键词: "${query}" (引擎: ${search_engine}, 共 ${results.length} 条)\n\n${formatted}`;
      } catch (err: any) {
        if (/command not found|not recognized/i.test(err.message) || err.status === 127) {
          return `[web_search_real] ❌ 系统未安装 curl\n  macOS: 自带或 brew install curl\n  Ubuntu/Debian: sudo apt install curl\n  RHEL/CentOS: sudo yum install curl`;
        }
        return `[web_search_real] 搜索失败: ${err.message}`;
      }
    },
  });

  // ============================================================
  // 2. whois_lookup - WHOIS 域名信息查询
  // ============================================================
  registry.register({
    name: "whois_lookup",
    description: "WHOIS 域名信息查询（优先使用 whois 命令，回退 RDAP API）",
    parameters: z.object({
      domain: z.string().describe("要查询的域名（如 example.com）"),
      record_type: z.enum(["all", "registrar", "dates", "ns", "contact"]).optional().describe("记录类型: all|registrar|dates|ns|contact，默认 all"),
    }),
    category: "osint",
    concurrent: true,
    execute: async (args: any) => {
      const { domain, record_type = "all" } = args;
      // 简单域名格式校验，防止命令注入
      if (!/^[a-zA-Z0-9.-]+$/.test(domain)) {
        return `[whois_lookup] ❌ 无效的域名: ${domain}`;
      }
      try {
        let rawWhois = "";
        let usedTool = "whois";

        // 优先尝试 whois 命令
        try {
          rawWhois = child_process.execSync(`whois ${domain}`, {
            timeout: 15000,
            maxBuffer: 1024 * 1024,
            encoding: "utf-8",
          });
        } catch (e: any) {
          // whois 命令不存在或失败，回退到 RDAP API
          usedTool = "rdap";
          try {
            const rdap = child_process.execSync(
              `curl -s -A "Mozilla/5.0 (compatible; Flagent-OSINT/1.0)" "https://rdap.org/domain/${domain}"`,
              { timeout: 15000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
            );
            if (rdap) {
              const data = JSON.parse(rdap);
              return formatRdap(data, domain, record_type);
            }
          } catch (e2: any) {
            if (/command not found|not recognized/i.test(e.message)) {
              return `[whois_lookup] ❌ 系统未安装 whois 命令且 RDAP 查询也失败\n  macOS: brew install whois\n  Ubuntu/Debian: sudo apt install whois\n  RHEL/CentOS: sudo yum install whois\n  错误: ${e2.message}`;
            }
            return `[whois_lookup] 查询失败: ${e.message}`;
          }
        }

        return parseWhois(rawWhois, domain, record_type, usedTool);
      } catch (err: any) {
        return `[whois_lookup] 查询失败: ${err.message}`;
      }
    },
  });

  // ============================================================
  // 3. social_media_search - 社交媒体用户关联查询
  // ============================================================
  registry.register({
    name: "social_media_search",
    description: "社交媒体账号关联查询（检查用户名在多平台的存在性 + GitHub 公开信息）",
    parameters: z.object({
      username: z.string().describe("用户名"),
      platforms: z.array(z.enum(["github", "twitter", "reddit", "instagram", "youtube"])).optional().describe("要查询的平台列表，默认全部"),
    }),
    category: "osint",
    concurrent: true,
    execute: async (args: any) => {
      const { username, platforms = ["github", "twitter", "reddit", "instagram", "youtube"] } = args;
      // 用户名简单校验
      if (!/^[a-zA-Z0-9._-]+$/.test(username)) {
        return `[social_media_search] ❌ 无效的用户名: ${username}`;
      }

      const checks: Array<{ platform: string; url: string; checkType: "header" | "api" }> = [
        { platform: "github", url: `https://github.com/${username}`, checkType: "api" },
        { platform: "twitter", url: `https://twitter.com/${username}`, checkType: "header" },
        { platform: "reddit", url: `https://www.reddit.com/user/${username}`, checkType: "header" },
        { platform: "instagram", url: `https://www.instagram.com/${username}/`, checkType: "header" },
        { platform: "youtube", url: `https://www.youtube.com/@${username}`, checkType: "header" },
      ];

      const results: string[] = [];

      for (const c of checks) {
        if (!platforms.includes(c.platform as any)) continue;
        try {
          if (c.checkType === "api" && c.platform === "github") {
            // GitHub 公开 API 获取公开信息
            const apiRes = child_process.execSync(
              `curl -s -A "Mozilla/5.0 (compatible; Flagent-OSINT/1.0)" "https://api.github.com/users/${username}"`,
              { timeout: 15000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
            );
            try {
              const data = JSON.parse(apiRes);
              if (data.login) {
                results.push(
                  `  ✓ [GitHub] 账号存在: ${data.html_url}\n` +
                  `    名称: ${data.name || "(无)"}\n` +
                  `    公司: ${data.company || "(无)"}\n` +
                  `    位置: ${data.location || "(无)"}\n` +
                  `    公开仓库: ${data.public_repos || 0}\n` +
                  `    关注者: ${data.followers || 0}\n` +
                  `    创建时间: ${data.created_at || "(无)"}\n` +
                  `    简介: ${(data.bio || "(无)").slice(0, 100)}`
                );
              } else {
                results.push(`  ✗ [GitHub] 账号不存在 (404)`);
              }
            } catch {
              results.push(`  ? [GitHub] API 响应解析失败`);
            }
          } else {
            // 用 curl -sI 检查 HTTP 状态码
            const statusCode = child_process.execSync(
              `curl -sI -A "Mozilla/5.0 (compatible; Flagent-OSINT/1.0)" -o /dev/null -w "%{http_code}" "${c.url}"`,
              { timeout: 15000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
            ).trim();
            const code = parseInt(statusCode, 10);
            if (code === 200) {
              results.push(`  ✓ [${c.platform}] 账号可能存在 (HTTP 200): ${c.url}`);
            } else if (code === 404) {
              results.push(`  ✗ [${c.platform}] 账号不存在 (HTTP 404)`);
            } else if (code === 301 || code === 302) {
              results.push(`  ? [${c.platform}] 重定向 (HTTP ${code}): ${c.url}`);
            } else {
              results.push(`  ? [${c.platform}] 状态码 ${code || "未知"}: ${c.url}`);
            }
          }
        } catch (err: any) {
          if (/command not found|not recognized/i.test(err.message)) {
            return `[social_media_search] ❌ 系统未安装 curl\n  macOS: 自带或 brew install curl\n  Ubuntu/Debian: sudo apt install curl\n  RHEL/CentOS: sudo yum install curl`;
          }
          results.push(`  ✗ [${c.platform}] 检测失败: ${err.message}`);
        }
      }

      return `[social_media_search] 用户名: ${username}\n检查平台: ${platforms.join(", ")}\n\n${results.join("\n")}\n\n💡 提示:\n  - Twitter/Instagram 可能需要登录才能确认账号存在\n  - 建议多平台交叉验证`;
    },
  });

  // ============================================================
  // 4. geo_locate - 地理位置定位
  // ============================================================
  registry.register({
    name: "geo_locate",
    description: "地理位置定位（IP 定位或经纬度反查地址）",
    parameters: z.object({
      input: z.string().describe("IP 地址或经纬度坐标（如 8.8.8.8 或 40.7128,-74.0060）"),
      input_type: z.enum(["ip", "coords", "auto"]).optional().describe("输入类型: ip|coords|auto，默认 auto"),
    }),
    category: "osint",
    concurrent: true,
    execute: async (args: any) => {
      const { input, input_type = "auto" } = args;

      let actualType = input_type;
      if (actualType === "auto") {
        // 自动判断：纯 IP 格式或含逗号的坐标
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        const coordsRegex = /^-?\d+(\.\d+)?,\s*-?\d+(\.\d+)?$/;
        if (ipRegex.test(input)) actualType = "ip";
        else if (coordsRegex.test(input)) actualType = "coords";
        else actualType = "ip";
      }

      try {
        if (actualType === "ip") {
          // IP 定位: 用 curl 调用 ip-api.com 获取地理位置
          const apiRes = child_process.execSync(
            `curl -s "http://ip-api.com/json/${encodeURIComponent(input)}?lang=zh-CN"`,
            { timeout: 15000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
          );
          const data = JSON.parse(apiRes);
          if (data.status === "success") {
            return `[geo_locate] IP: ${input}\n` +
              `  国家: ${data.country || "(无)"} (${data.countryCode || "?"})\n` +
              `  省份: ${data.regionName || "(无)"}\n` +
              `  城市: ${data.city || "(无)"}\n` +
              `  经纬度: ${data.lat}, ${data.lon}\n` +
              `  时区: ${data.timezone || "(无)"}\n` +
              `  ISP: ${data.isp || "(无)"}\n` +
              `  组织: ${data.org || "(无)"}\n` +
              `  AS: ${data.as || "(无)"}\n` +
              `  Google Maps: https://www.google.com/maps?q=${data.lat},${data.lon}`;
          } else {
            return `[geo_locate] IP 查询失败: ${data.message || "未知错误"}`;
          }
        } else {
          // 坐标反查: 返回最近的大城市/地址信息
          const parts = input.split(",").map((s: string) => s.trim());
          const lat = parts[0];
          const lon = parts[1];
          const apiRes = child_process.execSync(
            `curl -s -A "Flagent-OSINT/1.0" "https://nominatim.openstreetmap.org/reverse?lat=${encodeURIComponent(lat)}&lon=${encodeURIComponent(lon)}&format=json&accept-language=zh-CN"`,
            { timeout: 15000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
          );
          const data = JSON.parse(apiRes);
          if (data.error) {
            return `[geo_locate] 坐标反查失败: ${data.error}`;
          }
          const addr = data.address || {};
          return `[geo_locate] 坐标: ${lat}, ${lon}\n` +
            `  显示名: ${data.display_name || "(无)"}\n` +
            `  国家: ${addr.country || "(无)"}\n` +
            `  省份: ${addr.state || addr.region || "(无)"}\n` +
            `  城市: ${addr.city || addr.town || addr.village || addr.county || "(无)"}\n` +
            `  邮编: ${addr.postcode || "(无)"}\n` +
            `  Google Maps: https://www.google.com/maps?q=${lat},${lon}`;
        }
      } catch (err: any) {
        if (/command not found|not recognized/i.test(err.message)) {
          return `[geo_locate] ❌ 系统未安装 curl\n  macOS: 自带或 brew install curl\n  Ubuntu/Debian: sudo apt install curl\n  RHEL/CentOS: sudo yum install curl`;
        }
        return `[geo_locate] 查询失败: ${err.message}`;
      }
    },
  });

  // ============================================================
  // 5. image_exif_analyze - 图片 EXIF 元数据分析
  // ============================================================
  registry.register({
    name: "image_exif_analyze",
    description: "图片 EXIF 元数据分析（GPS 定位/相机信息/时间戳，优先用 exiftool，回退内置 JPEG 解析）",
    parameters: z.object({
      image_path: z.string().describe("图片文件路径"),
      extract_fields: z.array(z.enum(["gps", "camera", "timestamp", "software", "all"])).optional().describe("要提取的字段: gps|camera|timestamp|software|all，默认 all"),
    }),
    category: "osint",
    concurrent: true,
    execute: async (args: any) => {
      const { image_path, extract_fields = ["all"] } = args;
      if (!fs.existsSync(image_path)) return `❌ 文件不存在: ${image_path}`;

      const wantAll = extract_fields.includes("all" as any);
      const wantGps = wantAll || extract_fields.includes("gps" as any);
      const wantCamera = wantAll || extract_fields.includes("camera" as any);
      const wantTimestamp = wantAll || extract_fields.includes("timestamp" as any);
      const wantSoftware = wantAll || extract_fields.includes("software" as any);

      try {
        // 检查 exiftool 是否安装
        let exiftoolPath = "";
        try {
          exiftoolPath = child_process.execSync("which exiftool 2>/dev/null", {
            timeout: 3000,
            encoding: "utf-8",
          }).trim();
        } catch {
          exiftoolPath = "";
        }

        if (exiftoolPath) {
          // 用 exiftool 命令提取 EXIF 数据（JSON 输出）
          const exifOutput = child_process.execSync(
            `exiftool -j "${image_path}"`,
            { timeout: 15000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
          );
          try {
            const data = JSON.parse(exifOutput)[0];
            const lines: string[] = [];

            if (wantGps) {
              const lat = data.GPSLatitude;
              const lon = data.GPSLongitude;
              if (lat !== undefined && lon !== undefined) {
                const latStr = `${Math.abs(lat)}${lat >= 0 ? "N" : "S"}`;
                const lonStr = `${Math.abs(lon)}${lon >= 0 ? "E" : "W"}`;
                lines.push(`[GPS 位置]`);
                lines.push(`  经纬度: ${lat}, ${lon} (${latStr}, ${lonStr})`);
                lines.push(`  Google Maps: https://www.google.com/maps?q=${lat},${lon}`);
                if (data.GPSAltitude) lines.push(`  海拔: ${data.GPSAltitude} m`);
              } else {
                lines.push(`[GPS 位置] (无 GPS 信息)`);
              }
            }

            if (wantCamera) {
              lines.push(`[相机信息]`);
              lines.push(`  相机厂商: ${data.Make || "(无)"}`);
              lines.push(`  相机型号: ${data.Model || "(无)"}`);
              lines.push(`  镜头: ${data.LensModel || data.LensInfo || "(无)"}`);
              lines.push(`  光圈: ${data.FNumber ? `f/${data.FNumber}` : "(无)"}`);
              lines.push(`  快门: ${data.ExposureTime ? `${data.ExposureTime}s` : "(无)"}`);
              lines.push(`  ISO: ${data.ISO || "(无)"}`);
              lines.push(`  焦距: ${data.FocalLength ? `${data.FocalLength}mm` : "(无)"}`);
            }

            if (wantTimestamp) {
              lines.push(`[时间戳]`);
              lines.push(`  拍摄时间: ${data.DateTimeOriginal || data.CreateDate || "(无)"}`);
              lines.push(`  修改时间: ${data.ModifyDate || "(无)"}`);
            }

            if (wantSoftware) {
              lines.push(`[软件信息]`);
              lines.push(`  软件: ${data.Software || "(无)"}`);
              lines.push(`  设备: ${data.HostComputer || "(无)"}`);
            }

            return `[image_exif_analyze] ${image_path}\n（使用 exiftool）\n\n${lines.join("\n")}`;
          } catch {
            return `[image_exif_analyze] ${image_path}\n（使用 exiftool）\n\n${exifOutput.slice(0, 5000)}`;
          }
        } else {
          // exiftool 不存在，用 Node.js 解析 JPEG EXIF 段（解析 APP1 段中的 TIFF IFD）
          const buf = fs.readFileSync(image_path);
          const exifData = parseJpegExif(buf);
          if (!exifData) {
            return `[image_exif_analyze] ${image_path}\n\n⚠️ 系统未安装 exiftool，且文件不是有效 JPEG 或无 EXIF 段\n  安装 exiftool 以获得更完整信息:\n  macOS: brew install exiftool\n  Ubuntu/Debian: sudo apt install libimage-exiftool-perl\n  RHEL/CentOS: sudo yum install perl-Image-ExifTool`;
          }

          const lines: string[] = [];

          if (wantGps) {
            if (exifData.gps) {
              const g = exifData.gps;
              lines.push(`[GPS 位置]`);
              lines.push(`  经纬度: ${g.lat}, ${g.lon}`);
              if (g.altitude) lines.push(`  海拔: ${g.altitude} m`);
              lines.push(`  Google Maps: https://www.google.com/maps?q=${g.lat},${g.lon}`);
            } else {
              lines.push(`[GPS 位置] (无 GPS 信息)`);
            }
          }

          if (wantCamera) {
            lines.push(`[相机信息]`);
            lines.push(`  相机厂商: ${exifData.Make || "(无)"}`);
            lines.push(`  相机型号: ${exifData.Model || "(无)"}`);
            lines.push(`  镜头: ${exifData.LensModel || "(无)"}`);
            lines.push(`  光圈: ${exifData.FNumber ? `f/${exifData.FNumber}` : "(无)"}`);
            lines.push(`  快门: ${exifData.ExposureTime ? `${exifData.ExposureTime}s` : "(无)"}`);
            lines.push(`  ISO: ${exifData.ISO || "(无)"}`);
            lines.push(`  焦距: ${exifData.FocalLength ? `${exifData.FocalLength}mm` : "(无)"}`);
          }

          if (wantTimestamp) {
            lines.push(`[时间戳]`);
            lines.push(`  拍摄时间: ${exifData.DateTimeOriginal || exifData.DateTime || "(无)"}`);
          }

          if (wantSoftware) {
            lines.push(`[软件信息]`);
            lines.push(`  软件: ${exifData.Software || "(无)"}`);
          }

          return `[image_exif_analyze] ${image_path}\n（使用内置 JPEG EXIF 解析器，建议安装 exiftool 获得更完整信息）\n\n${lines.join("\n")}`;
        }
      } catch (err: any) {
        return `[image_exif_analyze] 分析失败: ${err.message}`;
      }
    },
  });

  // ============================================================
  // 6. reverse_image_search - 反向图片搜索
  // ============================================================
  registry.register({
    name: "reverse_image_search",
    description: "反向图片搜索（生成搜索 URL 和使用指引，支持 Google/TinEye/Bing/Yandex）",
    parameters: z.object({
      image_path: z.string().describe("本地图片路径"),
      engine: z.enum(["google", "tineye", "bing", "yandex"]).optional().describe("搜索引擎: google|tineye|bing|yandex，默认 google"),
    }),
    category: "osint",
    concurrent: true,
    execute: async (args: any) => {
      const { image_path, engine = "google" } = args;
      if (!fs.existsSync(image_path)) return `❌ 文件不存在: ${image_path}`;

      try {
        const lines: string[] = [];
        lines.push(`[reverse_image_search] 图片: ${image_path}`);
        lines.push(`引擎: ${engine}`);
        lines.push("");
        lines.push(`⚠️ 反向图片搜索需要浏览器交互，以下为搜索 URL 和使用指引:`);
        lines.push("");

        if (engine === "google") {
          // Google Images: 构造搜索 URL 指引
          lines.push(`[Google Lens 反向搜索]`);
          lines.push(`  方式1 (上传图片):`);
          lines.push(`    1. 访问 https://lens.google.com/`);
          lines.push(`    2. 点击上传按钮，选择本地图片: ${image_path}`);
          lines.push(`    3. 等待 Google 识别并显示相似图片`);
          lines.push(`  方式2 (传统图片搜索):`);
          lines.push(`    1. 访问 https://www.google.com/imghp`);
          lines.push(`    2. 点击相机图标`);
          lines.push(`    3. 选择"上传图片"标签，上传 ${image_path}`);
          lines.push(`  方式3 (若有图片URL):`);
          lines.push(`    https://lens.google.com/uploadbyurl?url=<你的图片URL>`);
        } else if (engine === "tineye") {
          // TinEye: 构造搜索 URL
          lines.push(`[TinEye 反向搜索]`);
          lines.push(`  方式1 (上传图片):`);
          lines.push(`    1. 访问 https://tineye.com/`);
          lines.push(`    2. 点击上传按钮，选择本地图片: ${image_path}`);
          lines.push(`  方式2 (若有图片URL):`);
          lines.push(`    https://tineye.com/search?url=<你的图片URL>`);
        } else if (engine === "bing") {
          lines.push(`[Bing Visual Search]`);
          lines.push(`  1. 访问 https://www.bing.com/images`);
          lines.push(`  2. 点击搜索框右侧的相机图标`);
          lines.push(`  3. 上传本地图片: ${image_path}`);
        } else if (engine === "yandex") {
          lines.push(`[Yandex Images 反向搜索] (对人脸/地理位置识别效果好)`);
          lines.push(`  1. 访问 https://yandex.com/images/`);
          lines.push(`  2. 点击搜索框右侧的相机图标`);
          lines.push(`  3. 上传本地图片: ${image_path}`);
        }

        lines.push("");
        lines.push(`💡 提示:`);
        lines.push(`  - Yandex 对人脸识别效果最好`);
        lines.push(`  - Google Lens 对物体/文字识别效果好`);
        lines.push(`  - TinEye 适合查找图片的原始出处`);
        lines.push(`  - 建议多引擎交叉验证`);

        return lines.join("\n");
      } catch (err: any) {
        return `[reverse_image_search] 失败: ${err.message}`;
      }
    },
  });

  // ============================================================
  // 7. subdomain_enum - 子域名枚举
  // ============================================================
  registry.register({
    name: "subdomain_enum",
    description: "子域名枚举（多数据源聚合查询：crt.sh/dnsdumpster/hackertarget）",
    parameters: z.object({
      domain: z.string().describe("目标域名"),
      sources: z.array(z.enum(["crtsh", "dnsdumpster", "hackertarget", "all"])).optional().describe("数据源: crtsh|dnsdumpster|hackertarget|all，默认 all"),
      max_results: z.number().min(10).max(500).optional().describe("最大返回结果数（10-500），默认 100"),
    }),
    category: "osint",
    concurrent: true,
    execute: async (args: any) => {
      const { domain, sources = ["all"], max_results = 100 } = args;
      // 域名格式校验
      if (!/^[a-zA-Z0-9.-]+$/.test(domain)) {
        return `[subdomain_enum] ❌ 无效的域名: ${domain}`;
      }

      const useAll = sources.includes("all" as any);
      const useCrtsh = useAll || sources.includes("crtsh" as any);
      const useDnsdumpster = useAll || sources.includes("dnsdumpster" as any);
      const useHackertarget = useAll || sources.includes("hackertarget" as any);

      // 子域名 -> 来源集合
      const subdomains = new Map<string, Set<string>>();

      function addSubdomain(sub: string, source: string) {
        const clean = sub.toLowerCase().trim().replace(/\.$/, "").replace(/^\*\./, "");
        if (!clean) return;
        if (!subdomains.has(clean)) subdomains.set(clean, new Set());
        subdomains.get(clean)!.add(source);
      }

      const errors: string[] = [];

      // crt.sh: 查询证书透明度日志
      if (useCrtsh) {
        try {
          const crtshRes = child_process.execSync(
            `curl -s "https://crt.sh/?q=${encodeURIComponent(domain)}&output=json"`,
            { timeout: 15000, maxBuffer: 2 * 1024 * 1024, encoding: "utf-8" }
          );
          if (crtshRes) {
            try {
              const entries = JSON.parse(crtshRes);
              for (const entry of entries) {
                const names: string = entry.name_value || "";
                for (const name of names.split("\n")) {
                  addSubdomain(name, "crtsh");
                }
              }
            } catch {}
          }
        } catch (err: any) {
          errors.push(`crtsh: ${err.message}`);
        }
      }

      // dnsdumpster: 需要 CSRF token，无法直接 curl，跳过
      if (useDnsdumpster) {
        errors.push(`dnsdumpster: 需要 CSRF token/浏览器交互，已跳过（建议手动访问 https://dnsdumpster.com/）`);
      }

      // hackertarget: 子域名查询 API
      if (useHackertarget) {
        try {
          const htRes = child_process.execSync(
            `curl -s "https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}"`,
            { timeout: 15000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
          );
          if (htRes && !htRes.startsWith("error") && !htRes.includes("API count exceeded")) {
            for (const line of htRes.split("\n")) {
              const parts = line.split(",");
              if (parts[0]) addSubdomain(parts[0], "hackertarget");
            }
          } else if (htRes) {
            errors.push(`hackertarget: ${htRes.slice(0, 200)}`);
          }
        } catch (err: any) {
          errors.push(`hackertarget: ${err.message}`);
        }
      }

      if (subdomains.size === 0) {
        return `[subdomain_enum] 域名: ${domain}\n数据源: ${sources.join(", ")}\n\n未发现子域名${errors.length ? `\n\n错误信息:\n  ${errors.join("\n  ")}` : ""}`;
      }

      // 过滤掉非子域名（保留 *.domain 形式的）
      const filtered = Array.from(subdomains.entries())
        .filter(([sub]) => sub === domain || sub.endsWith(`.${domain}`))
        .sort();

      const limited = filtered.slice(0, max_results);

      const formatted = limited.map(([sub, srcs]) =>
        `  ${sub}  [${Array.from(srcs).join(", ")}]`
      ).join("\n");

      return `[subdomain_enum] 域名: ${domain}\n` +
        `数据源: ${sources.join(", ")}\n` +
        `发现子域名: ${filtered.length} 个${filtered.length > max_results ? ` (显示前 ${max_results})` : ""}\n\n` +
        `${formatted}` +
        `${errors.length ? `\n\n错误信息:\n  ${errors.join("\n  ")}` : ""}`;
    },
  });

  // ============================================================
  // 8. wayback_lookup - Wayback Machine 历史快照查询
  // ============================================================
  registry.register({
    name: "wayback_lookup",
    description: "Wayback Machine 历史快照查询（列出/获取/对比历史页面）",
    parameters: z.object({
      url: z.string().describe("目标 URL"),
      mode: z.enum(["list", "snapshot", "diff"]).optional().describe("模式: list|snapshot|diff，默认 list"),
      limit: z.number().min(5).max(100).optional().describe("返回快照数（5-100），默认 20"),
      timestamp: z.string().optional().describe("指定时间戳（如 20230101），mode=snapshot 时使用；mode=diff 时格式为 ts1,ts2"),
    }),
    category: "osint",
    concurrent: true,
    execute: async (args: any) => {
      const { url, mode = "list", limit = 20, timestamp } = args;

      try {
        if (mode === "list") {
          // mode=list: 列出历史快照
          const apiUrl = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(url)}&output=json&limit=${limit}`;
          const res = child_process.execSync(
            `curl -s -A "Mozilla/5.0 (compatible; Flagent-OSINT/1.0)" "${apiUrl}"`,
            { timeout: 15000, maxBuffer: 2 * 1024 * 1024, encoding: "utf-8" }
          );

          try {
            const data = JSON.parse(res);
            if (!Array.isArray(data) || data.length <= 1) {
              return `[wayback_lookup] URL: ${url}\n模式: list\n\n未找到历史快照`;
            }

            // 第一行是表头: urlkey, timestamp, original, mimetype, statuscode, digest, length
            const header = data[0];
            const rows = data.slice(1);

            const tsIdx = header.indexOf("timestamp");
            const statusIdx = header.indexOf("statuscode");
            const origIdx = header.indexOf("original");

            const formatted = rows.map((row: any[]) => {
              const ts = tsIdx >= 0 ? row[tsIdx] : "?";
              const status = statusIdx >= 0 ? row[statusIdx] : "?";
              const orig = origIdx >= 0 ? row[origIdx] : "?";
              const snapshotUrl = `https://web.archive.org/web/${ts}/${orig}`;
              return `  ${ts}  [HTTP ${status}]  ${snapshotUrl}`;
            }).join("\n");

            return `[wayback_lookup] URL: ${url}\n模式: list (共 ${rows.length} 个快照)\n\n${formatted}`;
          } catch {
            return `[wayback_lookup] URL: ${url}\n模式: list\n\nJSON 解析失败，原始响应:\n${res.slice(0, 5000)}`;
          }
        } else if (mode === "snapshot") {
          // mode=snapshot: 获取指定时间戳的快照内容
          if (!timestamp) {
            return `[wayback_lookup] ❌ mode=snapshot 必须传 timestamp 参数（如 20230101）`;
          }
          if (!/^\d+$/.test(timestamp)) {
            return `[wayback_lookup] ❌ timestamp 必须为数字（如 20230101）`;
          }
          const snapshotUrl = `https://web.archive.org/web/${timestamp}/${url}`;
          const res = child_process.execSync(
            `curl -s -L -A "Mozilla/5.0 (compatible; Flagent-OSINT/1.0)" "${snapshotUrl}"`,
            { timeout: 15000, maxBuffer: 2 * 1024 * 1024, encoding: "utf-8" }
          );

          // 提取标题
          const titleMatch = res.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
          const title = titleMatch ? decodeHtml(titleMatch[1].trim()) : "(无标题)";

          // 截取部分内容（去标签后）
          const bodyText = res
            .replace(/<script[\s\S]*?<\/script>/gi, "")
            .replace(/<style[\s\S]*?<\/style>/gi, "")
            .replace(/<[^>]+>/g, " ")
            .replace(/\s+/g, " ")
            .trim()
            .slice(0, 3000);

          return `[wayback_lookup] URL: ${url}\n模式: snapshot\n时间戳: ${timestamp}\n快照URL: ${snapshotUrl}\n标题: ${title}\n\n内容预览:\n${bodyText}${bodyText.length >= 3000 ? "\n...(截断)" : ""}`;
        } else if (mode === "diff") {
          // mode=diff: 对比两个时间点的页面差异
          if (!timestamp) {
            return `[wayback_lookup] ❌ mode=diff 必须传 timestamp 参数（格式: "ts1,ts2" 如 "20220101,20230101"）`;
          }
          const ts = timestamp.split(",").map((s: string) => s.trim());
          if (ts.length !== 2 || !ts.every((t: string) => /^\d+$/.test(t))) {
            return `[wayback_lookup] ❌ mode=diff 的 timestamp 格式应为 "ts1,ts2"（纯数字，如 20220101,20230101）`;
          }

          const [ts1, ts2] = ts;
          const url1 = `https://web.archive.org/web/${ts1}/${url}`;
          const url2 = `https://web.archive.org/web/${ts2}/${url}`;

          // 获取两个快照
          let res1 = "";
          let res2 = "";
          try {
            res1 = child_process.execSync(
              `curl -s -L -A "Mozilla/5.0 (compatible; Flagent-OSINT/1.0)" "${url1}"`,
              { timeout: 15000, maxBuffer: 2 * 1024 * 1024, encoding: "utf-8" }
            );
          } catch (e: any) {
            return `[wayback_lookup] 获取快照1失败 (${ts1}): ${e.message}`;
          }
          try {
            res2 = child_process.execSync(
              `curl -s -L -A "Mozilla/5.0 (compatible; Flagent-OSINT/1.0)" "${url2}"`,
              { timeout: 15000, maxBuffer: 2 * 1024 * 1024, encoding: "utf-8" }
            );
          } catch (e: any) {
            return `[wayback_lookup] 获取快照2失败 (${ts2}): ${e.message}`;
          }

          // 提取纯文本行进行对比
          const extractText = (html: string): string[] => html
            .replace(/<script[\s\S]*?<\/script>/gi, "")
            .replace(/<style[\s\S]*?<\/style>/gi, "")
            .replace(/<[^>]+>/g, "\n")
            .replace(/\n+/g, "\n")
            .trim()
            .split("\n")
            .map((l) => l.trim())
            .filter((l) => l.length > 0);

          const lines1 = new Set(extractText(res1));
          const lines2 = new Set(extractText(res2));

          const onlyIn1: string[] = [];
          const onlyIn2: string[] = [];
          for (const l of lines1) if (!lines2.has(l)) onlyIn1.push(l);
          for (const l of lines2) if (!lines1.has(l)) onlyIn2.push(l);

          return `[wayback_lookup] URL: ${url}\n模式: diff\n对比: ${ts1} vs ${ts2}\n快照1: ${url1}\n快照2: ${url2}\n\n` +
            `仅在快照1 (${ts1}) 中存在 (${onlyIn1.length} 行):\n` +
            `${onlyIn1.slice(0, 20).map((l) => `  - ${l.slice(0, 200)}`).join("\n")}${onlyIn1.length > 20 ? `\n  ...(+${onlyIn1.length - 20} 行)` : ""}\n\n` +
            `仅在快照2 (${ts2}) 中存在 (${onlyIn2.length} 行):\n` +
            `${onlyIn2.slice(0, 20).map((l) => `  + ${l.slice(0, 200)}`).join("\n")}${onlyIn2.length > 20 ? `\n  ...(+${onlyIn2.length - 20} 行)` : ""}`;
        }

        return `[wayback_lookup] 未知模式: ${mode}`;
      } catch (err: any) {
        if (/command not found|not recognized/i.test(err.message)) {
          return `[wayback_lookup] ❌ 系统未安装 curl\n  macOS: 自带或 brew install curl\n  Ubuntu/Debian: sudo apt install curl\n  RHEL/CentOS: sudo yum install curl`;
        }
        return `[wayback_lookup] 查询失败: ${err.message}`;
      }
    },
  });

  return registry;
}

// ============================================================
// 辅助函数
// ============================================================

/** HTML 实体解码 */
function decodeHtml(text: string): string {
  return text
    .replace(/&#(\d+);/g, (_m, code: string) => String.fromCharCode(parseInt(code, 10)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_m, code: string) => String.fromCharCode(parseInt(code, 16)))
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&nbsp;/g, " ");
}

/** 解析 whois 命令原始输出为结构化信息 */
function parseWhois(raw: string, domain: string, recordType: string, usedTool: string): string {
  const lines = raw.split("\n");
  const info: Record<string, string> = {};
  // 收集所有 NS 记录（可能有多个同名行）
  const nsList: string[] = [];

  for (const line of lines) {
    const m = line.match(/^\s*([\w\s.-]+?)\s*:\s*(.+?)\s*$/);
    if (m) {
      const key = m[1].trim().toLowerCase();
      const val = m[2].trim();
      if (/name server|nserver/.test(key)) {
        nsList.push(val);
      }
      if (!info[key]) info[key] = val;
    }
  }

  const section: string[] = [];
  section.push(`[whois_lookup] 域名: ${domain} (使用 ${usedTool} 命令)`);

  if (recordType === "all" || recordType === "registrar") {
    section.push(`[注册商]`);
    section.push(`  注册商: ${info["registrar"] || info["sponsoring registrar"] || "(无)"}`);
    section.push(`  注册商URL: ${info["registrar url"] || "(无)"}`);
    section.push(`  注册商邮箱: ${info["registrar email"] || info["abuse contact email"] || "(无)"}`);
    section.push(`  注册商电话: ${info["registrar phone"] || info["abuse contact phone"] || "(无)"}`);
  }

  if (recordType === "all" || recordType === "dates") {
    section.push(`[日期]`);
    section.push(`  创建时间: ${info["creation date"] || info["registered on"] || info["created"] || info["registration time"] || "(无)"}`);
    section.push(`  过期时间: ${info["registry expiry date"] || info["expiry date"] || info["registrar registration expiration date"] || info["expiration time"] || "(无)"}`);
    section.push(`  更新时间: ${info["updated date"] || info["last updated"] || info["last-modified"] || "(无)"}`);
  }

  if (recordType === "all" || recordType === "ns") {
    section.push(`[域名服务器]`);
    if (nsList.length) {
      nsList.forEach((ns) => section.push(`  ${ns}`));
    } else {
      section.push(`  (无)`);
    }
  }

  if (recordType === "all" || recordType === "contact") {
    section.push(`[联系人]`);
    section.push(`  注册人: ${info["registrant name"] || info["registrant"] || "(无)"}`);
    section.push(`  注册人组织: ${info["registrant organization"] || "(无)"}`);
    section.push(`  注册人邮箱: ${info["registrant email"] || "(无)"}`);
    section.push(`  注册人电话: ${info["registrant phone"] || "(无)"}`);
    section.push(`  注册人国家: ${info["registrant country"] || info["country"] || "(无)"}`);
  }

  return section.join("\n");
}

/** 格式化 RDAP API 返回为结构化 WHOIS 信息 */
function formatRdap(data: any, domain: string, recordType: string): string {
  const section: string[] = [];
  section.push(`[whois_lookup] 域名: ${domain} (使用 RDAP API)`);

  // 解析 events（注册/过期/更新时间）
  const events = data.events || [];
  const eventMap: Record<string, string> = {};
  for (const e of events) {
    eventMap[e.eventAction] = e.eventDate;
  }

  // 解析 entities（注册商/联系人）
  let registrarName = "(无)";
  let registrarEmail = "(无)";
  let registrarPhone = "(无)";
  for (const ent of data.entities || []) {
    const roles = ent.roles || [];
    if (roles.includes("registrar")) {
      const vcard = ent.vcardArray?.[1] || [];
      const fnEntry = vcard.find((v: any[]) => v[0] === "fn");
      const emailEntry = vcard.find((v: any[]) => v[0] === "email");
      const telEntry = vcard.find((v: any[]) => v[0] === "tel");
      registrarName = fnEntry?.[3] || ent.handle || "(无)";
      if (emailEntry) registrarEmail = emailEntry[3];
      if (telEntry) registrarPhone = telEntry[3];
    }
  }

  // 解析 NS
  const nsList: string[] = [];
  for (const ns of data.nameservers || []) {
    nsList.push(ns.ldhName || "(unknown)");
  }

  // 解析状态
  const status = (data.status || []).join(", ") || "(无)";

  if (recordType === "all" || recordType === "registrar") {
    section.push(`[注册商]`);
    section.push(`  注册商: ${registrarName}`);
    section.push(`  注册商邮箱: ${registrarEmail}`);
    section.push(`  注册商电话: ${registrarPhone}`);
  }

  if (recordType === "all" || recordType === "dates") {
    section.push(`[日期]`);
    section.push(`  创建时间: ${eventMap["registration"] || "(无)"}`);
    section.push(`  过期时间: ${eventMap["expiration"] || "(无)"}`);
    section.push(`  更新时间: ${eventMap["last changed"] || eventMap["last update of rdap database"] || "(无)"}`);
  }

  if (recordType === "all" || recordType === "ns") {
    section.push(`[域名服务器]`);
    if (nsList.length) nsList.forEach((ns) => section.push(`  ${ns}`));
    else section.push(`  (无)`);
  }

  if (recordType === "all" || recordType === "contact") {
    section.push(`[状态]`);
    section.push(`  ${status}`);
  }

  return section.join("\n");
}

/** 解析 JPEG EXIF 段（APP1 -> TIFF IFD），返回结构化 EXIF 信息 */
function parseJpegExif(buf: Buffer): any | null {
  try {
    // 检查 JPEG 文件头 (FF D8)
    if (buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8) return null;

    let offset = 2;
    while (offset < buf.length - 4) {
      // 查找 marker
      if (buf[offset] !== 0xff) {
        offset++;
        continue;
      }
      const marker = buf[offset + 1];

      // SOS (Start of Scan)，之后无更多 APP 段
      if (marker === 0xda) break;
      // 跳过填充字节
      if (marker === 0xff) {
        offset++;
        continue;
      }

      // APP1 (0xe1) - EXIF 数据段
      if (marker === 0xe1) {
        const segLen = buf.readUInt16BE(offset + 2);
        const segData = buf.slice(offset + 4, offset + 2 + segLen);

        // 检查 "Exif\0\0" 头
        if (segData.length >= 6 && segData.toString("ascii", 0, 4) === "Exif" && segData[4] === 0x00 && segData[5] === 0x00) {
          return parseExifTiff(segData.slice(6));
        }
      }

      // 跳过当前段
      const segLen = buf.readUInt16BE(offset + 2);
      offset += 2 + segLen;
    }
    return null;
  } catch {
    return null;
  }
}

/** 解析 TIFF IFD 数据 */
function parseExifTiff(tiffData: Buffer): any {
  const result: any = {};

  try {
    // TIFF header: 字节序 (II=little endian, MM=big endian)
    const byteOrder = tiffData.toString("ascii", 0, 2);
    const littleEndian = byteOrder === "II";
    const readU16 = (off: number) => littleEndian ? tiffData.readUInt16LE(off) : tiffData.readUInt16BE(off);
    const readU32 = (off: number) => littleEndian ? tiffData.readUInt32LE(off) : tiffData.readUInt32BE(off);

    // TIFF magic number = 42
    if (readU16(2) !== 42) return result;

    const ifd0Offset = readU32(4);
    const ifd0 = parseIfd(tiffData, ifd0Offset, readU16, readU32);

    // IFD0 常见字段
    if (ifd0[0x010f]) result.Make = ifd0[0x010f].value;
    if (ifd0[0x0110]) result.Model = ifd0[0x0110].value;
    if (ifd0[0x0131]) result.Software = ifd0[0x0131].value;
    if (ifd0[0x0132]) result.DateTime = ifd0[0x0132].value;
    if (ifd0[0xa434]) result.LensModel = ifd0[0xa434].value;

    // Exif SubIFD
    if (ifd0[0x8769]) {
      const subIfdOffset = ifd0[0x8769].value as number;
      const subIfd = parseIfd(tiffData, subIfdOffset, readU16, readU32);
      if (!result.DateTimeOriginal && subIfd[0x9003]) result.DateTimeOriginal = subIfd[0x9003].value;
      if (subIfd[0x9004]) result.DateTimeDigitized = subIfd[0x9004].value;
      if (subIfd[0x920a]) result.FocalLength = subIfd[0x920a].value;
      if (subIfd[0x829d]) result.FNumber = subIfd[0x829d].value;
      if (subIfd[0x829a]) result.ExposureTime = subIfd[0x829a].value;
      if (subIfd[0x8827]) result.ISO = subIfd[0x8827].value;
      if (!result.LensModel && subIfd[0xa434]) result.LensModel = subIfd[0xa434].value;
    }

    // GPS IFD
    if (ifd0[0x8825]) {
      const gpsIfdOffset = ifd0[0x8825].value as number;
      const gpsIfd = parseIfd(tiffData, gpsIfdOffset, readU16, readU32);

      const gpsLatRef = gpsIfd[0x0001]?.value as string;
      const gpsLat = gpsIfd[0x0002]?.value as number[];
      const gpsLonRef = gpsIfd[0x0004]?.value as string;
      const gpsLon = gpsIfd[0x0005]?.value as number[];
      const gpsAlt = gpsIfd[0x0006]?.value as number;
      const gpsAltRef = gpsIfd[0x0005]?.value as number;

      if (gpsLat && gpsLon) {
        const lat = gpsToDecimal(gpsLat, gpsLatRef);
        const lon = gpsToDecimal(gpsLon, gpsLonRef);
        if (lat !== null && lon !== null) {
          result.gps = { lat, lon, altitude: gpsAlt !== undefined ? gpsAlt : undefined };
        }
      }
    }

    return result;
  } catch {
    return result;
  }
}

/** 解析单个 IFD（Image File Directory） */
function parseIfd(tiffData: Buffer, offset: number, readU16: (o: number) => number, readU32: (o: number) => number): Record<number, any> {
  const result: Record<number, any> = {};

  try {
    const count = readU16(offset);
    let pos = offset + 2;

    for (let i = 0; i < count; i++) {
      if (pos + 12 > tiffData.length) break;

      const tag = readU16(pos);
      const type = readU16(pos + 2);
      const numValues = readU32(pos + 4);
      const valueOffset = readU32(pos + 8);

      // 类型对应字节数: 1=BYTE, 2=ASCII, 3=SHORT, 4=LONG, 5=RATIONAL, 7=UNDEFINED, 9=SLONG, 10=SRATIONAL
      const typeSizes: Record<number, number> = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };
      const typeSize = typeSizes[type] || 1;
      const totalSize = numValues * typeSize;

      // 值位置: 总长 <=4 时内联在 valueOffset 字段，否则 valueOffset 是偏移量
      let valuePos = pos + 8;
      if (totalSize > 4) valuePos = valueOffset;

      let value: any;

      if (type === 2) {
        // ASCII 字符串
        value = tiffData.toString("ascii", valuePos, valuePos + numValues).replace(/\0+$/, "");
      } else if (type === 3) {
        // SHORT (16位无符号)
        if (numValues === 1) value = readU16(valuePos);
        else {
          value = [];
          for (let j = 0; j < numValues; j++) value.push(readU16(valuePos + j * 2));
        }
      } else if (type === 4) {
        // LONG (32位无符号)
        if (numValues === 1) value = readU32(valuePos);
        else {
          value = [];
          for (let j = 0; j < numValues; j++) value.push(readU32(valuePos + j * 4));
        }
      } else if (type === 5) {
        // RATIONAL (两个 LONG: 分子/分母)
        if (numValues === 1) {
          const numer = readU32(valuePos);
          const denom = readU32(valuePos + 4);
          value = denom !== 0 ? numer / denom : 0;
        } else {
          value = [];
          for (let j = 0; j < numValues; j++) {
            const n = readU32(valuePos + j * 8);
            const d = readU32(valuePos + j * 8 + 4);
            value.push(d !== 0 ? n / d : 0);
          }
        }
      } else if (type === 7) {
        // UNDEFINED - 原始字节
        value = tiffData.toString("ascii", valuePos, valuePos + numValues);
      } else {
        // 其他类型取 valueOffset 原始值
        value = valueOffset;
      }

      result[tag] = { type, value };
      pos += 12;
    }
  } catch {}

  return result;
}

/** GPS 坐标转换: 度/分/秒 (rational 数组) -> 十进制 */
function gpsToDecimal(coord: number[], ref?: string): number | null {
  if (!Array.isArray(coord) || coord.length < 3) return null;
  const dec = coord[0] + coord[1] / 60 + coord[2] / 3600;
  return (ref === "S" || ref === "W") ? -dec : dec;
}
