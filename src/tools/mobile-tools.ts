import { z } from "zod";
import * as fs from "fs";
import * as child_process from "child_process";
import { ToolRegistry } from "./registry";

export function createMobileTools(): ToolRegistry {
  const registry = new ToolRegistry();

  // === 1. APK 深度分析 ===
  registry.register({
    name: "apk_deep_analysis",
    description: "APK 深度分析：解析 AndroidManifest（权限/组件/Intent Filter）、提取资源、反编译 Smali、提取签名信息",
    parameters: z.object({
      apk_path: z.string().describe("APK 文件路径"),
      mode: z.enum(["manifest", "resources", "smali", "cert", "all"]).optional().describe("分析模式，默认 all"),
    }),
    category: "mobile",
    concurrent: true,
    execute: async (args: any) => {
      const { apk_path, mode = "all" } = args;
      if (!fs.existsSync(apk_path)) {
        return "❌ 文件不存在: " + apk_path;
      }

      const os = require("os");
      const path = require("path");
      const sections: string[] = [];
      sections.push("[APK 深度分析] " + apk_path);

      // 检查工具是否安装
      const hasApktool = isToolInstalled("apktool");
      const hasAapt = isToolInstalled("aapt");
      const hasAapt2 = isToolInstalled("aapt2");
      const hasKeytool = isToolInstalled("keytool");
      const hasApksigner = isToolInstalled("apksigner");

      // 创建临时目录
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "flagent-apk-"));

      try {
        // --- manifest 模式：解析 AndroidManifest.xml ---
        if (mode === "manifest" || mode === "all") {
          sections.push("\n── AndroidManifest.xml（权限/组件/Intent Filter）──");
          try {
            if (hasAapt || hasAapt2) {
              const aaptBin = hasAapt ? "aapt" : "aapt2";
              const out = child_process.execSync(
                aaptBin + ' dump xmltree "' + apk_path + '" AndroidManifest.xml',
                { timeout: 30000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
              );
              sections.push(truncate(out, 8000));
            } else if (hasApktool) {
              child_process.execSync(
                'apktool d -f -s "' + apk_path + '" -o "' + tmpDir + '"',
                { timeout: 60000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
              );
              const manifestPath = path.join(tmpDir, "AndroidManifest.xml");
              if (fs.existsSync(manifestPath)) {
                sections.push(truncate(fs.readFileSync(manifestPath, "utf-8"), 8000));
              } else {
                sections.push("(未找到 AndroidManifest.xml)");
              }
            } else {
              sections.push("❌ 需要 aapt/aapt2 或 apktool（均未安装）");
              sections.push("安装方式:");
              sections.push("  macOS: brew install apktool");
              sections.push("  Linux: apt install apktool aapt");
            }
          } catch (err: any) {
            sections.push("[Manifest 解析失败] " + err.message);
          }
        }

        // --- resources 模式：提取资源文件 ---
        if (mode === "resources" || mode === "all") {
          sections.push("\n── 资源文件（strings.xml/layout）──");
          try {
            if (!hasApktool) {
              sections.push("❌ 需要 apktool（未安装）");
              sections.push("安装: brew install apktool / apt install apktool");
            } else {
              const resDir = path.join(tmpDir, "res");
              if (!fs.existsSync(resDir)) {
                // 仅解码资源（-s 跳过 smali）
                child_process.execSync(
                  'apktool d -f -s "' + apk_path + '" -o "' + tmpDir + '"',
                  { timeout: 60000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
                );
              }
              const stringsPath = path.join(tmpDir, "res", "values", "strings.xml");
              if (fs.existsSync(stringsPath)) {
                sections.push("[strings.xml]");
                sections.push(truncate(fs.readFileSync(stringsPath, "utf-8"), 6000));
              } else {
                sections.push("(未找到 res/values/strings.xml)");
              }
              // 列出 layout 文件
              const layoutDir = path.join(tmpDir, "res", "layout");
              if (fs.existsSync(layoutDir)) {
                const layouts = fs.readdirSync(layoutDir).slice(0, 20);
                sections.push("\n[layout 文件] (" + layouts.length + ")");
                sections.push(layouts.join("\n") || "(无)");
              }
            }
          } catch (err: any) {
            sections.push("[资源提取失败] " + err.message);
          }
        }

        // --- smali 模式：反编译为 Smali 代码 ---
        if (mode === "smali" || mode === "all") {
          sections.push("\n── Smali 反编译 ──");
          try {
            if (!hasApktool) {
              sections.push("❌ 需要 apktool（未安装）");
              sections.push("安装: brew install apktool / apt install apktool");
            } else {
              const smaliRoot = path.join(tmpDir, "smali");
              if (!fs.existsSync(smaliRoot)) {
                // 完整反编译（含 smali）
                child_process.execSync(
                  'apktool d -f "' + apk_path + '" -o "' + tmpDir + '"',
                  { timeout: 120000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
                );
              }
              const smaliFiles = listSmaliFiles(tmpDir);
              sections.push("Smali 文件数: " + smaliFiles.length);
              // 以相对路径展示前 30 个关键类
              const relFiles = smaliFiles.slice(0, 30).map((f) => path.relative(tmpDir, f));
              sections.push("\n[关键类（前 30）]");
              sections.push(relFiles.join("\n") || "(无)");
            }
          } catch (err: any) {
            sections.push("[Smali 反编译失败] " + err.message);
          }
        }

        // --- cert 模式：提取签名信息 ---
        if (mode === "cert" || mode === "all") {
          sections.push("\n── 签名信息 ──");
          try {
            if (hasApksigner) {
              const out = child_process.execSync(
                'apksigner verify --print-certs "' + apk_path + '"',
                { timeout: 30000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
              );
              sections.push(truncate(out, 6000));
            } else if (hasKeytool) {
              const out = child_process.execSync(
                'keytool -printcert -jarfile "' + apk_path + '"',
                { timeout: 30000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
              );
              sections.push(truncate(out, 6000));
            } else {
              sections.push("❌ 需要 apksigner 或 keytool（均未安装）");
              sections.push("安装: apksigner 随 Android SDK build-tools 提供");
              sections.push("      keytool 随 JDK/JRE 提供");
            }
          } catch (err: any) {
            sections.push("[签名提取失败] " + err.message);
          }
        }
      } finally {
        // 清理临时目录
        try {
          fs.rmSync(tmpDir, { recursive: true, force: true });
        } catch {}
      }

      return sections.join("\n");
    },
  });

  // === 2. DEX 反编译为 Java ===
  registry.register({
    name: "dex_decompile",
    description: "DEX 反编译为 Java 源码：优先使用 jadx（直接 DEX→Java），其次 dex2jar + cfr",
    parameters: z.object({
      dex_path: z.string().describe("DEX 文件或 APK 路径"),
      output_dir: z.string().optional().describe("输出目录，可选"),
      decompiler: z.enum(["jadx", "dex2jar", "auto"]).optional().describe("反编译器，默认 auto"),
    }),
    category: "mobile",
    concurrent: true,
    execute: async (args: any) => {
      const { dex_path, output_dir, decompiler = "auto" } = args;
      if (!fs.existsSync(dex_path)) {
        return "❌ 文件不存在: " + dex_path;
      }

      const os = require("os");
      const path = require("path");
      const hasJadx = isToolInstalled("jadx");
      const hasD2j = isToolInstalled("d2j-dex2jar.sh") || isToolInstalled("dex2jar");
      const hasCfr = isToolInstalled("cfr");
      const outDir = output_dir || fs.mkdtempSync(path.join(os.tmpdir(), "flagent-dex-"));

      const sections: string[] = [];
      sections.push("[DEX 反编译] " + dex_path);

      const useJadx = decompiler === "jadx" || (decompiler === "auto" && hasJadx);

      try {
        if (useJadx) {
          if (!hasJadx) {
            sections.push("❌ jadx 未安装");
            sections.push("安装: brew install jadx");
            sections.push("或从 https://github.com/skylot/jadx 下载");
            return sections.join("\n");
          }
          child_process.execSync(
            'jadx -d "' + outDir + '" "' + dex_path + '"',
            { timeout: 120000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
          );
        } else {
          // dex2jar 模式
          if (!hasD2j) {
            sections.push("❌ jadx 和 dex2jar 均未安装");
            sections.push("建议优先安装 jadx: brew install jadx");
            sections.push("或安装 dex2jar: brew install dex2jar");
            return sections.join("\n");
          }
          const d2jBin = isToolInstalled("d2j-dex2jar.sh") ? "d2j-dex2jar.sh" : "dex2jar";
          const jarPath = path.join(outDir, "output.jar");
          child_process.execSync(
            d2jBin + ' "' + dex_path + '" -o "' + jarPath + '"',
            { timeout: 60000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
          );
          sections.push("[dex2jar 完成] jar: " + jarPath);

          // 用 cfr 进一步反编译 jar 为 Java 源码
          if (hasCfr) {
            child_process.execSync(
              'cfr "' + jarPath + '" --outputdir "' + outDir + '"',
              { timeout: 60000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
            );
          } else {
            sections.push("提示: 安装 cfr 可进一步反编译为 Java 源码");
            sections.push("  下载: https://github.com/leibnitz27/cfr");
            sections.push("  用法: java -jar cfr.jar " + jarPath + " --outputdir " + outDir);
          }
        }

        // 生成 Java 代码摘要：类列表 + 关键方法
        const javaFiles = listJavaFiles(outDir);
        sections.push("\n反编译 Java 文件数: " + javaFiles.length);
        sections.push("\n[类列表（前 40）]");
        sections.push(
          javaFiles.slice(0, 40).map((f) => path.relative(outDir, f)).join("\n") || "(无)"
        );

        // 提取关键方法签名
        const keyMethods: string[] = [];
        for (const jf of javaFiles.slice(0, 50)) {
          try {
            const content = fs.readFileSync(jf, "utf-8");
            const methodMatches = content.match(
              /(?:public|private|protected|static)\s+[\w<>\[\]]+\s+\w+\s*\([^)]*\)/g
            );
            if (methodMatches && methodMatches.length) {
              const rel = path.relative(outDir, jf);
              keyMethods.push("• " + rel + ":");
              methodMatches.slice(0, 5).forEach((m) => keyMethods.push("    " + m.trim()));
            }
          } catch {}
        }
        if (keyMethods.length) {
          sections.push("\n[关键方法（前 50 个文件的签名）]");
          sections.push(keyMethods.slice(0, 200).join("\n"));
        }

        sections.push("\n输出目录: " + outDir);
        return sections.join("\n");
      } catch (err: any) {
        sections.push("[反编译失败] " + err.message);
        sections.push("\n建议:");
        sections.push("  - 确保 jadx 已安装: brew install jadx");
        sections.push("  - 大型 APK 可能需要增加超时或内存 (-J-Xmx4g)");
        return sections.join("\n");
      }
    },
  });

  // === 3. Smali 代码编辑与重打包 ===
  registry.register({
    name: "smali_edit",
    description: "Smali 代码编辑与重打包：反编译 APK、替换 Smali 文件、重打包并签名",
    parameters: z.object({
      apk_path: z.string().describe("APK 路径"),
      smali_dir: z.string().optional().describe("已反编译的 smali 目录（patch/rebuild/sign 时使用）"),
      action: z.enum(["decompile", "patch", "rebuild", "sign"]).optional().describe("操作类型，默认 decompile"),
      patch_file: z.string().optional().describe("要替换的 smali 文件路径（action=patch 时使用）"),
      output_apk: z.string().optional().describe("输出 APK 路径（rebuild/sign 时使用）"),
    }),
    category: "mobile",
    requirePermission: true,
    execute: async (args: any) => {
      const { apk_path, smali_dir, action = "decompile", patch_file, output_apk } = args;
      const os = require("os");
      const path = require("path");

      // --- decompile：反编译 APK ---
      if (action === "decompile") {
        if (!fs.existsSync(apk_path)) {
          return "❌ 文件不存在: " + apk_path;
        }
        if (!isToolInstalled("apktool")) {
          return "❌ apktool 未安装\n安装: brew install apktool / apt install apktool";
        }
        const outDir = smali_dir || path.join(os.tmpdir(), "flagent-smali-" + Date.now());
        try {
          child_process.execSync(
            'apktool d -f "' + apk_path + '" -o "' + outDir + '"',
            { timeout: 120000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
          );
          const count = listSmaliFiles(outDir).length;
          return "[反编译成功] 输出目录: " + outDir + "\n\nSmali 文件: " + count + " 个";
        } catch (err: any) {
          return "[反编译失败] " + err.message;
        }
      }

      // --- patch：替换指定 smali 文件 ---
      if (action === "patch") {
        const targetDir = smali_dir || "";
        if (!targetDir) {
          return "❌ 需要指定 smali_dir（已反编译的目录）";
        }
        if (!fs.existsSync(targetDir)) {
          return "❌ 目录不存在: " + targetDir;
        }
        if (!patch_file || !fs.existsSync(patch_file)) {
          return "❌ 需要指定有效的 patch_file（要替换的 smali 文件路径）";
        }
        // 在 smali_dir 中查找与 patch_file 同名的文件
        const fileName = path.basename(patch_file);
        const candidates = findFileRecursive(targetDir, fileName);
        if (candidates.length === 0) {
          // 找不到同名文件，复制到 smali 根目录并提示
          const dest = path.join(targetDir, fileName);
          fs.copyFileSync(patch_file, dest);
          return "[Patch 完成] 未找到同名文件，已复制到: " + dest + "\n请手动放置到正确的 smali 子目录";
        }
        const dest = candidates[0];
        fs.copyFileSync(patch_file, dest);
        return "[Patch 完成] 已替换: " + dest;
      }

      // --- rebuild：重打包 APK ---
      if (action === "rebuild") {
        const srcDir = smali_dir || "";
        if (!srcDir || !fs.existsSync(srcDir)) {
          return "❌ 需要指定有效的 smali_dir（已反编译的目录）";
        }
        if (!isToolInstalled("apktool")) {
          return "❌ apktool 未安装\n安装: brew install apktool / apt install apktool";
        }
        const outApk = output_apk || path.join(os.tmpdir(), "flagent-rebuilt-" + Date.now() + ".apk");
        try {
          child_process.execSync(
            'apktool b "' + srcDir + '" -o "' + outApk + '"',
            { timeout: 120000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
          );
          const size = fs.statSync(outApk).size;
          return "[重打包成功] 输出: " + outApk + " (" + size + " 字节)";
        } catch (err: any) {
          return "[重打包失败] " + err.message;
        }
      }

      // --- sign：签名 APK ---
      if (action === "sign") {
        const targetApk = output_apk || apk_path;
        if (!fs.existsSync(targetApk)) {
          return "❌ 文件不存在: " + targetApk;
        }
        if (!isToolInstalled("apksigner") && !isToolInstalled("jarsigner")) {
          return "❌ apksigner 和 jarsigner 均未安装\n安装: apksigner 随 Android SDK build-tools 提供\n      jarsigner 随 JDK/JRE 提供";
        }

        // 生成临时 debug keystore（若不存在）
        const ks = path.join(os.tmpdir(), "flagent-debug.keystore");
        if (!fs.existsSync(ks)) {
          if (!isToolInstalled("keytool")) {
            return "❌ keytool 未安装（生成 keystore 需要 keytool，随 JDK 提供）";
          }
          try {
            child_process.execSync(
              'keytool -genkey -v -keystore "' + ks + '" -alias flagent -keyalg RSA -keysize 2048 -validity 10000 -storepass flagent123 -keypass flagent123 -dname "CN=flagent, OU=ctf, O=ctf, L=NA, ST=NA, C=NA"',
              { timeout: 30000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
            );
          } catch (err: any) {
            return "[签名失败] 生成 keystore 失败: " + err.message;
          }
        }

        // 优先使用 apksigner（支持 v2 签名）
        if (isToolInstalled("apksigner")) {
          try {
            child_process.execSync(
              'apksigner sign --ks "' + ks + '" --ks-pass pass:flagent123 --key-pass pass:flagent123 "' + targetApk + '"',
              { timeout: 30000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
            );
            // 验证签名
            let verify = "OK";
            try {
              verify = child_process.execSync(
                'apksigner verify "' + targetApk + '"',
                { timeout: 30000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
              ).trim() || "OK";
            } catch {}
            return "[签名成功] " + targetApk + "\n验证: " + verify + "\n(使用 apksigner v2 签名)";
          } catch (err: any) {
            return "[签名失败] " + err.message;
          }
        }

        // 降级使用 jarsigner（仅 v1 签名）
        try {
          child_process.execSync(
            'jarsigner -keystore "' + ks + '" -storepass flagent123 "' + targetApk + '" flagent',
            { timeout: 30000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
          );
          return "[签名成功] " + targetApk + "\n(使用 jarsigner v1 签名，建议用 apksigner 进行 v2 签名)";
        } catch (err: any) {
          return "[签名失败] " + err.message;
        }
      }

      return "❌ 未知 action: " + action;
    },
  });

  // === 4. Frida 动态 Hook ===
  registry.register({
    name: "frida_hook",
    description: "Frida 动态 Hook：执行 Frida JS 脚本对目标应用进行运行时 hook",
    parameters: z.object({
      script_path: z.string().describe("Frida JS 脚本路径"),
      target: z.string().describe("目标应用包名或 PID"),
      device: z.enum(["local", "usb"]).optional().describe("设备类型，默认 local"),
      spawn: z.boolean().optional().describe("是否 spawn 模式启动（启动新进程），默认 false"),
      timeout_sec: z.number().optional().describe("hook 运行时长（秒），5-120，默认 30"),
    }),
    category: "mobile",
    requirePermission: true,
    execute: async (args: any) => {
      const { script_path, target, device = "local", spawn = false, timeout_sec = 30 } = args;

      // 参数校验：超时范围 5-120
      const clampedTimeout = Math.max(5, Math.min(120, Number(timeout_sec) || 30));

      if (!fs.existsSync(script_path)) {
        return "❌ 文件不存在: " + script_path;
      }

      // 检查 frida 是否安装（frida --version）
      let fridaVersion = "";
      try {
        fridaVersion = child_process.execSync("frida --version", {
          timeout: 10000,
          maxBuffer: 1024 * 1024,
          encoding: "utf-8",
        }).trim();
      } catch (err: any) {
        return "❌ frida 未安装或不可用\n安装: pip install frida-tools\n或: brew install frida\n错误: " + err.message;
      }

      const os = require("os");
      const path = require("path");
      const tmpLog = path.join(os.tmpdir(), "flagent-frida-" + Date.now() + ".log");

      // 构造 frida 命令
      let cmd = "frida";
      if (device === "usb") cmd += " -U";
      cmd += ' -l "' + script_path + '"';
      if (spawn) {
        // spawn 模式：-f <package>
        cmd += ' -f "' + target + '"';
      } else {
        // attach 模式：<pid>
        cmd += ' "' + target + '"';
      }
      // 非交互：stdin 重定向到 /dev/null，输出重定向到日志文件
      cmd += ' < /dev/null > "' + tmpLog + '" 2>&1';

      const sections: string[] = [];
      sections.push("[Frida Hook]");
      sections.push("frida 版本: " + fridaVersion);
      sections.push("脚本: " + script_path);
      sections.push("目标: " + target + (spawn ? " (spawn 模式)" : " (attach 模式)"));
      sections.push("设备: " + device);
      sections.push("超时: " + clampedTimeout + "s");
      sections.push("");

      try {
        child_process.execSync(cmd, {
          timeout: clampedTimeout * 1000,
          maxBuffer: 1024 * 1024,
          encoding: "utf-8",
        });
      } catch (err: any) {
        // frida 通常是长驻进程，超时退出属正常行为
        if (err.killed || err.signal === "SIGTERM" || err.status === null) {
          sections.push("(进程在 " + clampedTimeout + "s 后被终止，属正常行为)");
        } else {
          sections.push("[hook 执行异常] " + err.message);
        }
      }

      // 读取捕获的输出
      if (fs.existsSync(tmpLog)) {
        const output = fs.readFileSync(tmpLog, "utf-8");
        sections.push("[hook 输出]");
        sections.push(truncate(output, 10000));
        try { fs.unlinkSync(tmpLog); } catch {}
      } else {
        sections.push("(无输出)");
      }

      return sections.join("\n");
    },
  });

  // === 5. iOS IPA 分析 ===
  registry.register({
    name: "ipa_analysis",
    description: "iOS IPA 分析：解析 Mach-O 依赖、权限、Objective-C 类、关键字符串",
    parameters: z.object({
      ipa_path: z.string().describe("IPA 文件路径"),
      mode: z.enum(["info", "entitlements", "classes", "strings", "all"]).optional().describe("分析模式，默认 all"),
    }),
    category: "mobile",
    concurrent: true,
    execute: async (args: any) => {
      const { ipa_path, mode = "all" } = args;
      if (!fs.existsSync(ipa_path)) {
        return "❌ 文件不存在: " + ipa_path;
      }

      const os = require("os");
      const path = require("path");
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "flagent-ipa-"));

      const sections: string[] = [];
      sections.push("[iOS IPA 分析] " + ipa_path);

      try {
        // IPA 本质是 ZIP，先解压
        try {
          child_process.execSync(
            'unzip -o "' + ipa_path + '" -d "' + tmpDir + '"',
            { timeout: 60000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
          );
        } catch (err: any) {
          sections.push("[解压失败] " + err.message);
          return sections.join("\n");
        }

        // 查找 Payload/*.app 目录
        const payloadDir = path.join(tmpDir, "Payload");
        if (!fs.existsSync(payloadDir)) {
          sections.push("❌ 未找到 Payload 目录（可能不是有效的 IPA）");
          return sections.join("\n");
        }

        const appDirs = fs.readdirSync(payloadDir).filter((d: string) => d.endsWith(".app"));
        if (appDirs.length === 0) {
          sections.push("❌ Payload 目录下未找到 .app");
          return sections.join("\n");
        }

        const appDir = path.join(payloadDir, appDirs[0]);
        const appName = appDirs[0].replace(".app", "");
        let binaryPath = path.join(appDir, appName);

        // 如果标准路径不存在，查找 .app 目录中的可执行文件
        if (!fs.existsSync(binaryPath)) {
          const files = fs.readdirSync(appDir);
          for (const f of files) {
            const fp = path.join(appDir, f);
            try {
              const stat = fs.statSync(fp);
              if (stat.isFile() && (stat.mode & 0o111)) {
                binaryPath = fp;
                break;
              }
            } catch {}
          }
        }

        sections.push("应用: " + appName);
        sections.push("二进制: " + binaryPath);

        // --- info 模式：用 otool -L 分析 Mach-O 依赖库 ---
        if (mode === "info" || mode === "all") {
          sections.push("\n── Mach-O 依赖库（otool -L）──");
          try {
            if (fs.existsSync(binaryPath)) {
              const out = child_process.execSync(
                'otool -L "' + binaryPath + '"',
                { timeout: 30000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
              );
              sections.push(truncate(out, 6000));
            } else {
              sections.push("(二进制文件不存在)");
            }
          } catch (err: any) {
            sections.push("[otool 失败] " + err.message);
          }
        }

        // --- entitlements 模式：用 ldid -e 或 codesign -d --entitlements 提取权限 ---
        if (mode === "entitlements" || mode === "all") {
          sections.push("\n── 权限（Entitlements）──");
          let done = false;
          // 优先 ldid
          try {
            const out = child_process.execSync(
              'ldid -e "' + binaryPath + '"',
              { timeout: 30000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
            );
            if (out && out.trim()) {
              sections.push(truncate(out, 6000));
              done = true;
            }
          } catch {}
          // 降级 codesign
          if (!done) {
            try {
              const out = child_process.execSync(
                'codesign -d --entitlements - "' + binaryPath + '"',
                { timeout: 30000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
              );
              if (out && out.trim()) {
                sections.push(truncate(out, 6000));
                done = true;
              }
            } catch {}
          }
          if (!done) {
            sections.push("❌ ldid 和 codesign 均无法提取权限");
            sections.push("建议安装 ldid: brew install ldid");
          }
        }

        // --- classes 模式：用 class-dump 提取 Objective-C 类信息 ---
        if (mode === "classes" || mode === "all") {
          sections.push("\n── Objective-C 类（class-dump）──");
          try {
            const out = child_process.execSync(
              'class-dump "' + binaryPath + '"',
              { timeout: 30000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
            );
            // 提取 @interface 类定义
            const classMatches = out.match(/@interface\s+[\w:()<>]+\s*\n?/g);
            if (classMatches && classMatches.length) {
              const cleaned = classMatches.map((m) => m.trim().replace(/\s+/g, " "));
              sections.push("类数量: " + cleaned.length);
              sections.push("[类列表（前 40）]");
              sections.push(cleaned.slice(0, 40).join("\n"));
            } else {
              sections.push(truncate(out, 6000));
            }
          } catch (err: any) {
            sections.push("❌ class-dump 未安装或执行失败");
            sections.push("安装: brew install class-dump");
            sections.push("或从 https://github.com/nygard/class-dump 下载");
          }
        }

        // --- strings 模式：提取关键字符串（URL/API key/密码模式）---
        if (mode === "strings" || mode === "all") {
          sections.push("\n── 关键字符串（URL/API key/密码模式）──");
          try {
            const out = child_process.execSync(
              'strings "' + binaryPath + '"',
              { timeout: 30000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
            );
            const lines = out.split("\n");
            const patterns = [
              { re: /https?:\/\/[^\s"'<>]+/g, label: "URL" },
              { re: /[Aa]pi[_-]?[Kk]ey["'\s:=]+[A-Za-z0-9_\-]{16,}/g, label: "API Key" },
              { re: /[Pp]assword["'\s:=]+[^\s"']{4,}/g, label: "Password" },
              { re: /[Tt]oken["'\s:=]+[A-Za-z0-9_\-\.]{16,}/g, label: "Token" },
              { re: /[Ss]ecret["'\s:=]+[A-Za-z0-9_\-]{8,}/g, label: "Secret" },
            ];
            const found: Record<string, string[]> = {};
            for (const p of patterns) found[p.label] = [];
            for (const line of lines) {
              for (const p of patterns) {
                const m = line.match(p.re);
                if (m) {
                  for (const match of m) {
                    if (found[p.label].indexOf(match) === -1) {
                      found[p.label].push(match);
                    }
                  }
                }
              }
            }
            let anyFound = false;
            for (const label of Object.keys(found)) {
              const items = found[label].slice(0, 20);
              if (items.length) {
                anyFound = true;
                sections.push("\n[" + label + "] (" + items.length + ")");
                sections.push(items.join("\n"));
              }
            }
            if (!anyFound) {
              sections.push("(未找到关键字符串)");
            }
          } catch (err: any) {
            sections.push("[字符串提取失败] " + err.message);
          }
        }
      } finally {
        // 清理临时目录
        try {
          fs.rmSync(tmpDir, { recursive: true, force: true });
        } catch {}
      }

      return sections.join("\n");
    },
  });

  // === 6. SSL Pinning 绕过脚本生成 ===
  registry.register({
    name: "ssl_pinning_bypass",
    description: "SSL Pinning 绕过：生成 Frida/Objection 脚本或手动绕过说明",
    parameters: z.object({
      platform: z.enum(["android", "ios"]).optional().describe("目标平台，默认 android"),
      method: z.enum(["frida", "objection", "manual"]).optional().describe("绕过方法，默认 frida"),
      package: z.string().optional().describe("应用包名"),
      output_path: z.string().optional().describe("脚本输出路径，可选"),
    }),
    category: "mobile",
    concurrent: true,
    execute: async (args: any) => {
      const { platform = "android", method = "frida", package: pkg, output_path } = args;

      const sections: string[] = [];
      sections.push("[SSL Pinning 绕过]");
      sections.push("平台: " + platform);
      sections.push("方法: " + method);
      if (pkg) sections.push("包名: " + pkg);
      sections.push("");

      let scriptContent = "";

      if (method === "frida") {
        // 生成 Frida SSL Pinning Bypass 脚本（覆盖 OkHttp/TrustManager/Conscrypt）
        scriptContent = generateFridaSslBypass(platform);
        sections.push("=== Frida SSL Pinning Bypass 脚本 ===");
        sections.push(scriptContent);
        sections.push("");
        sections.push("=== 使用说明 ===");
        if (platform === "android") {
          sections.push("1. 确保 frida-server 在设备上运行:");
          sections.push('   adb shell "su -c \'/data/local/tmp/frida-server &\'"');
          sections.push("2. 执行 hook（spawn 模式）:");
          sections.push("   frida -U -l ssl_bypass.js -f " + (pkg || "<包名>"));
          sections.push("3. 或 attach 模式（attach 到已运行进程）:");
          sections.push("   frida -U -l ssl_bypass.js " + (pkg || "<包名>"));
          sections.push("4. 启动后用 Burp/mitmproxy 抓包验证");
        } else {
          sections.push("1. 确保 frida-server 在越狱设备上运行");
          sections.push("2. 执行 hook（spawn 模式）:");
          sections.push("   frida -U -l ssl_bypass.js -f " + (pkg || "<Bundle ID>"));
          sections.push("3. 启动后用 Burp/mitmproxy 抓包验证");
        }
      } else if (method === "objection") {
        // 生成 objection 命令
        sections.push("=== Objection 命令 ===");
        if (platform === "android") {
          sections.push("# 启动 objection（spawn 模式）");
          sections.push("objection -g " + (pkg || "<包名>") + " explore");
          sections.push("");
          sections.push("# 在 objection 交互界面中执行:");
          sections.push("android sslpinning disable");
          sections.push("");
          sections.push("# 或一行命令自动绕过:");
          sections.push('objection -g ' + (pkg || "<包名>") + ' explore --startup-command "android sslpinning disable"');
        } else {
          sections.push("# 启动 objection（iOS）");
          sections.push("objection -g " + (pkg || "<Bundle ID>") + " explore");
          sections.push("");
          sections.push("# 在 objection 交互界面中执行:");
          sections.push("ios sslpinning disable");
          sections.push("");
          sections.push("# 或一行命令自动绕过:");
          sections.push('objection -g ' + (pkg || "<Bundle ID>") + ' explore --startup-command "ios sslpinning disable"');
        }
        sections.push("");
        sections.push("=== 安装 ===");
        sections.push("pip install objection");
        sections.push("# 需要 frida 已安装并运行");
      } else {
        // manual：生成手动绕过步骤说明（Nethunter/mitmproxy 证书安装）
        sections.push("=== 手动绕过 SSL Pinning 步骤 ===");
        if (platform === "android") {
          sections.push("方法一：安装系统 CA 证书（需 root）");
          sections.push("1. 导出 Burp/mitmproxy CA 证书为 DER 格式");
          sections.push("2. 计算证书的 hash（用于文件名）:");
          sections.push("   openssl x509 -inform DER -in cert.der -out cacert.pem");
          sections.push("   openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1");
          sections.push("3. 重命名为 <hash>.0 并推送到设备:");
          sections.push("   adb push <hash>.0 /sdcard/");
          sections.push('   adb shell su -c "cp /sdcard/<hash>.0 /system/etc/security/cacerts/"');
          sections.push("4. 重启设备");
          sections.push("");
          sections.push("方法二：使用 Magisk + MagiskTrustUserCerts 模块");
          sections.push("1. 安装 Magisk（需 root）");
          sections.push("2. 安装 MagiskTrustUserCerts 模块");
          sections.push("3. 将 CA 证书安装为用户证书，重启后自动提升为系统证书");
          sections.push("");
          sections.push("方法三：Nethunter / Kali Nethunter");
          sections.push("1. 安装 Nethunter");
          sections.push("2. 使用 Nethunter 的 MITM 工具自动安装证书");
        } else {
          sections.push("方法一：安装 CA 证书到设备");
          sections.push("1. 导出 Burp/mitmproxy CA 证书为 .crt/.cer 格式");
          sections.push("2. 通过 AirDrop / 邮件 / Safari 推送到 iOS 设备");
          sections.push("3. 设置 → 通用 → 描述文件与设备管理 → 安装证书");
          sections.push("4. 设置 → 通用 → 关于本机 → 证书信任设置 → 启用完全信任");
          sections.push("");
          sections.push("方法二：越狱设备使用 SSL Kill Switch 2");
          sections.push("1. 越狱设备（如使用 unc0ver / palera1n）");
          sections.push("2. 安装 SSL Kill Switch 2（Cydia/Sileo）");
          sections.push("3. 在 SSL Kill Switch 2 中启用对目标 App 的绕过");
          sections.push("");
          sections.push("方法三：mitmproxy + 证书安装");
          sections.push("1. 运行 mitmproxy");
          sections.push("2. iOS 设备设置代理指向 mitmproxy");
          sections.push("3. 访问 mitm.it 安装证书");
          sections.push("4. 信任证书（同方法一步骤 4）");
        }
        sections.push("");
        sections.push("注意: 部分 App 实施证书固定（Certificate Pinning），");
        sections.push("仅安装 CA 证书无法绕过，需配合 Frida/objection 或修改 App 代码。");
      }

      // 如果指定了输出路径，写入文件（仅 frida 模式生成脚本文件）
      if (output_path && method === "frida") {
        try {
          fs.writeFileSync(output_path, scriptContent, "utf-8");
          sections.push("");
          sections.push("[脚本已保存] " + output_path);
        } catch (err: any) {
          sections.push("[保存失败] " + err.message);
        }
      }

      return sections.join("\n");
    },
  });

  return registry;
}

// === 辅助函数 ===

/** 检查系统命令是否已安装（which <tool>） */
function isToolInstalled(tool: string): boolean {
  try {
    child_process.execSync("which " + tool, {
      timeout: 5000,
      maxBuffer: 1024 * 1024,
      encoding: "utf-8",
      stdio: "pipe",
    });
    return true;
  } catch {
    return false;
  }
}

/** 截断文本到指定长度 */
function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen) + "\n... (已截断，共 " + text.length + " 字符)";
}

/** 递归列出目录下所有 .smali 文件 */
function listSmaliFiles(dir: string): string[] {
  const path = require("path");
  const results: string[] = [];
  function walk(d: string) {
    try {
      const entries = fs.readdirSync(d, { withFileTypes: true });
      for (const e of entries) {
        const full = path.join(d, e.name);
        if (e.isDirectory()) {
          walk(full);
        } else if (e.name.endsWith(".smali")) {
          results.push(full);
        }
      }
    } catch {}
  }
  walk(dir);
  return results;
}

/** 递归列出目录下所有 .java 文件 */
function listJavaFiles(dir: string): string[] {
  const path = require("path");
  const results: string[] = [];
  function walk(d: string) {
    try {
      const entries = fs.readdirSync(d, { withFileTypes: true });
      for (const e of entries) {
        const full = path.join(d, e.name);
        if (e.isDirectory()) {
          walk(full);
        } else if (e.name.endsWith(".java")) {
          results.push(full);
        }
      }
    } catch {}
  }
  walk(dir);
  return results;
}

/** 递归查找目录下指定文件名的文件 */
function findFileRecursive(dir: string, fileName: string): string[] {
  const path = require("path");
  const results: string[] = [];
  function walk(d: string) {
    try {
      const entries = fs.readdirSync(d, { withFileTypes: true });
      for (const e of entries) {
        const full = path.join(d, e.name);
        if (e.isDirectory()) {
          walk(full);
        } else if (e.name === fileName) {
          results.push(full);
        }
      }
    } catch {}
  }
  walk(dir);
  return results;
}

/** 生成 Frida SSL Pinning Bypass 脚本（覆盖 OkHttp/TrustManager/Conscrypt） */
function generateFridaSslBypass(platform: string): string {
  if (platform === "ios") {
    return [
      "/*",
      " * Frida SSL Pinning Bypass - iOS",
      " * 覆盖 NSURLSession / SecTrustEvaluate / AFNetworking",
      " */",
      "",
      "// === 1. 替换 SecTrustEvaluate（信任所有证书）===",
      "try {",
      "    var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');",
      "    if (SecTrustEvaluate) {",
      "        Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, result) {",
      "            console.log('[+] SecTrustEvaluate 已绕过');",
      "            Memory.writeUInt(result, 4, 4); // kSecTrustResultProceed",
      "            return 0; // errSecSuccess",
      "        }, 'int', ['pointer', 'pointer']));",
      "    }",
      "} catch (e) {",
      "    console.log('[-] SecTrustEvaluate hook 失败: ' + e);",
      "}",
      "",
      "// === 2. 替换 SecTrustEvaluateForDomain ===",
      "try {",
      "    var SecTrustEvaluateForDomain = Module.findExportByName('Security', 'SecTrustEvaluateForDomain');",
      "    if (SecTrustEvaluateForDomain) {",
      "        Interceptor.replace(SecTrustEvaluateForDomain, new NativeCallback(function (trust, domain, result) {",
      "            console.log('[+] SecTrustEvaluateForDomain 已绕过: ' + (domain ? Memory.readCString(domain) : '(null)'));",
      "            Memory.writeUInt(result, 4, 4); // kSecTrustResultProceed",
      "            return 0;",
      "        }, 'int', ['pointer', 'pointer', 'pointer']));",
      "    }",
      "} catch (e) {",
      "    console.log('[-] SecTrustEvaluateForDomain hook 失败: ' + e);",
      "}",
      "",
      "// === 3. AFNetworking AFSecurityPolicy ===",
      "try {",
      "    var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;",
      "    if (AFSecurityPolicy) {",
      "        var setPinningMode = AFSecurityPolicy['- setSSLPinningMode:'];",
      "        if (setPinningMode) {",
      "            Interceptor.attach(setPinningMode.implementation, {",
      "                onEnter: function (args) {",
      "                    args[2] = ptr(0); // AFSSLPinningModeNone",
      "                    console.log('[+] AFSecurityPolicy SSL Pinning 已禁用');",
      "                }",
      "            });",
      "        }",
      "        // 绕过 evaluateServerTrust",
      "        var evalTrust = AFSecurityPolicy['- evaluateServerTrust:forDomain:'];",
      "        if (evalTrust) {",
      "            Interceptor.replace(evalTrust.implementation, new NativeCallback(function (self, sel, trust, domain) {",
      "                console.log('[+] AFSecurityPolicy.evaluateServerTrust 已绕过');",
      "                return 1; // YES",
      "            }, 'bool', ['pointer', 'pointer', 'pointer', 'pointer']));",
      "        }",
      "    }",
      "} catch (e) {",
      "    console.log('[-] AFSecurityPolicy hook 失败: ' + e);",
      "}",
      "",
      "console.log('[*] iOS SSL Pinning Bypass 注入完成');",
    ].join("\n");
  }

  // Android: 覆盖 OkHttp / TrustManager / Conscrypt
  return [
    "/*",
    " * Frida SSL Pinning Bypass - Android",
    " * 覆盖 OkHttp / TrustManager / Conscrypt",
    " */",
    "Java.perform(function () {",
    "    console.log('[*] SSL Pinning Bypass 已加载');",
    "",
    "    // === 1. 信任所有证书的 TrustManager ===",
    "    try {",
    "        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');",
    "        var SSLContext = Java.use('javax.net.ssl.SSLContext');",
    "",
    "        var TrustManager = Java.registerClass({",
    "            name: 'org.flagent.TrustAllManager',",
    "            implements: [X509TrustManager],",
    "            methods: {",
    "                checkClientTrusted: function (chain, authType) {},",
    "                checkServerTrusted: function (chain, authType) {},",
    "                getAcceptedIssuers: function () { return []; }",
    "            }",
    "        });",
    "",
    "        var TrustManagers = [TrustManager.$new()];",
    "        SSLContext.init.overload(",
    "            '[Ljavax.net.ssl.KeyManager;',",
    "            '[Ljavax.net.ssl.TrustManager;',",
    "            'java.security.SecureRandom'",
    "        ).implementation = function (km, tm, sr) {",
    "            console.log('[+] SSLContext.init 已劫持，替换 TrustManager');",
    "            this.init(km, TrustManagers, sr);",
    "        };",
    "    } catch (e) {",
    "        console.log('[-] TrustManager hook 失败: ' + e);",
    "    }",
    "",
    "    // === 2. OkHttp3 CertificatePinner ===",
    "    try {",
    "        var CertificatePinner = Java.use('okhttp3.CertificatePinner');",
    "        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (host, peerCerts) {",
    "            console.log('[+] OkHttp3 CertificatePinner.check(List) 已绕过: ' + host);",
    "        };",
    "        CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (host, peerCerts) {",
    "            console.log('[+] OkHttp3 CertificatePinner.check(varargs) 已绕过: ' + host);",
    "        };",
    "        console.log('[+] OkHttp3 CertificatePinner 已 hook');",
    "    } catch (e) {",
    "        console.log('[-] OkHttp3 hook 失败: ' + e);",
    "    }",
    "",
    "    // === 3. OkHttp CertificatePinner (旧版) ===",
    "    try {",
    "        var CertificatePinnerOld = Java.use('com.squareup.okhttp.CertificatePinner');",
    "        CertificatePinnerOld.check.overload('java.lang.String', 'java.util.List').implementation = function (host, peerCerts) {",
    "            console.log('[+] OkHttp CertificatePinner.check 已绕过: ' + host);",
    "        };",
    "    } catch (e) {",
    "        // 旧版 OkHttp 不存在，忽略",
    "    }",
    "",
    "    // === 4. Conscrypt TrustManagerImpl ===",
    "    try {",
    "        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');",
    "        TrustManagerImpl.checkTrustedRecursive.implementation = function (a, b, c, d, e, f) {",
    "            console.log('[+] Conscrypt TrustManagerImpl.checkTrustedRecursive 已绕过');",
    "            return Java.use('java.util.ArrayList').$new();",
    "        };",
    "    } catch (e) {",
    "        console.log('[-] Conscrypt hook 失败: ' + e);",
    "    }",
    "",
    "    // === 5. HostnameVerifier ===",
    "    try {",
    "        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');",
    "        var HV = Java.registerClass({",
    "            name: 'org.flagent.TrustAllHV',",
    "            implements: [HostnameVerifier],",
    "            methods: {",
    "                verify: function (host, session) { return true; }",
    "            }",
    "        });",
    "        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');",
    "        HttpsURLConnection.setDefaultHostnameVerifier(HV.$new());",
    "        console.log('[+] HostnameVerifier 已替换');",
    "    } catch (e) {",
    "        console.log('[-] HostnameVerifier hook 失败: ' + e);",
    "    }",
    "",
    "    console.log('[*] SSL Pinning Bypass 注入完成');",
    "});",
  ].join("\n");
}
