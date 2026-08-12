import { z } from "zod";
import * as fs from "fs";
import * as child_process from "child_process";
import { ToolRegistry } from "./registry";

/**
 * 检查系统命令是否存在（通过 which）
 */
function commandExists(cmd: string): boolean {
  try {
    child_process.execSync(`which ${cmd} 2>/dev/null`, {
      encoding: "utf-8",
      timeout: 5000,
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * 执行系统命令，返回 stdout 字符串
 * 失败时抛出异常，由调用方 try-catch
 */
function runCmd(cmd: string, timeout = 30000): string {
  return child_process.execSync(cmd, {
    timeout,
    maxBuffer: 1024 * 1024,
    encoding: "utf-8",
  });
}

export function createForensicsTools(): ToolRegistry {
  const registry = new ToolRegistry();

  // 1. 磁盘镜像取证分析
  registry.register({
    name: "disk_forensics",
    description: "磁盘镜像取证分析：识别镜像类型、列出分区表、列出已删除文件、数据雕刻恢复",
    parameters: z.object({
      image_path: z.string().describe("镜像文件路径"),
      mode: z
        .enum(["info", "partition", "deleted", "carve"])
        .default("info")
        .describe("分析模式：info=镜像类型与分区表, partition=分区详情, deleted=已删除文件, carve=数据雕刻恢复"),
    }),
    category: "forensics",
    concurrent: true,
    execute: async (args: any) => {
      const { image_path, mode } = args;
      if (!fs.existsSync(image_path)) return `❌ 文件不存在: ${image_path}`;

      const out: string[] = [`[磁盘取证分析] ${image_path}\n模式: ${mode}\n`];

      try {
        if (mode === "info") {
          // 用 file 命令识别镜像类型
          try {
            const fileType = runCmd(`file "${image_path}"`).trim();
            out.push(`── 镜像类型识别 ──\n${fileType}\n`);
          } catch (err: any) {
            out.push(`── 镜像类型识别失败 ──\n${err.message}\n`);
          }

          // 用 mmls 或 fdisk -l 列出分区表
          if (commandExists("mmls")) {
            try {
              const mmls = runCmd(`mmls "${image_path}"`);
              out.push(`── 分区表 (mmls) ──\n${mmls}`);
            } catch (err: any) {
              out.push(`── mmls 读取失败 ──\n${err.message}`);
            }
          } else if (commandExists("fdisk")) {
            try {
              const fdisk = runCmd(`fdisk -l "${image_path}"`);
              out.push(`── 分区表 (fdisk) ──\n${fdisk}`);
            } catch (err: any) {
              out.push(`── fdisk 读取失败 ──\n${err.message}`);
            }
          } else {
            out.push(
              `⚠️  未找到分区表分析工具。\n` +
              `  建议安装 sleuthkit（提供 mmls/fls/icat 等工具）：\n` +
              `  macOS: brew install sleuthkit\n` +
              `  Ubuntu/Debian: sudo apt install sleuthkit\n` +
              `  RHEL/CentOS: sudo yum install sleuthkit`
            );
          }
        } else if (mode === "partition") {
          // 列出分区详细信息（类型/大小/偏移）
          if (commandExists("mmls")) {
            try {
              const mmls = runCmd(`mmls -t auto "${image_path}"`);
              out.push(`── 分区详细信息 (mmls) ──\n${mmls}`);
            } catch (err: any) {
              out.push(`── mmls 失败 ──\n${err.message}`);
            }
          } else if (commandExists("fdisk")) {
            try {
              const fdisk = runCmd(`fdisk -l -u "${image_path}"`);
              out.push(`── 分区详细信息 (fdisk) ──\n${fdisk}`);
            } catch (err: any) {
              out.push(`── fdisk 失败 ──\n${err.message}`);
            }
          } else {
            out.push(
              `⚠️  未找到分区分析工具。\n` +
              `  建议安装 sleuthkit：\n` +
              `  macOS: brew install sleuthkit\n` +
              `  Ubuntu/Debian: sudo apt install sleuthkit`
            );
          }
        } else if (mode === "deleted") {
          // 用 fls (sleuthkit) 列出已删除文件
          if (!commandExists("fls")) {
            return (
              `⚠️  系统未安装 fls（属于 sleuthkit 工具包）。\n` +
              `  macOS: brew install sleuthkit\n` +
              `  Ubuntu/Debian: sudo apt install sleuthkit\n` +
              `  RHEL/CentOS: sudo yum install sleuthkit`
            );
          }
          try {
            // fls -r 递归列出，-d 只显示已删除文件
            const fls = runCmd(`fls -r -d "${image_path}"`);
            out.push(`── 已删除文件列表 (fls -r -d) ──\n${fls || "(未发现已删除文件)"}`);
          } catch (err: any) {
            out.push(`── fls 失败 ──\n${err.message}`);
          }
        } else if (mode === "carve") {
          // 用 foremost 或 scalpel 恢复文件
          if (commandExists("foremost")) {
            try {
              const outputDir = `/tmp/foremost_${Date.now()}`;
              const result = runCmd(`foremost -i "${image_path}" -o "${outputDir}"`);
              out.push(`── 数据雕刻恢复 (foremost) ──\n输出目录: ${outputDir}\n${result || "恢复完成"}`);
            } catch (err: any) {
              out.push(`── foremost 失败 ──\n${err.message}`);
            }
          } else if (commandExists("scalpel")) {
            try {
              const outputDir = `/tmp/scalpel_${Date.now()}`;
              const result = runCmd(`scalpel -c /etc/scalpel/scalpel.conf -o "${outputDir}" "${image_path}"`);
              out.push(`── 数据雕刻恢复 (scalpel) ──\n输出目录: ${outputDir}\n${result || "恢复完成"}`);
            } catch (err: any) {
              out.push(`── scalpel 失败 ──\n${err.message}`);
            }
          } else {
            out.push(
              `⚠️  未找到数据雕刻工具。\n` +
              `  建议安装 foremost 或 scalpel：\n` +
              `  macOS: brew install foremost\n` +
              `  Ubuntu/Debian: sudo apt install foremost scalpel\n` +
              `  RHEL/CentOS: sudo yum install foremost`
            );
          }
        }
      } catch (err: any) {
        out.push(`\n❌ 分析失败: ${err.message}`);
      }

      return out.join("\n");
    },
  });

  // 2. 文件系统分析
  registry.register({
    name: "filesystem_analyze",
    description: "文件系统分析：支持 NTFS/EXT4/FAT32/APFS 文件系统结构分析，提取 inode/journal/MFT 等信息",
    parameters: z.object({
      path: z.string().describe("镜像或设备路径"),
      fs_type: z
        .enum(["ntfs", "ext4", "fat32", "apfs", "auto"])
        .default("auto")
        .describe("文件系统类型，auto=自动检测"),
      partition_offset: z.number().optional().describe("分区字节偏移，默认 0"),
    }),
    category: "forensics",
    concurrent: true,
    execute: async (args: any) => {
      const { path, fs_type, partition_offset = 0 } = args;
      if (!fs.existsSync(path)) return `❌ 文件不存在: ${path}`;

      const out: string[] = [`[文件系统分析] ${path}\n指定类型: ${fs_type}\n偏移: ${partition_offset}\n`];
      let detectedType = fs_type;

      try {
        // auto 模式：先用 blkid 或 fsstat 检测文件系统类型
        if (fs_type === "auto") {
          if (commandExists("blkid")) {
            try {
              const blkid = runCmd(`blkid "${path}"`);
              out.push(`── 文件系统检测 (blkid) ──\n${blkid}\n`);
              // 尝试从 blkid 输出中提取类型
              if (/ntfs/i.test(blkid)) detectedType = "ntfs";
              else if (/ext4/i.test(blkid)) detectedType = "ext4";
              else if (/vfat|fat32/i.test(blkid)) detectedType = "fat32";
              else if (/apfs/i.test(blkid)) detectedType = "apfs";
            } catch (err: any) {
              out.push(`── blkid 检测失败 ──\n${err.message}\n`);
            }
          } else if (commandExists("fsstat")) {
            try {
              const offsetArg = partition_offset ? `-o ${partition_offset}` : "";
              const fsstat = runCmd(`fsstat ${offsetArg} "${path}"`);
              out.push(`── 文件系统检测 (fsstat) ──\n${fsstat.slice(0, 2000)}\n`);
              if (/ntfs/i.test(fsstat)) detectedType = "ntfs";
              else if (/ext/i.test(fsstat)) detectedType = "ext4";
              else if (/fat/i.test(fsstat)) detectedType = "fat32";
              else if (/apfs/i.test(fsstat)) detectedType = "apfs";
            } catch (err: any) {
              out.push(`── fsstat 检测失败 ──\n${err.message}\n`);
            }
          } else {
            out.push(
              `⚠️  未找到文件系统检测工具（blkid/fsstat）。\n` +
              `  建议安装 sleuthkit：\n` +
              `  macOS: brew install sleuthkit\n` +
              `  Ubuntu/Debian: sudo apt install sleuthkit\n`
            );
          }
          out.push(`检测结果: ${detectedType}\n`);
        }

        const offsetArg = partition_offset ? `-o ${partition_offset}` : "";

        // 根据文件系统类型进行分析
        if (detectedType === "ntfs") {
          // 用 mftdump 或 icat 分析 MFT 记录
          if (commandExists("mftdump")) {
            try {
              const mftdump = runCmd(`mftdump ${offsetArg} "${path}"`);
              out.push(`── MFT 记录 (mftdump) ──\n${mftdump.slice(0, 4000)}`);
            } catch (err: any) {
              out.push(`── mftdump 失败 ──\n${err.message}`);
            }
          } else if (commandExists("fsstat")) {
            try {
              const fsstat = runCmd(`fsstat ${offsetArg} -f ntfs "${path}"`);
              out.push(`── NTFS 文件系统信息 (fsstat) ──\n${fsstat.slice(0, 4000)}`);
            } catch (err: any) {
              out.push(`── fsstat 失败 ──\n${err.message}`);
            }
          } else {
            out.push(`⚠️  未找到 NTFS 分析工具，建议安装 sleuthkit (mftdump/fsstat)`);
          }
        } else if (detectedType === "ext4") {
          // 用 dumpe2fs 分析 inode/journal
          if (commandExists("dumpe2fs")) {
            try {
              const dumpe2fs = runCmd(`dumpe2fs "${path}"`);
              out.push(`── EXT4 文件系统信息 (dumpe2fs) ──\n${dumpe2fs.slice(0, 4000)}`);
            } catch (err: any) {
              out.push(`── dumpe2fs 失败 ──\n${err.message}`);
            }
          } else {
            out.push(
              `⚠️  未找到 dumpe2fs 工具。\n` +
              `  macOS: brew install e2fsprogs\n` +
              `  Ubuntu/Debian: sudo apt install e2fsprogs`
            );
          }
        } else if (detectedType === "fat32") {
          // 用 fsck.fat 分析 FAT 表
          if (commandExists("fsck.fat") || commandExists("fsck.vfat")) {
            const fsckCmd = commandExists("fsck.fat") ? "fsck.fat" : "fsck.vfat";
            try {
              const fsck = runCmd(`${fsckCmd} -v -n "${path}"`);
              out.push(`── FAT32 文件系统信息 (${fsckCmd}) ──\n${fsck.slice(0, 4000)}`);
            } catch (err: any) {
              out.push(`── ${fsckCmd} 失败 ──\n${err.message}`);
            }
          } else {
            out.push(
              `⚠️  未找到 fsck.fat 工具。\n` +
              `  Ubuntu/Debian: sudo apt install dosfstools\n` +
              `  macOS: brew install dosfstools`
            );
          }
        } else if (detectedType === "apfs") {
          // APFS 分析
          if (commandExists("fsstat")) {
            try {
              const fsstat = runCmd(`fsstat ${offsetArg} "${path}"`);
              out.push(`── APFS 文件系统信息 (fsstat) ──\n${fsstat.slice(0, 4000)}`);
            } catch (err: any) {
              out.push(`── fsstat 失败 ──\n${err.message}`);
            }
          } else {
            out.push(
              `⚠️  APFS 分析需要 sleuthkit 或专用工具。\n` +
              `  macOS: brew install sleuthkit\n` +
              `  也可使用 apfs-fuse / libapfs 等工具`
            );
          }
        } else {
          out.push(`⚠️  无法确定文件系统类型，请手动指定 fs_type 参数`);
        }
      } catch (err: any) {
        out.push(`\n❌ 分析失败: ${err.message}`);
      }

      return out.join("\n");
    },
  });

  // 3. Windows 注册表分析
  registry.register({
    name: "registry_analyze",
    description: "Windows 注册表 hive 文件分析：提取用户账户、自启动项、USB 设备记录、网络配置",
    parameters: z.object({
      hive_path: z.string().describe("注册表 hive 文件路径"),
      mode: z
        .enum(["users", "autorun", "usb", "network", "all"])
        .default("all")
        .describe("分析模式：users=用户账户, autorun=自启动项, usb=USB设备, network=网络配置, all=全部"),
    }),
    category: "forensics",
    concurrent: true,
    execute: async (args: any) => {
      const { hive_path, mode } = args;
      if (!fs.existsSync(hive_path)) return `❌ 文件不存在: ${hive_path}`;

      const out: string[] = [`[注册表分析] ${hive_path}\n模式: ${mode}\n`];

      // 检查工具是否存在
      const hasReglookup = commandExists("reglookup");
      const hasHivexsh = commandExists("hivexsh");

      if (!hasReglookup && !hasHivexsh) {
        return (
          `⚠️  系统未安装注册表分析工具。\n` +
          `  建议安装 reglookup 或 hivex：\n` +
          `  Ubuntu/Debian: sudo apt install reglookup hive-utils\n` +
          `  macOS: brew install reglookup hivex\n` +
          `  RHEL/CentOS: sudo yum install reglookup hivex`
        );
      }

      // 注册表路径常量（适用于 SAM/SYSTEM/SOFTWARE/NTUSER.DAT 等 hive）
      const registryPaths: Record<string, string[]> = {
        users: [
          "SAM\\Domains\\Account\\Users",
          "SAM\\Domains\\Account\\Users\\Names",
        ],
        autorun: [
          "Microsoft\\Windows\\CurrentVersion\\Run",
          "Microsoft\\Windows\\CurrentVersion\\RunOnce",
          "Microsoft\\Windows\\CurrentVersion\\Services",
          "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        ],
        usb: [
          "Microsoft\\Windows\\CurrentVersion\\USBSTOR",
          "MountedDevices",
          "System\\CurrentControlSet\\Enum\\USBSTOR",
        ],
        network: [
          "Microsoft\\Windows NT\\CurrentVersion\\NetworkList",
          "System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
          "System\\CurrentControlSet\\Services\\Tcpip\\Parameters",
        ],
      };

      const modesToRun = mode === "all" ? ["users", "autorun", "usb", "network"] : [mode];

      try {
        for (const m of modesToRun) {
          out.push(`\n── ${m.toUpperCase()} 分析 ──`);

          if (hasReglookup) {
            // reglookup 递归导出整个 hive，然后过滤相关路径
            try {
              const fullPath = runCmd(`reglookup "${hive_path}"`);
              const paths = registryPaths[m] || [];
              const filtered = fullPath
                .split("\n")
                .filter((line) => {
                  // reglookup 输出格式: PATH,TYPE,VALUE,DATA
                  return paths.some((p) => {
                    const normP = p.replace(/\\/g, "/").toLowerCase();
                    const normLine = line.toLowerCase();
                    return normLine.includes(normP) || normLine.includes(p.toLowerCase());
                  });
                })
                .join("\n");
              out.push(filtered || `  (未找到 ${m} 相关注册表项)`);
            } catch (err: any) {
              out.push(`  reglookup 失败: ${err.message}`);
            }
          } else if (hasHivexsh) {
            // 用 hivexsh 逐个路径查询
            const paths = registryPaths[m] || [];
            for (const regPath of paths) {
              try {
                // hivexsh 通过 stdin 接受命令
                const hivexCmd = `cd '${regPath}'\\nlsval\\n`;
                const result = runCmd(`echo -e '${hivexCmd}' | hivexsh "${hive_path}"`);
                out.push(`  [${regPath}]\n${result || "  (空)"}`);
              } catch (err: any) {
                out.push(`  [${regPath}] 查询失败: ${err.message}`);
              }
            }
          }
        }
      } catch (err: any) {
        out.push(`\n❌ 分析失败: ${err.message}`);
      }

      return out.join("\n");
    },
  });

  // 4. 系统日志取证
  registry.register({
    name: "log_forensics",
    description: "系统日志取证分析：检测登录失败/成功、特权提升、异常IP、Web攻击特征（SQL注入/XSS/路径遍历）",
    parameters: z.object({
      log_path: z.string().describe("日志文件路径"),
      log_type: z
        .enum(["syslog", "apache", "nginx", "auth", "windows_evt", "auto"])
        .default("auto")
        .describe("日志类型，auto=自动检测"),
      filter: z.string().optional().describe("关键词过滤"),
      max_lines: z
        .number()
        .min(50)
        .max(5000)
        .default(200)
        .describe("最大返回行数 (50-5000)，默认 200"),
    }),
    category: "forensics",
    concurrent: true,
    execute: async (args: any) => {
      const { log_path, log_type, filter, max_lines } = args;
      if (!fs.existsSync(log_path)) return `❌ 文件不存在: ${log_path}`;

      const out: string[] = [`[日志取证分析] ${log_path}\n类型: ${log_type}\n`];

      try {
        let logContent = "";
        let detectedType = log_type;

        // windows_evt 需要用 evtx_dump 解析
        if (log_type === "windows_evt") {
          if (commandExists("evtx_dump")) {
            try {
              logContent = runCmd(`evtx_dump "${log_path}"`, 60000);
              out.push(`── 使用 evtx_dump 解析 ──\n`);
            } catch (err: any) {
              out.push(`── evtx_dump 失败 ──\n${err.message}`);
              // 尝试 python-evtx
              if (commandExists("python3")) {
                try {
                  logContent = runCmd(
                    `python3 -c "import Evtx.Evtx as evtx; r=evtx.Evtx('${log_path}'); [print(r.record(i).xml()) for i in range(len(r.records()))]" 2>/dev/null`,
                    60000
                  );
                  out.push(`── 使用 python-evtx 解析 ──\n`);
                } catch (err2: any) {
                  out.push(`── python-evtx 也失败 ──\n${err2.message}`);
                  return out.join("\n");
                }
              } else {
                return out.join("\n");
              }
            }
          } else if (commandExists("python3")) {
            try {
              logContent = runCmd(
                `python3 -c "import Evtx.Evtx as evtx; r=evtx.Evtx('${log_path}'); [print(r.record(i).xml()) for i in range(len(r.records()))]" 2>/dev/null`,
                60000
              );
              out.push(`── 使用 python-evtx 解析 ──\n`);
            } catch (err: any) {
              out.push(
                `── 解析失败 ──\n${err.message}\n` +
                `  建议安装 evtx_dump 或 python-evtx：\n` +
                `  pip install python-evtx\n` +
                `  或安装 libevtx 工具包`
              );
              return out.join("\n");
            }
          } else {
            return (
              `⚠️  系统未安装 Windows EVT 解析工具。\n` +
              `  建议安装：\n` +
              `  pip install python-evtx\n` +
              `  或 macOS: brew install libevtx`
            );
          }
        } else {
          // 读取日志文件
          logContent = fs.readFileSync(log_path, "utf-8");
        }

        // auto 模式：检测日志类型
        if (log_type === "auto") {
          const sample = logContent.slice(0, 2000);
          if (/apache|httpd|GET .* HTTP\/|POST .* HTTP\//i.test(sample)) {
            detectedType = "apache";
          } else if (/nginx/i.test(sample)) {
            detectedType = "nginx";
          } else if (/sshd|Failed password|Accepted password|session opened/i.test(sample)) {
            detectedType = "auth";
          } else if (/syslog|rsyslog|daemon/i.test(sample)) {
            detectedType = "syslog";
          } else {
            detectedType = "syslog"; // 默认
          }
          out.push(`检测结果: ${detectedType}\n`);
        }

        // 关键词过滤
        let lines = logContent.split("\n");
        if (filter) {
          lines = lines.filter((l) => l.includes(filter));
          out.push(`── 关键词过滤: "${filter}" (${lines.length} 行匹配) ──\n`);
        }

        // 可疑活动检测
        const suspicious: string[] = [];
        const suspiciousPatterns: Array<{ pattern: RegExp; type: string }> = [
          // 登录失败/成功
          { pattern: /Failed password|authentication failure|login failed/i, type: "登录失败" },
          { pattern: /Accepted password|session opened|Login Successful/i, type: "登录成功" },
          // 特权提升
          { pattern: /sudo.*COMMAND|su:\s.*root|sudo:.*root/i, type: "特权提升" },
          { pattern: /privilege escalat|setuid|setgid/i, type: "特权提升" },
          // Web 攻击特征 - SQL 注入
          { pattern: /union.*select|or\s+1=1|'\s*or\s*'1'='1|information_schema|sleep\(|benchmark\(/i, type: "SQL注入" },
          // Web 攻击特征 - XSS
          { pattern: /<script|javascript:|onerror=|onload=|alert\(|document\.cookie/i, type: "XSS攻击" },
          // Web 攻击特征 - 路径遍历
          { pattern: /\.\.\/|\.\.\\|%2e%2e|%2f|etc\/passwd|etc\/shadow/i, type: "路径遍历" },
          // 其他可疑活动
          { pattern: /wget\s|curl\s|nc\s+-|netcat|reverse.*shell/i, type: "可疑命令" },
          { pattern: /19[0-9]\.|10\.0\.|172\.(1[6-9]|2[0-9]|3[01])\./i, type: "内网IP" },
        ];

        for (const line of lines) {
          for (const sp of suspiciousPatterns) {
            if (sp.pattern.test(line)) {
              suspicious.push(`  [${sp.type}] ${line.trim().slice(0, 200)}`);
              break; // 每行只记录一次
            }
          }
        }

        // 输出可疑事件摘要
        out.push(`── 可疑事件摘要 (${suspicious.length} 条) ──`);
        if (suspicious.length > 0) {
          out.push(suspicious.slice(0, Math.min(suspicious.length, 100)).join("\n"));
          if (suspicious.length > 100) {
            out.push(`... (共 ${suspicious.length} 条可疑事件，仅显示前 100 条)`);
          }
        } else {
          out.push("  (未检测到可疑事件)");
        }

        // 输出原始日志片段
        const displayLines = lines.slice(0, max_lines);
        out.push(`\n── 原始日志片段 (前 ${displayLines.length} 行) ──\n${displayLines.join("\n")}`);
        if (lines.length > max_lines) {
          out.push(`... (共 ${lines.length} 行，仅显示前 ${max_lines} 行)`);
        }
      } catch (err: any) {
        out.push(`\n❌ 分析失败: ${err.message}`);
      }

      return out.join("\n");
    },
  });

  // 5. 事件时间线重建
  registry.register({
    name: "timeline_reconstruct",
    description: "事件时间线重建：收集文件 MAC 时间和系统日志事件，按时间排序生成时间线",
    parameters: z.object({
      path: z.string().describe("目标路径（镜像文件、目录或日志文件）"),
      mode: z
        .enum(["mac", "log", "all"])
        .default("all")
        .describe("模式：mac=文件MAC时间, log=日志事件, all=全部合并"),
      start_time: z.string().optional().describe("起始时间（如 2024-01-01 或 2024-01-01 12:00:00）"),
      end_time: z.string().optional().describe("结束时间"),
    }),
    category: "forensics",
    concurrent: true,
    execute: async (args: any) => {
      const { path, mode, start_time, end_time } = args;
      if (!fs.existsSync(path)) return `❌ 文件不存在: ${path}`;

      const out: string[] = [`[时间线重建] ${path}\n模式: ${mode}\n`];
      const events: Array<{ time: string; source: string; desc: string }> = [];

      try {
        const stat = fs.statSync(path);

        // mode=mac 或 all：收集文件 MAC 时间
        if (mode === "mac" || mode === "all") {
          if (commandExists("fls") && stat.isFile()) {
            // 对镜像文件用 fls -m 收集 MAC 时间
            try {
              const bodyFile = runCmd(`fls -m / -r "${path}"`);
              // 用 mactime 转换为时间线
              if (commandExists("mactime")) {
                try {
                  const timeline = runCmd(`echo '${bodyFile.replace(/'/g, "'\\''")}' | mactime -b -`);
                  const tlLines = timeline.split("\n").filter((l) => l.trim());
                  for (const line of tlLines) {
                    events.push({ time: line.split(/\s+/).slice(0, 2).join(" "), source: "MAC", desc: line });
                  }
                } catch (err: any) {
                  out.push(`── mactime 转换失败 ──\n${err.message}`);
                  // 直接输出 body file
                  out.push(`── Body File (fls -m) ──\n${bodyFile.slice(0, 4000)}`);
                }
              } else {
                out.push(`── Body File (fls -m) ──\n${bodyFile.slice(0, 4000)}`);
                out.push(`⚠️  未安装 mactime，仅输出 body file。建议安装 sleuthkit。`);
              }
            } catch (err: any) {
              out.push(`── fls -m 失败 ──\n${err.message}`);
            }
          } else {
            // 对目录/文件用 find + stat 收集 MAC 时间
            try {
              if (stat.isDirectory()) {
                // macOS stat 格式: stat -f "%Sm %N" -t "%Y-%m-%d %H:%M:%S"
                const findResult = runCmd(
                  `find "${path}" -type f -exec stat -f "%Sm %N" -t "%Y-%m-%d %H:%M:%S" {} + 2>/dev/null`,
                  60000
                );
                const macLines = findResult.split("\n").filter((l) => l.trim());
                for (const line of macLines) {
                  const timePart = line.slice(0, 19);
                  events.push({ time: timePart, source: "MAC", desc: line });
                }
                out.push(`── 文件 MAC 时间 (find+stat) ──\n收集 ${macLines.length} 个文件时间`);
              } else {
                // 单个文件
                const statResult = runCmd(
                  `stat -f "修改时间: %Sm" -t "%Y-%m-%d %H:%M:%S" "${path}"`
                );
                events.push({ time: statResult.replace(/修改时间:\s*/, "").trim(), source: "MAC", desc: `${path} - ${statResult.trim()}` });
                out.push(`── 文件 MAC 时间 ──\n${statResult}`);
              }
            } catch (err: any) {
              out.push(`── MAC 时间收集失败 ──\n${err.message}`);
            }
          }
        }

        // mode=log 或 all：解析系统日志中的时间戳事件
        if (mode === "log" || mode === "all") {
          try {
            let logContent = "";
            if (stat.isDirectory()) {
              // 查找目录下的日志文件
              const findLogs = runCmd(`find "${path}" -type f \\( -name "*.log" -o -name "auth.log" -o -name "syslog" -o -name "messages" \\) 2>/dev/null`);
              const logFiles = findLogs.split("\n").filter((l) => l.trim());
              for (const logFile of logFiles.slice(0, 10)) {
                try {
                  logContent += fs.readFileSync(logFile.trim(), "utf-8") + "\n";
                } catch {}
              }
              out.push(`── 发现日志文件 ${logFiles.length} 个 ──`);
            } else {
              logContent = fs.readFileSync(path, "utf-8");
            }

            // 提取带时间戳的日志行
            const logLines = logContent.split("\n");
            const timePattern = /(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/;
            let logEventCount = 0;
            for (const line of logLines) {
              const match = line.match(timePattern);
              if (match) {
                events.push({ time: match[1], source: "LOG", desc: line.trim().slice(0, 200) });
                logEventCount++;
              }
            }
            out.push(`── 日志事件: 提取 ${logEventCount} 条带时间戳的记录 ──`);
          } catch (err: any) {
            out.push(`── 日志解析失败 ──\n${err.message}`);
          }
        }

        // 时间范围过滤
        let filteredEvents = events;
        if (start_time) {
          filteredEvents = filteredEvents.filter((e) => e.time >= start_time);
        }
        if (end_time) {
          filteredEvents = filteredEvents.filter((e) => e.time <= end_time);
        }

        // 按时间排序
        filteredEvents.sort((a, b) => a.time.localeCompare(b.time));

        // 输出时间线
        out.push(`\n── 时间线事件 (${filteredEvents.length} 条，按时间排序) ──`);
        const displayEvents = filteredEvents.slice(0, 500);
        for (const e of displayEvents) {
          out.push(`[${e.time}] [${e.source}] ${e.desc}`);
        }
        if (filteredEvents.length > 500) {
          out.push(`... (共 ${filteredEvents.length} 条事件，仅显示前 500 条)`);
        }
      } catch (err: any) {
        out.push(`\n❌ 时间线重建失败: ${err.message}`);
      }

      return out.join("\n");
    },
  });

  // 6. Volatility 3 内存取证插件
  registry.register({
    name: "volatility_plugin",
    description: "Volatility 3 内存取证：执行指定插件分析内存镜像（pslist/pstree/netscan/hashdump/malfind/cmdline/filescan/environ）",
    parameters: z.object({
      image_path: z.string().describe("内存镜像文件路径"),
      plugin: z
        .string()
        .describe("插件名：pslist/pstree/netscan/hashdump/malfind/cmdline/filescan/environ"),
      args: z.string().optional().describe("额外参数"),
    }),
    category: "forensics",
    requirePermission: true,
    execute: async (args: any) => {
      const { image_path, plugin, args: extraArgs } = args;
      if (!fs.existsSync(image_path)) return `❌ 文件不存在: ${image_path}`;

      const out: string[] = [`[Volatility 3 插件分析] ${image_path}\n插件: ${plugin}\n`];

      // 检查 volatility 是否安装
      let volCmd = "";
      if (commandExists("vol")) {
        volCmd = "vol";
      } else if (commandExists("vol.py")) {
        volCmd = "vol.py";
      } else {
        // 检查 python3 -m volatility
        try {
          child_process.execSync("python3 -m volatility --help 2>/dev/null", {
            encoding: "utf-8",
            timeout: 10000,
          });
          volCmd = "python3 -m volatility";
        } catch {
          // 未安装
        }
      }

      if (!volCmd) {
        return (
          `⚠️  系统未安装 Volatility 3。\n` +
          `  安装方式：\n` +
          `  pip install volatility3\n` +
          `  或从源码安装: git clone https://github.com/volatilityfoundation/volatility3.git\n` +
          `  安装后可用命令: vol / vol.py / python3 -m volatility\n` +
          `  使用示例: vol -f "${image_path}" ${plugin}`
        );
      }

      try {
        // 构造 volatility 命令
        const cmd = `${volCmd} -f "${image_path}" ${plugin}${extraArgs ? " " + extraArgs : ""}`;
        out.push(`执行命令: ${cmd}\n`);
        const result = runCmd(cmd, 120000);
        out.push(result || "(无输出)");
      } catch (err: any) {
        // execSync 错误对象包含 stdout/stderr
        const errMsg = err.message || "";
        const errStdout = err.stdout ? `\nSTDOUT:\n${err.stdout}` : "";
        const errStderr = err.stderr ? `\nSTDERR:\n${err.stderr}` : "";
        out.push(
          `❌ 插件执行失败: ${errMsg}${errStdout}${errStderr}\n\n` +
          `  常见原因：\n` +
          `  - 插件名错误，常见插件: pslist/pstree/netscan/hashdump/malfind/cmdline/filescan/environ\n` +
          `  - 内存镜像格式不支持，Volatility 3 支持 raw/lim/qemu/LILO 等格式\n` +
          `  - 缺少符号表(symbol tables)，尝试: vol -f "${image_path}" banners\n` +
          `  - Windows 镜像需要下载 symbol table 到 volatility3/symbols/windows/`
        );
      }

      return out.join("\n");
    },
  });

  // 7. PCAP 深度分析
  registry.register({
    name: "pcap_deep_analyze",
    description: "PCAP 网络抓包深度分析：协议分布统计、HTTP/DNS/FTP 提取、文件提取、明文凭据搜索",
    parameters: z.object({
      pcap_path: z.string().describe("PCAP 文件路径"),
      mode: z
        .enum(["overview", "http", "dns", "ftp", "extract", "credentials"])
        .default("overview")
        .describe("模式：overview=协议统计, http=HTTP请求, dns=DNS查询, ftp=FTP命令, extract=数据提取, credentials=凭据搜索"),
      filter: z.string().optional().describe("BPF 过滤表达式（如 \"tcp port 80\"）"),
      max_packets: z
        .number()
        .min(100)
        .max(10000)
        .default(500)
        .describe("最大分析数据包数 (100-10000)，默认 500"),
    }),
    category: "forensics",
    concurrent: true,
    execute: async (args: any) => {
      const { pcap_path, mode, filter, max_packets } = args;
      if (!fs.existsSync(pcap_path)) return `❌ 文件不存在: ${pcap_path}`;

      // 检查 tshark 是否安装
      if (!commandExists("tshark")) {
        return (
          `⚠️  系统未安装 tshark（属于 Wireshark 工具包）。\n` +
          `  macOS: brew install --cask wireshark\n` +
          `  Ubuntu/Debian: sudo apt install tshark\n` +
          `  RHEL/CentOS: sudo yum install wireshark`
        );
      }

      const out: string[] = [`[PCAP 深度分析] ${pcap_path}\n模式: ${mode}\n`];
      // 构建 BPF 过滤参数
      const filterArg = filter ? `-f "${filter}"` : "";
      // 限制数据包数量
      const maxPacketsArg = `-c ${max_packets}`;

      try {
        if (mode === "overview") {
          // 协议分布统计
          try {
            const stats = runCmd(`tshark -r "${pcap_path}" ${filterArg} -q -z io,stat,0`);
            out.push(`── 协议分布统计 ──\n${stats}`);
          } catch (err: any) {
            out.push(`── 统计失败 ──\n${err.message}`);
          }
          // 协议层级统计
          try {
            const phStats = runCmd(`tshark -r "${pcap_path}" ${filterArg} -q -z io,phs`);
            out.push(`\n── 协议层级统计 ──\n${phStats}`);
          } catch (err: any) {
            out.push(`── 协议层级统计失败 ──\n${err.message}`);
          }
          // 会话统计
          try {
            const convStats = runCmd(`tshark -r "${pcap_path}" ${filterArg} -q -z conv,tcp 2>/dev/null | head -30`);
            out.push(`\n── TCP 会话 (前30) ──\n${convStats}`);
          } catch (err: any) {
            // 非致命错误
          }
        } else if (mode === "http") {
          // 提取 HTTP 请求/响应
          try {
            const http = runCmd(
              `tshark -r "${pcap_path}" ${filterArg} ${maxPacketsArg} -Y "http" -T fields -e frame.number -e ip.src -e ip.dst -e http.request.method -e http.request.uri -e http.host -e http.response.code -e http.content_type 2>/dev/null`
            );
            out.push(`── HTTP 请求/响应 ──\n${http || "(无 HTTP 流量)"}`);
          } catch (err: any) {
            out.push(`── HTTP 提取失败 ──\n${err.message}`);
          }
        } else if (mode === "dns") {
          // 提取 DNS 查询
          try {
            const dns = runCmd(
              `tshark -r "${pcap_path}" ${filterArg} ${maxPacketsArg} -Y "dns" -T fields -e frame.number -e ip.src -e ip.dst -e dns.qry.name -e dns.qry.type -e dns.a 2>/dev/null`
            );
            out.push(`── DNS 查询 ──\n${dns || "(无 DNS 流量)"}`);
          } catch (err: any) {
            out.push(`── DNS 提取失败 ──\n${err.message}`);
          }
        } else if (mode === "ftp") {
          // 提取 FTP 命令和凭据
          try {
            const ftp = runCmd(
              `tshark -r "${pcap_path}" ${filterArg} ${maxPacketsArg} -Y "ftp" -T fields -e frame.number -e ip.src -e ip.dst -e ftp.request.command -e ftp.request.arg -e ftp.response.code -e ftp.response.arg 2>/dev/null`
            );
            out.push(`── FTP 命令 ──\n${ftp || "(无 FTP 流量)"}`);
          } catch (err: any) {
            out.push(`── FTP 提取失败 ──\n${err.message}`);
          }
          // FTP 凭据搜索
          try {
            const ftpCred = runCmd(
              `tshark -r "${pcap_path}" ${maxPacketsArg} -Y "ftp.request.command == \\"USER\\" or ftp.request.command == \\"PASS\\"" -T fields -e frame.number -e ip.src -e ftp.request.command -e ftp.request.arg 2>/dev/null`
            );
            if (ftpCred.trim()) {
              out.push(`\n── FTP 凭据 ──\n${ftpCred}`);
            }
          } catch {}
        } else if (mode === "extract") {
          // 用 tshark -T fields 提取特定字段或 tcpxtract 提取文件
          if (commandExists("tcpxtract")) {
            try {
              const outputDir = `/tmp/pcap_extract_${Date.now()}`;
              const result = runCmd(`tcpxtract -f "${pcap_path}" -o "${outputDir}"`);
              out.push(`── 文件提取 (tcpxtract) ──\n输出目录: ${outputDir}\n${result || "提取完成"}`);
            } catch (err: any) {
              out.push(`── tcpxtract 失败 ──\n${err.message}`);
            }
          } else {
            // 用 tshark 提取 HTTP 传输的文件
            try {
              const outputDir = `/tmp/pcap_extract_${Date.now()}`;
              fs.mkdirSync(outputDir, { recursive: true });
              const result = runCmd(
                `tshark -r "${pcap_path}" ${filterArg} --export-objects "http,${outputDir}" -q 2>/dev/null; echo "提取完成"`,
                60000
              );
              out.push(`── HTTP 对象提取 (tshark --export-objects) ──\n输出目录: ${outputDir}\n${result}`);
            } catch (err: any) {
              out.push(
                `── 文件提取失败 ──\n${err.message}\n` +
                `  也可安装 tcpxtract: sudo apt install tcpxtract`
              );
            }
          }
        } else if (mode === "credentials") {
          // 搜索明文密码（FTP/Telnet/HTTP POST）
          out.push(`── 明文凭据搜索 ──\n`);

          // FTP 凭据
          try {
            const ftpCred = runCmd(
              `tshark -r "${pcap_path}" -Y "ftp.request.command == \\"USER\\" or ftp.request.command == \\"PASS\\"" -T fields -e frame.number -e ip.src -e ip.dst -e ftp.request.command -e ftp.request.arg 2>/dev/null`
            );
            if (ftpCred.trim()) {
              out.push(`[FTP 凭据]\n${ftpCred}`);
            }
          } catch {}

          // Telnet 凭据
          try {
            const telnet = runCmd(
              `tshark -r "${pcap_path}" -Y "telnet" -T fields -e frame.number -e ip.src -e ip.dst -e data 2>/dev/null | head -50`
            );
            if (telnet.trim()) {
              out.push(`\n[Telnet 数据]\n${telnet}`);
            }
          } catch {}

          // HTTP POST 表单数据
          try {
            const httpPost = runCmd(
              `tshark -r "${pcap_path}" -Y "http.request.method == \\"POST\\" and http.file_data" -T fields -e frame.number -e ip.src -e ip.dst -e http.host -e http.request.uri -e http.file_data 2>/dev/null`
            );
            if (httpPost.trim()) {
              out.push(`\n[HTTP POST 数据]\n${httpPost}`);
            }
          } catch {}

          // HTTP Basic Auth
          try {
            const httpAuth = runCmd(
              `tshark -r "${pcap_path}" -Y "http.authorization" -T fields -e frame.number -e ip.src -e ip.dst -e http.authorization 2>/dev/null`
            );
            if (httpAuth.trim()) {
              out.push(`\n[HTTP Basic Auth]\n${httpAuth}`);
            }
          } catch {}

          // POP3/SMTP 凭据
          try {
            const mailCred = runCmd(
              `tshark -r "${pcap_path}" -Y "pop.request.command == \\"USER\\" or pop.request.command == \\"PASS\\" or smtp.req.command == \\"AUTH\\"" -T fields -e frame.number -e ip.src -e ip.dst -e pop.request.command -e pop.request.parameter -e smtp.req.command -e smtp.req.parameter 2>/dev/null`
            );
            if (mailCred.trim()) {
              out.push(`\n[邮件凭据 (POP3/SMTP)]\n${mailCred}`);
            }
          } catch {}

          if (out.length <= 2) {
            out.push("(未找到明文凭据)");
          }
        }
      } catch (err: any) {
        out.push(`\n❌ 分析失败: ${err.message}`);
      }

      return out.join("\n");
    },
  });

  return registry;
}
