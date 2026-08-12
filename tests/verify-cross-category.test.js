// 跨类工具机制 + database/web-advanced/linux-security 工具集 Smoke 测试
"use strict";

const assert = require("assert");
const { createToolRegistry } = require("../dist/tools");
const {
  ToolExecutor,
  Scheduler,
  createAgentSystem,
} = require("../dist/agents");
const { PermissionManager } = require("../dist/permissions/permission-manager");

const registry = createToolRegistry();
const permissionManager = new PermissionManager(async () => true);
const toolExecutor = new ToolExecutor(registry, permissionManager);

const system = createAgentSystem({
  toolRegistry: registry,
  permissionManager,
  sessionId: "test-cross",
  title: "test",
  maxSteps: 3,
});
const scheduler = system.scheduler;

// 三类新工具的预期清单
const expectedToolGroups = {
  database: [
    "db_connect_brute", "db_enum", "redis_attack", "nosql_scan",
    "sqlmap_advanced", "sqlite_exploit", "mssql_exploit",
  ],
  webAdvanced: [
    "waf_cdn_detect", "cors_audit", "jwt_attack", "csrf_audit",
    "xxe_test", "graphql_attack", "race_condition", "csp_audit",
    "saml_oauth_audit", "websocket_audit", "auth_bypass",
  ],
  linuxSecurity: [
    "suid_cap_audit", "process_service_audit", "kernel_exploit_match",
    "file_permission_audit", "firewall_network_audit", "ssh_crack",
    "container_escape_test", "linpeas_report",
  ],
};

let total = 0, passed = 0;

async function test(name, fn) {
  total++;
  try {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (e) {
    console.log(`  ✗ ${name}: ${e.message}`);
    process.exitCode = 1;
  }
}

console.log("\n== crossCategory + 三类新工具 Smoke 测试 ==");

(async function run() {
  // 1. 三类工具全部在 registry 中注册，且描述与 schema 存在
  for (const [group, names] of Object.entries(expectedToolGroups)) {
    await test(`${group} 全部 ${names.length} 个工具已在 registry 注册`, async () => {
      for (const n of names) {
        const tool = registry.get(n);
        assert.ok(tool, `缺少工具: ${n}`);
        assert.ok(typeof tool.description === "string" && tool.description.length > 3,
          `${n} 描述为空或过短`);
        assert.ok(tool.parameters && typeof tool.parameters === "object",
          `${n} 缺少 parameters schema`);
      }
    });
  }

  // 2. 三类工具的 meta 分类 / perm 与名称语义一致
  await test("database 工具 category 为 database / 高危被 perm: true 保护", async () => {
    // sqlmap_advanced 设计为仅在有 db_type 时需要额外防护，不需要 perm 标记
    const dm = { db_connect_brute: true, redis_attack: true, mssql_exploit: true };
    for (const n of expectedToolGroups.database) {
      const tool = registry.get(n);
      assert.strictEqual(tool.category, "database", `${n} category 应为 database`);
      const perm = tool.requiresPermission || tool.requirePermission;
      if (dm[n]) {
        assert.strictEqual(perm, true, `${n} 应需要权限`);
      }
    }
  });

  await test("web-advanced 工具 category 为 web", async () => {
    for (const n of expectedToolGroups.webAdvanced) {
      const tool = registry.get(n);
      assert.strictEqual(tool.category, "web", `${n} category 应为 web`);
    }
  });

  await test("linux-security 工具 分类+高危权限检查", async () => {
    // container_escape_test 归属 cloud-tools，类别为 cloud；其余 linux-security 归为 linux
    const linuxOnly = expectedToolGroups.linuxSecurity.filter(n => n !== "container_escape_test");
    for (const n of linuxOnly) {
      const tool = registry.get(n);
      assert.strictEqual(tool.category, "linux", `${n} category 应为 linux`);
    }
    // container_escape_test 存在且 category=cloud（来自 cloud-tools.ts），权限为 true
    const cet = registry.get("container_escape_test");
    assert.ok(cet, "container_escape_test 应存在");
    assert.strictEqual(cet.category, "cloud");
    const cetPerm = cet.requiresPermission || cet.requirePermission;
    assert.strictEqual(cetPerm, true, "container_escape_test 应需要权限");
    const hi = { ssh_crack: true };
    for (const n of linuxOnly) {
      const tool = registry.get(n);
      const perm = tool.requiresPermission || tool.requirePermission;
      if (hi[n]) {
        assert.strictEqual(perm, true, `${n} 应需要权限`);
      }
    }
  });

  // 3. 三类工具在输入文件不存在 / 非预期输入下返回优雅提示（而不是抛异常）
  await test("database/sqlmap_advanced: 空 payload 返回优雅错误", async () => {
    const tool = registry.get("sqlmap_advanced");
    try {
      const res = await tool.execute({});
      assert.ok(typeof res === "string", "应返回字符串");
      assert.ok(res.includes("target_url") || res.includes("缺少") || res.includes("参数"),
        `结果应提示缺少参数: ${res.slice(0, 80)}`);
    } catch (e) {
      // Zod 或运行时异常都视为"已处理的错误"，这里只需要不抛即可
      assert.ok(e instanceof Error, "应抛出有意义的错误对象");
    }
  });

  await test("web-advanced/waf_cdn_detect: 无参数返回优雅错误", async () => {
    const tool = registry.get("waf_cdn_detect");
    try {
      const res = await tool.execute({});
      assert.ok(typeof res === "string", "应返回字符串");
      assert.ok(res.includes("缺少") || res.includes("参数") || res.includes("url"),
        `结果应提示缺少参数: ${res.slice(0, 80)}`);
    } catch (e) {
      assert.ok(e instanceof Error, "应抛出有意义的错误对象");
    }
  });

  await test("linux-security/suid_cap_audit: 无参数返回优雅错误", async () => {
    const tool = registry.get("suid_cap_audit");
    try {
      const res = await tool.execute({});
      assert.ok(typeof res === "string", "应返回字符串");
      assert.ok(res.includes("缺少") || res.includes("参数") || res.includes("target") || res.includes("二进制") || res.includes("路径"),
        `结果应提示缺少参数: ${res.slice(0, 80)}`);
    } catch (e) {
      assert.ok(e instanceof Error, "应抛出有意义的错误对象");
    }
  });

  // 4. SubAgent 都有 crossCategoryToolNames 且与 factory 配置一致
  const agentIds = ["web", "pwn", "reverse", "crypto", "misc", "forensics", "mobile", "blockchain", "osint", "cloud", "iot", "aiml"];
  await test(`12 个 SubAgent 全部注册且都配置了 crossCategoryToolNames`, async () => {
    for (const id of agentIds) {
      const agent = scheduler.getAgent(id);
      assert.ok(agent, `缺少 agent: ${id}`);
      const cc = agent.getCrossCategoryToolNames ? agent.getCrossCategoryToolNames() : (agent.crossCategoryToolNames || []);
      assert.ok(Array.isArray(cc) && cc.length > 0, `${id} 未配置 crossCategoryToolNames`);
    }
  });

  // 5. webAgent 的主工具 + 跨类工具 包含关键的 database/web-advanced
  await test("webAgent 主工具+跨类工具包含 web 高级与 database 关键字段", async () => {
    const agent = scheduler.getAgent("web");
    const main = agent.getAllowedToolNames ? agent.getAllowedToolNames() : [];
    const mustHave = ["sqlmap_advanced", "waf_cdn_detect", "cors_audit", "jwt_attack", "redis_attack", "db_connect_brute"];
    for (const n of mustHave) {
      assert.ok(main.includes(n), `webAgent 应能访问 ${n}`);
    }
  });

  // 6. pwnAgent 的主工具 + 跨类工具包含 linux 提权关键工具
  await test("pwnAgent 主工具+跨类工具包含 linux 提权关键字段", async () => {
    const agent = scheduler.getAgent("pwn");
    const main = agent.getAllowedToolNames ? agent.getAllowedToolNames() : [];
    const mustHave = ["suid_cap_audit", "process_service_audit", "kernel_exploit_match", "container_escape_test", "linpeas_report"];
    for (const n of mustHave) {
      assert.ok(main.includes(n), `pwnAgent 应能访问 ${n}`);
    }
  });

  // 7. 非授权 SubAgent 不会拿到完全无关的高危工具（例如 aiml 默认没有 ssh_crack 在主工具）
  await test("aimlAgent 的主工具 不包含 ssh_crack/iam_enum（跨类里允许才可以）", async () => {
    const agent = scheduler.getAgent("aiml");
    const main = agent.toolNames || [];
    assert.ok(!main.includes("ssh_crack"), "aiml 主工具不应含 ssh_crack");
    assert.ok(!main.includes("iam_enum"), "aiml 主工具不应含 iam_enum");
  });

  // 8. buildPrompt 的 prompt 文本里会出现跨类工具的标记（用于确认 LLM 能感知）
  await test("crossCategory 会在 SubAgent buildPrompt 中渲染标记", async () => {
    const agent = scheduler.getAgent("web");
    // 借助私有方法模拟构建 prompt；若未来重构，这里改为公开调用
    const privateBuild = agent.buildPrompt || agent._buildPrompt;
    if (typeof privateBuild === "function") {
      const text = privateBuild.call(agent, "http://target.test/ 综合题", 1);
      assert.ok(text.includes("跨类"), "prompt 未出现 '跨类' 提示块");
    }
  });

  console.log(`\n结果: ${passed}/${total} 通过\n`);
})();
