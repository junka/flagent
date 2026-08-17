// 阶段6 单元测试：ToolExecutor 并发限制器 / PermissionManager 双检锁
// 无需网络与 LLM（全部 mock）。运行：node tests/stage6.test.js
const { z } = require("zod");
const { ToolRegistry } = require("../dist/tools");
const { ToolExecutor } = require("../dist/agents/tool-executor");
const {
  PermissionManager,
} = require("../dist/permissions/permission-manager");

let pass = 0;
let fail = 0;
const ok = (name, cond) => {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}`); }
};

(async () => {
  // ============ ToolExecutor 并发限制器 ============
  console.log("\n=== ToolExecutor 并发限制器 ===");

  async function testConcurrencyLimit(limit, numTasks) {
    const reg = new ToolRegistry();
    let active = 0;
    let maxActive = 0;
    reg.register({
      name: "slow_tool",
      description: "慢工具用于测并发",
      parameters: z.object({ id: z.number() }),
      category: "test",
      concurrent: true,
      execute: async (args) => {
        active++;
        maxActive = Math.max(maxActive, active);
        await new Promise((res) => setTimeout(res, 30));
        active--;
        return `done ${args.id}`;
      },
    });
    const executor = new ToolExecutor(reg, undefined, limit);
    const actions = Array.from({ length: numTasks }, (_, i) => ({
      toolName: "slow_tool",
      toolArgs: { id: i },
    }));
    const results = await executor.executeBatch(actions);
    return { maxActive, count: results.length, allSuccess: results.every((x) => x.success) };
  }

  let t = await testConcurrencyLimit(3, 10);
  ok("限流=3 时最大并发不超过3", t.maxActive <= 3);
  ok("10 个任务全部执行", t.count === 10);
  ok("全部成功", t.allSuccess);
  console.log(`    (实测最大并发: ${t.maxActive})`);

  t = await testConcurrencyLimit(8, 20);
  ok("限流=8 时最大并发不超过8", t.maxActive <= 8);
  ok("20 个任务全部执行", t.count === 20);
  console.log(`    (实测最大并发: ${t.maxActive})`);

  t = await testConcurrencyLimit(2, 5);
  ok("限流=2 时最大并发不超过2", t.maxActive <= 2);
  console.log(`    (实测最大并发: ${t.maxActive})`);

  // ============ PermissionManager 并发双检锁 ============
  console.log("\n=== PermissionManager 并发双检锁 ===");

  let promptCount = 0;
  const pm = new PermissionManager(async () => {
    promptCount++;
    await new Promise((r) => setTimeout(r, 10));
    return true;
  });
  const results = await Promise.all(
    Array.from({ length: 5 }, () => pm.check("command_exec", { command: "x" }))
  );
  ok("5 个并发 check 全部返回 true", results.every((x) => x === true));
  ok("只弹窗 1 次（双检锁生效）", promptCount === 1);
  console.log(`    (实际弹窗次数: ${promptCount})`);

  promptCount = 0;
  const pm2 = new PermissionManager(async () => {
    promptCount++;
    return true;
  });
  await Promise.all([pm2.check("command_exec", {}), pm2.check("file_write_real", {})]);
  ok("不同工具各自弹窗", promptCount === 2);

  const pm3 = new PermissionManager(async () => false);
  const denied = await Promise.all([
    pm3.check("command_exec", {}),
    pm3.check("command_exec", {}),
  ]);
  ok("拒绝全部返回 false", denied.every((x) => x === false));
  ok("拒绝不记入 approved", !pm3.isApproved("command_exec"));

  console.log(`\n=== 结果: ${pass} passed, ${fail} failed ===`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR:", e); process.exit(1); });
