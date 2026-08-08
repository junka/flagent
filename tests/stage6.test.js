// 阶段6 单元测试：parseMainReactResponse / ToolExecutor 并发限制器 / PermissionManager 双检锁
// 无需网络与 LLM（全部 mock）。运行：node tests/stage6.test.js
const { z } = require("zod");
const { ToolRegistry } = require("../dist/tools");
const { ToolExecutor } = require("../dist/agents/tool-executor");
const {
  PermissionManager,
} = require("../dist/permissions/permission-manager");
const {
  parseMainReactResponse,
} = require("../dist/agents/react-parser");

let pass = 0;
let fail = 0;
const ok = (name, cond) => {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}`); }
};

(async () => {
  // ============ parseMainReactResponse ============
  console.log("\n=== parseMainReactResponse ===");

  let r = parseMainReactResponse(
    `THOUGHT: 并发采集两个目标
ACTIONS:
  - http_request({"url":"http://a.com"})
  - port_scan({"host":"a.com"})`
  );
  ok("多 ACTIONS 解析数量", r.actions.length === 2);
  ok("第一个工具名", r.actions[0].toolName === "http_request");
  ok("第一个工具参数", r.actions[0].toolArgs.url === "http://a.com");
  ok("第二个工具名", r.actions[1].toolName === "port_scan");
  ok("THOUGHT 解析", r.thought === "并发采集两个目标");
  ok("无 DELEGATE", r.delegates.length === 0);
  ok("无 FINAL_ANSWER", r.finalAnswer === "");

  r = parseMainReactResponse(
    `THOUGHT: 分派给两个专家
DELEGATE: web, pwn`
  );
  ok("多 DELEGATE 解析", r.delegates.length === 2 && r.delegates[0] === "web" && r.delegates[1] === "pwn");

  r = parseMainReactResponse(
    `THOUGHT: 边采集边委派
ACTIONS:
  - http_request({"url":"http://x.com"})
DELEGATE: crypto`
  );
  ok("混合 ACTIONS+DELEGATE", r.actions.length === 1 && r.delegates.length === 1 && r.delegates[0] === "crypto");

  r = parseMainReactResponse(
    `ACTIONS:
  - http_request({
      "url": "http://x.com",
      "timeout": 5000
    })`
  );
  ok("多行 JSON 参数解析", r.actions.length === 1 && r.actions[0].toolArgs.url === "http://x.com" && r.actions[0].toolArgs.timeout === 5000);

  r = parseMainReactResponse(
    `THOUGHT: 完成
FINAL_ANSWER: 最终答案`
  );
  ok("FINAL_ANSWER 解析", r.finalAnswer === "最终答案");
  ok("FINAL_ANSWER 时无 actions", r.actions.length === 0);

  r = parseMainReactResponse(
    `ACTIONS:
  http_request({"url":"http://a.com"})
  port_scan({"host":"a.com"})`
  );
  ok("无标记裸工具调用", r.actions.length === 2);

  r = parseMainReactResponse("random text no keys");
  ok("无键文本全空", r.actions.length === 0 && r.delegates.length === 0 && r.finalAnswer === "");

  r = parseMainReactResponse("DELEGATE：web，pwn");
  ok("全角冒号+全角逗号 DELEGATE", r.delegates.length === 2);

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
