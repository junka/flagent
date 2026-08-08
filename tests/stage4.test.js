// 阶段4 单元测试：ToolExecutor 统一执行（并发/串行混合、权限拒绝、未找到、顺序保持）
// 无需网络与 LLM（mock 工具）。运行：node tests/stage4.test.js
const { z } = require("zod");
const { ToolRegistry } = require("../dist/tools");
const { ToolExecutor } = require("../dist/agents/tool-executor");
const { PermissionManager } = require("../dist/permissions");

let pass = 0;
let fail = 0;
const ok = (name, cond) => {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}`); }
};

function buildReg() {
  const reg = new ToolRegistry();
  reg.register({
    name: "read_a", description: "只读a", parameters: z.object({}),
    category: "t", concurrent: true, execute: async () => "a-result",
  });
  reg.register({
    name: "read_b", description: "只读b", parameters: z.object({}),
    category: "t", concurrent: true, execute: async () => "b-result",
  });
  reg.register({
    name: "write_c", description: "写c", parameters: z.object({}),
    category: "t", requirePermission: true, execute: async () => "c-result",
  });
  return reg;
}

(async () => {
  console.log("\n=== 阶段4：ToolExecutor ===");

  // ① 混合并发+串行，保持原顺序返回
  const reg = buildReg();
  const ex = new ToolExecutor(reg, undefined, 8);
  const results = await ex.executeBatch([
    { toolName: "read_a", toolArgs: {} },
    { toolName: "read_b", toolArgs: {} },
    { toolName: "write_c", toolArgs: {} },
  ]);
  ok("全部执行", results.length === 3);
  ok("顺序保持 read_a 在前", results[0].toolName === "read_a");
  ok("顺序保持 write_c 在后", results[2].toolName === "write_c");
  ok("全部成功", results.every((r) => r.success));

  // ② 未找到工具 → 失败且含提示
  const r2 = await ex.executeBatch([{ toolName: "nope", toolArgs: {} }]);
  ok("未找到工具标记失败", r2[0].success === false);
  ok("未找到工具结果含提示", /未找到/.test(r2[0].result));

  // ③ 权限拒绝 → skipped，不执行
  const pmDeny = new PermissionManager(async () => false);
  const ex2 = new ToolExecutor(reg, pmDeny, 8);
  const r3 = await ex2.executeBatch([{ toolName: "write_c", toolArgs: {} }]);
  ok("权限拒绝标记失败", r3[0].success === false);
  ok("权限拒绝 skipped", r3[0].skipped === true);
  ok("权限拒绝结果含提示", /权限拒绝/.test(r3[0].result));

  // ④ 权限批准 → 执行成功
  const pmAllow = new PermissionManager(async () => true);
  const ex3 = new ToolExecutor(reg, pmAllow, 8);
  const r4 = await ex3.executeBatch([{ toolName: "write_c", toolArgs: {} }]);
  ok("权限批准执行成功", r4[0].success === true && r4[0].result === "c-result");

  // ⑤ 并发工具确实并发执行（计时验证）
  const reg2 = new ToolRegistry();
  reg2.register({
    name: "slow", description: "s", parameters: z.object({}),
    category: "t", concurrent: true,
    execute: async () => { await new Promise((r) => setTimeout(r, 50)); return "slow"; },
  });
  const ex4 = new ToolExecutor(reg2, undefined, 8);
  const t0 = Date.now();
  await ex4.executeBatch(Array.from({ length: 5 }, () => ({ toolName: "slow", toolArgs: {} })));
  const dur = Date.now() - t0;
  ok("5 个并发工具总耗时 < 串行(250ms)", dur < 200);
  console.log(`    (5 个并发实际耗时: ${dur}ms)`);

  // ⑥ 空数组直接返回空
  const r6 = await ex.executeBatch([]);
  ok("空 actions 返回空数组", Array.isArray(r6) && r6.length === 0);

  // ⑦ 串行工具顺序执行（用计数验证不并发）
  let active = 0;
  let maxActive = 0;
  const reg3 = new ToolRegistry();
  reg3.register({
    name: "serial_op", description: "s", parameters: z.object({}),
    category: "t", // 未标 concurrent → 串行
    execute: async () => {
      active++;
      maxActive = Math.max(maxActive, active);
      await new Promise((r) => setTimeout(r, 20));
      active--;
      return "ok";
    },
  });
  const ex5 = new ToolExecutor(reg3, undefined, 8);
  await ex5.executeBatch(Array.from({ length: 4 }, () => ({ toolName: "serial_op", toolArgs: {} })));
  ok("未标 concurrent 的工具串行执行", maxActive === 1);
  console.log(`    (串行组实测最大并发: ${maxActive})`);

  console.log(`\n=== 结果: ${pass} passed, ${fail} failed ===`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR:", e); process.exit(1); });
