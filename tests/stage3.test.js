// 阶段3 单元测试：PermissionManager（记忆 / reset / isApproved / getApproved / 串行化）
// 无需网络与 LLM（mock confirmFn）。运行：node tests/stage3.test.js
const { PermissionManager } = require("../dist/permissions");

let pass = 0;
let fail = 0;
const ok = (name, cond) => {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}`); }
};

(async () => {
  console.log("\n=== 阶段3：PermissionManager ===");

  // ① 记忆：第二次同工具不再询问
  let count = 0;
  const pm = new PermissionManager(async () => {
    count++;
    return true;
  });
  const r1 = await pm.check("command_exec", {});
  const r2 = await pm.check("command_exec", {});
  ok("首次返回 true", r1 === true);
  ok("二次返回 true", r2 === true);
  ok("只询问 1 次（记忆生效）", count === 1);
  ok("isApproved 标记", pm.isApproved("command_exec") === true);

  // ② getApproved
  ok("getApproved 包含已批准", pm.getApproved().includes("command_exec"));

  // ③ reset 清空记忆
  pm.reset();
  ok("reset 后不 approved", !pm.isApproved("command_exec"));
  ok("reset 后 getApproved 空", pm.getApproved().length === 0);

  // ④ 拒绝：返回 false 且不记入 approved
  const pm2 = new PermissionManager(async () => false);
  const d = await pm2.check("file_write_real", {});
  ok("拒绝返回 false", d === false);
  ok("拒绝不 approved", !pm2.isApproved("file_write_real"));

  // ⑤ promptLock 串行化：不同工具各自询问一次
  const seq = [];
  const pm3 = new PermissionManager(async (name) => {
    seq.push(name);
    await new Promise((r) => setTimeout(r, 5));
    return true;
  });
  await Promise.all([
    pm3.check("a", {}),
    pm3.check("b", {}),
    pm3.check("c", {}),
  ]);
  ok("三个不同工具各弹一次", seq.length === 3);
  ok("三个工具都被批准", pm3.getApproved().length === 3);

  // ⑥ 批准后再次并发同工具不重复询问（双检锁 fast-path）
  count = 0;
  const pm4 = new PermissionManager(async () => {
    count++;
    return true;
  });
  await pm4.check("x", {}); // 首次批准
  count = 0;
  const again = await Promise.all([
    pm4.check("x", {}),
    pm4.check("x", {}),
    pm4.check("x", {}),
  ]);
  ok("已批准后并发不再询问", count === 0);
  ok("已批准后并发全 true", again.every((x) => x === true));

  console.log(`\n=== 结果: ${pass} passed, ${fail} failed ===`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR:", e); process.exit(1); });
