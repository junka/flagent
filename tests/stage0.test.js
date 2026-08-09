// 阶段0 单元测试：工具元数据扩展（concurrent / requirePermission 标记）
// 无需网络与 LLM。运行：node tests/stage0.test.js
const {
  ToolRegistry,
  createWebTools,
  createPwnTools,
  createReverseTools,
  createCryptoTools,
  createMiscTools,
} = require("../dist/tools");

let pass = 0;
let fail = 0;
const ok = (name, cond) => {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}`); }
};

// 用真实工具工厂构造完整注册表（与 CLI createAgentSystem 一致）
function buildFullRegistry() {
  const reg = new ToolRegistry();
  for (const t of createWebTools().getAll()) reg.register(t);
  for (const t of createPwnTools().getAll()) reg.register(t);
  for (const t of createReverseTools().getAll()) reg.register(t);
  for (const t of createCryptoTools().getAll()) reg.register(t);
  for (const t of createMiscTools().getAll()) reg.register(t);
  return reg;
}

(() => {
  console.log("\n=== 阶段0：工具元数据 ===");
  const reg = buildFullRegistry();
  const all = reg.getAll();

  // requirePermission 标记（副作用工具）
  ok("command_exec 需权限", reg.requiresPermission("command_exec") === true);
  ok("file_write_real 需权限", reg.requiresPermission("file_write_real") === true);
  ok("nc_remote_client 需权限", reg.requiresPermission("nc_remote_client") === true);

  // 只读工具不需权限
  ok("http_request 不需权限", reg.requiresPermission("http_request") === false);
  ok("port_scan 不需权限", reg.requiresPermission("port_scan") === false);

  // concurrent 标记（只读采集可并发）
  ok("http_request 可并发", reg.isConcurrent("http_request") === true);
  ok("port_scan 可并发", reg.isConcurrent("port_scan") === true);
  ok("dns_lookup 可并发", reg.isConcurrent("dns_lookup") === true);

  // 副作用工具不可并发（保守，避免冲突）
  ok("command_exec 不可并发", reg.isConcurrent("command_exec") === false);
  ok("file_write_real 不可并发", reg.isConcurrent("file_write_real") === false);
  ok("nc_remote_client 不可并发", reg.isConcurrent("nc_remote_client") === false);

  // 未知工具
  ok("未知工具 requiresPermission=false", reg.requiresPermission("nope") === false);
  ok("未知工具 isConcurrent=false", reg.isConcurrent("nope") === false);

  // 数量统计
  const concurrentCount = all.filter((t) => t.concurrent === true).length;
  const permCount = all.filter((t) => t.requirePermission === true).length;
  ok("工具总数 > 30", all.length > 30);
  ok("并发工具数 > 10", concurrentCount > 10);
  ok("需权限工具数 >= 3（command_exec / file_write_real / nc_remote_client / pwn_run_exploit 等）", permCount >= 3);

  console.log(`\n=== 结果: ${pass} passed, ${fail} failed ===`);
  process.exit(fail === 0 ? 0 : 1);
})();
