// 阶段2 单元测试：web_fetch 工具元数据与结构
// 仅校验元数据（真实抓取由 e2e-stage7 / e2e-mainagent 覆盖）。运行：node tests/stage2.test.js
const { createWebTools } = require("../dist/tools");

let pass = 0;
let fail = 0;
const ok = (name, cond) => {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}`); }
};

(() => {
  console.log("\n=== 阶段2：web_fetch 元数据 ===");
  const reg = createWebTools();
  const webFetch = reg.get("web_fetch");

  ok("web_fetch 已注册", !!webFetch);
  ok("web_fetch 可并发 (concurrent:true)", webFetch.concurrent === true);
  ok("web_fetch 不需权限", webFetch.requirePermission !== true);
  ok("web_fetch 有描述", typeof webFetch.description === "string" && webFetch.description.length > 0);
  ok("web_fetch 有参数 schema", !!webFetch.parameters);
  ok("isConcurrent(web_fetch)=true", reg.isConcurrent("web_fetch") === true);
  ok("requiresPermission(web_fetch)=false", reg.requiresPermission("web_fetch") === false);

  // http_request 仍可用且并发
  ok("http_request 已注册", !!reg.get("http_request"));
  ok("http_request 可并发", reg.isConcurrent("http_request") === true);

  console.log(`\n=== 结果: ${pass} passed, ${fail} failed ===`);
  process.exit(fail === 0 ? 0 : 1);
})();
