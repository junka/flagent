// 阶段6 e2e：MainAgent 并发 ReAct（真实 LLM + 真实工具）
// 验证一次 ACTIONS 并发发起多个只读采集工具。
// 需配置 .env (DASHSCOPE_API_KEY) 与网络。运行：node tests/e2e-mainagent.test.js
const { createAgentSystem } = require("../dist/cli/index");
const { createToolRegistry } = require("../dist/tools");
const {
  PermissionManager,
} = require("../dist/permissions/permission-manager");

(async () => {
  const pm = new PermissionManager(async () => true); // 自动批准副作用工具
  const toolRegistry = createToolRegistry();
  const mainAgent = createAgentSystem({ toolRegistry, permissionManager: pm }).mainAgent;

  const task =
    "请并发抓取 http://example.com 和 https://www.iana.org 两个网页，告诉我每个页面的标题。请在一次 ACTIONS 中同时发起两个 web_fetch，不要逐个串行。";

  console.log("运行 MainAgent 并发 ReAct（真实 LLM）...\n");
  const result = await mainAgent.run(task);

  console.log("=== 最终答案 ===");
  console.log(result.finalAnswer);
  console.log(`\n步数: ${result.steps.length}  成功: ${result.success}  耗时: ${(result.duration / 1000).toFixed(1)}s`);

  console.log("\n=== 执行过程 ===");
  for (const s of result.steps) {
    console.log(
      `  Step ${s.step}: [${s.action}] ${(s.observation || "").slice(0, 100).replace(/\n/g, " ")}`
    );
  }

  // 检测并发：是否有同一 step 号下出现 2+ 个 TOOL 调用
  const byStep = {};
  for (const s of result.steps) {
    if (s.action.startsWith("TOOL")) {
      byStep[s.step] = (byStep[s.step] || 0) + 1;
    }
  }
  const maxConcurrentInStep = Math.max(0, ...Object.values(byStep));
  console.log(`\n=== 并发检测 ===`);
  console.log(`单步最大工具调用数: ${maxConcurrentInStep}`);
  console.log(`存在并发 ACTIONS (>=2): ${maxConcurrentInStep >= 2}`);

  const mentionsBoth =
    /example\.com/i.test(result.finalAnswer) && /iana/i.test(result.finalAnswer);
  console.log(`答案提到两个站点: ${mentionsBoth}`);

  const success = result.success && mentionsBoth;
  console.log(`\n=== 结果: ${success ? "PASS" : "FAIL"} ===`);
  process.exit(success ? 0 : 1);
})().catch((e) => {
  console.error("ERR:", e);
  process.exit(1);
});
