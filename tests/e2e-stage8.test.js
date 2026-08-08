// 阶段8 e2e：简单任务跳过 PLAN/ACTIONS 直接 FINAL_ANSWER（侦察→分类→深挖 prompt 的"简单任务可跳过"分支）
// 需配置 .env (DASHSCOPE_API_KEY)。运行：node tests/e2e-stage8.test.js
const { createAgentSystem } = require("../dist/cli/index");
const { createToolRegistry } = require("../dist/tools");
const {
  PermissionManager,
} = require("../dist/permissions/permission-manager");

(async () => {
  const pm = new PermissionManager(async () => true);
  const toolRegistry = createToolRegistry();
  const mainAgent = createAgentSystem({ toolRegistry, permissionManager: pm }).mainAgent;

  // 简单算术任务：期望跳过 PLAN/ACTIONS，直接 FINAL_ANSWER，不调用任何工具
  const task = "计算 23 乘以 17 等于多少？请直接回答，不要使用任何工具。";

  console.log("运行简单任务（真实 LLM，期望跳过工具）...\n");
  const result = await mainAgent.run(task);

  console.log("=== 最终答案 ===");
  console.log(result.finalAnswer);
  console.log(`\n步数: ${result.steps.length}  成功: ${result.success}  耗时: ${(result.duration / 1000).toFixed(1)}s`);

  console.log("\n=== 执行过程 ===");
  for (const s of result.steps) {
    console.log(`  Step ${s.step}: [${s.action}] ${(s.observation || "").slice(0, 80).replace(/\n/g, " ")}`);
  }

  // 关键断言：不应出现 TOOL 调用（简单任务跳过工具）
  const toolSteps = result.steps.filter((s) => s.action.startsWith("TOOL"));
  console.log(`\n=== 跳过工具检测 ===`);
  console.log(`TOOL 调用步数: ${toolSteps.length}`);
  console.log(`是否跳过工具: ${toolSteps.length === 0}`);

  // 答案应包含 391（23*17）
  const hasCorrect = /391/.test(result.finalAnswer);
  console.log(`答案包含 391: ${hasCorrect}`);

  const success = result.success && toolSteps.length === 0 && hasCorrect;
  console.log(`\n=== 结果: ${success ? "PASS" : "FAIL"} ===`);
  process.exit(success ? 0 : 1);
})().catch((e) => {
  console.error("ERR:", e);
  process.exit(1);
});
