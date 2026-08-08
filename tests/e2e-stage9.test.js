// 阶段9 e2e：仅用包入口(dist/index)导出编程式构建智能体系统 + 动态注册 agent + 真实 LLM 运行
// 验证库可作为独立包使用（不依赖 createAgentSystem）。需 .env 与网络。运行：node tests/e2e-stage9.test.js
const {
  ContextManager,
  ToolRegistry,
  MainAgent,
  Scheduler,
  ToolExecutor,
  PermissionManager,
} = require("../dist/index");
const { z } = require("zod");

(async () => {
  // ① 编程式构建（全部来自包入口导出）
  const pm = new PermissionManager(async () => true);
  const cm = new ContextManager({
    summaryThresholdTokens: 1e9,
    maxContextTokens: 1e9,
    windowMessages: 10,
  });

  const reg = new ToolRegistry();
  reg.register({
    name: "echo",
    description: "回显输入的文本（测试用工具）",
    parameters: z.object({ text: z.string() }),
    category: "test",
    concurrent: true,
    execute: async (args) => `[echo] ${args.text}`,
  });

  const executor = new ToolExecutor(reg, pm, 8);
  const scheduler = new Scheduler(reg, executor);

  // ② 动态注册一个能使用 echo 的通用 agent（决策四）
  scheduler.registerDynamicAgent({
    id: "gen-echoer",
    name: "回显专家",
    role: "回显测试员",
    systemPrompt: "你是回显测试员。接到任务后用 echo 工具回显指定文本并返回结果。请用中文回复。",
    toolNames: ["echo"],
    maxSteps: 3,
  });

  const mainAgent = new MainAgent(cm, reg, scheduler, executor, 10);

  // ③ 真实运行：主控应直接用 echo 工具（或委派 gen-echoer）完成任务
  const task = '请用 echo 工具回显文本 "flagent-stage9"，然后告诉我 echo 返回了什么。';
  console.log("运行编程式构建的 MainAgent（真实 LLM）...\n");
  const result = await mainAgent.run(task);

  console.log("=== 最终答案 ===");
  console.log(result.finalAnswer);
  console.log(`\n步数: ${result.steps.length}  成功: ${result.success}  耗时: ${(result.duration / 1000).toFixed(1)}s`);

  console.log("\n=== 执行过程 ===");
  for (const s of result.steps) {
    const obs = s.observation ? ` | ${s.observation.slice(0, 100).replace(/\n/g, " ")}` : "";
    console.log(`  Step ${s.step}: [${s.action}]${obs}`);
  }

  // 关键断言：echo 工具被调用过，且答案含回显文本
  const usedEcho = result.steps.some((s) => s.action.startsWith("TOOL: echo"));
  console.log(`\n=== 检测 ===`);
  console.log(`echo 工具被调用: ${usedEcho}`);
  const hasText = /flagent-stage9/.test(result.finalAnswer);
  console.log(`答案包含回显文本: ${hasText}`);

  const success = result.success && usedEcho && hasText;
  console.log(`\n=== 结果: ${success ? "PASS" : "FAIL"} ===`);
  process.exit(success ? 0 : 1);
})().catch((e) => {
  console.error("ERR:", e);
  process.exit(1);
});
