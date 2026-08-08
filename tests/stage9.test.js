// 阶段9 单元测试：端到端集成与导出
// ① 包入口导出完整性 ② createAgentSystem 装配（ToolExecutor 注入主/子/Scheduler）③ summarizeNow 短对话无 LLM
// 无需网络与 LLM（summarizeNow 在短对话下不触发摘要）。运行：node tests/stage9.test.js
const pkg = require("../dist/index");
const { createAgentSystem } = require("../dist/cli/index");
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
  console.log("\n=== 阶段9：导出完整性 ===");

  // ① 包入口导出所有公共 API
  const expected = [
    "ContextManager", "ToolRegistry", "createDefaultTools", "createWebTools",
    "createPwnTools", "createReverseTools", "createCryptoTools", "createMiscTools",
    "createToolRegistry",
    "SubAgent", "Scheduler", "MainAgent", "ToolExecutor",
    "parseReactResponse", "parseToolCallLine", "parseMainReactResponse",
    "createAgentSystem",
    "PermissionManager", "model",
  ];
  for (const name of expected) {
    ok(`导出 ${name}`, typeof pkg[name] === "function" || typeof pkg[name] === "object");
  }

  console.log("\n=== 阶段9：createAgentSystem 装配 ===");

  // ② 装配：ToolExecutor 统一注入 MainAgent / SubAgent / Scheduler
  const pm = new PermissionManager(async () => true);
  const toolRegistry = pkg.createToolRegistry();
  const mainAgent = createAgentSystem({ toolRegistry, permissionManager: pm }).mainAgent;

  ok("MainAgent.getToolExecutor() 非空", !!mainAgent.getToolExecutor());
  ok("MainAgent.getToolRegistry() 非空", !!mainAgent.getToolRegistry());
  ok("MainAgent.getScheduler() 非空", !!mainAgent.getScheduler());
  ok("MainAgent.getContextManager() 非空", !!mainAgent.getContextManager());

  const scheduler = mainAgent.getScheduler();
  const agents = scheduler.getAllAgents();
  ok("预设 5 个子智能体", agents.length === 5);

  const presetIds = ["web", "pwn", "reverse", "crypto", "misc"];
  ok("预设 id 齐全", presetIds.every((id) => scheduler.getAgent(id) !== undefined));

  // 每个预设子智能体都注入了共享 toolExecutor（运行时访问编译后的属性）
  const allHaveExecutor = agents.every((a) => a.toolExecutor !== undefined && a.toolExecutor !== null);
  ok("所有子智能体注入 toolExecutor", allHaveExecutor);

  // 主控与子智能体共享同一 toolExecutor 实例
  const shared = mainAgent.getToolExecutor();
  ok("主/子共享同一 ToolExecutor 实例", agents.every((a) => a.toolExecutor === shared));

  // 子智能体 maxSteps=8
  ok("子智能体 maxSteps=8", agents.every((a) => a.maxSteps === 8));

  // Scheduler 可动态注册（间接验证 toolRegistry 注入）
  const dynId = scheduler.registerDynamicAgent({
    id: "gen-test",
    name: "测试",
    role: "r",
    systemPrompt: "s",
    toolNames: ["http_request"],
    maxSteps: 4,
  });
  ok("Scheduler.registerDynamicAgent 可用", dynId === "gen-test" && !!scheduler.getAgent("gen-test"));
  ok("动态 agent 也注入共享 toolExecutor", scheduler.getAgent("gen-test").toolExecutor === shared);
  scheduler.unregisterDynamicAgent("gen-test");

  console.log("\n=== 阶段9：summarizeNow（短对话不触发 LLM） ===");

  // ③ 短对话（<= windowMessages）summarizeNow 不触发 LLM，返回空
  const { ContextManager } = pkg;
  const cm = new ContextManager({ summaryThresholdTokens: 1e9, maxContextTokens: 1e9, windowMessages: 10 });
  for (let i = 0; i < 3; i++) {
    await cm.addMessage({ role: "user", content: `短消息${i}` });
  }
  const summary = await cm.summarizeNow();
  ok("短对话 summarizeNow 返回空串", summary === "");
  ok("短对话消息不丢失", cm.getMessages().length === 3);

  console.log(`\n=== 结果: ${pass} passed, ${fail} failed ===`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR:", e); process.exit(1); });
