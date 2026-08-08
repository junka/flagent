// 阶段7 e2e：动态注册 agent → dispatchConcurrent → 真实 ReAct（LLM + 工具）
// 验证 registerDynamicAgent 创建的 SubAgent 能通过共享 toolExecutor 执行工具并返回结果。
// 需配置 .env (DASHSCOPE_API_KEY) 与网络。运行：node tests/e2e-stage7.test.js
const { createAgentSystem } = require("../dist/cli/index");
const { createToolRegistry } = require("../dist/tools");
const {
  PermissionManager,
} = require("../dist/permissions/permission-manager");

(async () => {
  const pm = new PermissionManager(async () => true); // 自动批准副作用工具
  const toolRegistry = createToolRegistry();
  const mainAgent = createAgentSystem({ toolRegistry, permissionManager: pm }).mainAgent;
  const scheduler = mainAgent.getScheduler();

  console.log("预设 agent 数:", scheduler.getAllAgents().length);

  // 动态注册一个"Web 侦察"通用 agent（自定义 role + 工具子集）
  const dynId = scheduler.registerDynamicAgent({
    id: "gen-webrecon",
    name: "Web侦察通用agent",
    role: "Web侦察分析员",
    systemPrompt:
      "你是 Web 侦察分析员。接到任务后用 web_fetch 抓取目标页面，提取标题与关键信息后给出结论。请用中文回复。",
    toolNames: ["web_fetch", "http_request"],
    maxSteps: 5,
  });
  console.log("动态注册 agent id:", dynId);
  const dyn = scheduler.getAgent(dynId);
  console.log("动态 agent 工具集:", dyn.toolNames.join(", "));

  // 委派任务给动态 agent（验证可复用 + 真实 ReAct）
  const task = "抓取 http://example.com 的页面标题并简述其内容。";

  console.log("\n运行 dispatchConcurrent（真实 LLM）...\n");
  const results = await scheduler.dispatchConcurrent([
    { agentId: "gen-webrecon", task },
  ]);

  let success = false;
  for (const r of results) {
    console.log(`=== [${r.agentId}] success=${r.success} ===`);
    console.log(r.result.slice(0, 400));
    console.log("");
    success = success || (r.success && /example/i.test(r.result));
  }

  // 清理：注销动态 agent
  scheduler.unregisterDynamicAgent("gen-webrecon");
  console.log("注销后是否仍存在:", scheduler.getAgent("gen-webrecon") ? "是" : "否");

  const ok = success;
  console.log(`\n=== 结果: ${ok ? "PASS" : "FAIL"} ===`);
  process.exit(ok ? 0 : 1);
})().catch((e) => {
  console.error("ERR:", e);
  process.exit(1);
});
