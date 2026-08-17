// 阶段7 单元测试：Scheduler.registerDynamicAgent / unregisterDynamicAgent / dispatchConcurrent
// 无需网络与 LLM（全部 mock）。运行：node tests/stage7.test.js
const { z } = require("zod");
const { ToolRegistry } = require("../dist/tools");
const { ToolExecutor } = require("../dist/agents/tool-executor");
const { Scheduler } = require("../dist/agents/scheduler");

let pass = 0;
let fail = 0;
const ok = (name, cond) => {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}`); }
};

function makeRegistry() {
  const reg = new ToolRegistry();
  for (const name of ["tool_a", "tool_b", "tool_c"]) {
    reg.register({
      name,
      description: `测试工具 ${name}`,
      parameters: z.object({ x: z.string().optional() }),
      category: "test",
      concurrent: true,
      execute: async () => `result of ${name}`,
    });
  }
  return reg;
}

(async () => {
  // ============ Scheduler.registerDynamicAgent ============
  console.log("\n=== Scheduler.registerDynamicAgent ===");

  const reg = makeRegistry();
  const executor = new ToolExecutor(reg, undefined, 4);
  const scheduler = new Scheduler(reg, executor);

  // 成功注册
  const id = scheduler.registerDynamicAgent({
    id: "gen-foo",
    name: "Foo专家",
    role: "Foo分析",
    systemPrompt: "你是Foo专家",
    toolNames: ["tool_a", "tool_b"],
    maxSteps: 6,
  });
  ok("注册成功返回 id", id === "gen-foo");
  const agent = scheduler.getAgent("gen-foo");
  ok("getAgent 能取到", !!agent);
  ok("动态 agent role 正确", agent.role === "Foo分析");
  ok("动态 agent toolNames 正确", agent.toolNames.length === 2 && agent.toolNames[0] === "tool_a");
  ok("动态 agent 已纳入 getAllAgents", scheduler.getAllAgents().some((a) => a.id === "gen-foo"));

  // id 冲突
  let threw = false;
  try {
    scheduler.registerDynamicAgent({
      id: "gen-foo",
      name: "重复",
      role: "r",
      systemPrompt: "s",
      toolNames: ["tool_a"],
    });
  } catch (e) { threw = true; }
  ok("id 冲突抛错", threw);

  // 部分未知工具：过滤保留已知
  scheduler.registerDynamicAgent({
    id: "gen-partial",
    name: "Partial",
    role: "r",
    systemPrompt: "s",
    toolNames: ["tool_a", "nonexistent_tool", "tool_c"],
  });
  const partial = scheduler.getAgent("gen-partial");
  ok("部分未知工具被过滤", partial.toolNames.length === 2 && !partial.toolNames.includes("nonexistent_tool"));

  // 全部未知工具：拒绝
  threw = false;
  try {
    scheduler.registerDynamicAgent({
      id: "gen-empty",
      name: "Empty",
      role: "r",
      systemPrompt: "s",
      toolNames: ["nope1", "nope2"],
    });
  } catch (e) { threw = true; }
  ok("全部未知工具拒绝注册", threw);

  // 空 toolNames：拒绝
  threw = false;
  try {
    scheduler.registerDynamicAgent({
      id: "gen-noargs",
      name: "NoArgs",
      role: "r",
      systemPrompt: "s",
      toolNames: [],
    });
  } catch (e) { threw = true; }
  ok("空 toolNames 拒绝注册", threw);

  // 缺省 name/role 用 id 回退
  scheduler.registerDynamicAgent({
    id: "gen-bare",
    name: "",
    role: "",
    systemPrompt: "",
    toolNames: ["tool_a"],
  });
  const bare = scheduler.getAgent("gen-bare");
  ok("缺省 name 回退到 id", bare.name === "gen-bare");
  ok("缺省 role 回退到 id", bare.role === "gen-bare");

  // 默认 maxSteps=8
  ok("缺省 maxSteps=8", bare.maxSteps === 8);

  // ============ unregisterDynamicAgent ============
  console.log("\n=== unregisterDynamicAgent ===");
  const removed = scheduler.unregisterDynamicAgent("gen-foo");
  ok("注销返回 true", removed === true);
  ok("注销后 getAgent 为 undefined", scheduler.getAgent("gen-foo") === undefined);
  ok("注销不存在返回 false", scheduler.unregisterDynamicAgent("nope") === false);

  // ============ dispatchConcurrent: 未找到 agent ============
  console.log("\n=== dispatchConcurrent 与动态 agent ===");
  const miss = await scheduler.dispatchConcurrent([{ agentId: "not_exist", task: "x" }]);
  ok("未找到 agent 标记失败", miss.length === 1 && miss[0].success === false && miss[0].result.includes("未找到"));

  console.log(`\n=== 结果: ${pass} passed, ${fail} failed ===`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR:", e); process.exit(1); });
