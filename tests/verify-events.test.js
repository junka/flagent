// 验证事件机制与 Plan 门控
// mock 策略：替换 dist/llm/client 导出的 model（export let → 可写 exports.model）
// main-agent.js 持有 require("../llm/client") 同一引用，patch 即生效
// doGenerate 动态读取 mockTextFn()，支持多场景切换

const client = require("../dist/llm/client");
let mockTextFn = () => "";
client.model = {
  specificationVersion: "v2",
  provider: "mock",
  modelId: "mock-model",
  doGenerate: async () => ({
    content: [{ type: "text", text: mockTextFn() }],
    usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 },
    finishReason: "stop",
    warnings: [],
    response: { timestamp: new Date(), modelId: "mock-model", headers: {} },
  }),
};

const { MainAgent } = require("../dist/agents/main-agent");
const { ToolExecutor } = require("../dist/agents/tool-executor");
const { ToolRegistry } = require("../dist/agents/../tools/registry");
const { ContextManager } = require("../dist/agents/../context/context-manager");
const { Scheduler } = require("../dist/agents/scheduler");
const { PermissionManager } = require("../dist/agents/../permissions/permission-manager");
const { Session } = require("../dist/agents/../session/session");

function buildRegistry() {
  const registry = new ToolRegistry();
  registry.register({
    name: "echo",
    description: "echo back",
    parameters: { type: "object", properties: {} },
    concurrent: true,
    execute: async () => "echo-result",
  });
  return registry;
}

function buildSession() {
  return Session.create({
    id: "test-" + Math.random().toString(36).slice(2, 8),
    toolRegistry: buildRegistry(),
    confirmFn: async () => true,
    maxSteps: 5,
  });
}

let pass = 0;
let fail = 0;
const assert = (cond, msg) => {
  if (cond) {
    pass++;
    console.log("  ✓ " + msg);
  } else {
    fail++;
    console.log("  ✗ " + msg);
  }
};

async function main() {
  // 测试1：FINAL_ANSWER 事件流
  console.log("\n=== 测试1: FINAL_ANSWER 事件流 ===");
  {
    const session = buildSession();
    const events = [];
    mockTextFn = () => "THOUGHT: 简单算术\nFINAL_ANSWER: 2";
    const result = await session.run("1+1=?", {
      onEvent: (e) => events.push(e),
    });
    const types = events.map((e) => e.type);
    assert(
      types.includes("thought") && types.includes("finalAnswer"),
      "应触发 thought + finalAnswer 事件"
    );
    assert(types.includes("complete"), "应触发 complete 事件");
    assert(result.success === true, "返回 success=true");
    assert(
      result.finalAnswer === "2",
      "finalAnswer=2 (实际: " + JSON.stringify(result.finalAnswer) + ")"
    );
  }

  // 测试2：多步骤 Plan 门控 - 用户确认（验证 toolExecutor 事件桥接）
  console.log("\n=== 测试2: 多步骤 Plan 门控（确认）===");
  {
    const session = buildSession();
    const events = [];
    let confirmCalled = false;
    let call = 0;
    mockTextFn = () => {
      call++;
      if (call === 1)
        return "PLAN: 1. 侦察目标\n2. 分析结果\nTHOUGHT: 需多步\nACTIONS:\n  - echo({})\n  - echo({})";
      return "THOUGHT: 完成\nFINAL_ANSWER: done";
    };
    const result = await session.run("复杂任务", {
      onEvent: (e) => events.push(e),
      confirmPlan: async () => {
        confirmCalled = true;
        return true;
      },
    });
    const types = events.map((e) => e.type);
    assert(types.includes("plan"), "应触发 plan 事件");
    assert(
      events.find((e) => e.type === "plan").isMultiStep === true,
      "isMultiStep=true（含2编号步骤）"
    );
    assert(confirmCalled, "confirmPlan 应被调用");
    assert(types.includes("planConfirmed"), "应触发 planConfirmed 事件");
    assert(types.includes("actionStart"), "应触发 actionStart 事件");
    assert(types.includes("toolEnd"), "应触发 toolEnd 事件（ToolExecutor 桥接）");
    assert(
      events.filter((t) => t.type === "toolEnd").length === 2,
      "2 个 toolEnd（2 个 echo）"
    );
    assert(result.finalAnswer === "done", "确认后继续执行到 done");
  }

  // 测试3：多步骤 Plan 门控 - 用户拒绝
  console.log("\n=== 测试3: 多步骤 Plan 门控（拒绝）===");
  {
    const session = buildSession();
    const events = [];
    mockTextFn = () =>
      "PLAN: 1. 侦察\n2. 利用\n3. 清理\nTHOUGHT: 复杂\nACTIONS:\n  - echo({})";
    const result = await session.run("渗透任务", {
      onEvent: (e) => events.push(e),
      confirmPlan: async () => false,
    });
    const types = events.map((e) => e.type);
    assert(
      events.find((e) => e.type === "plan").isMultiStep === true,
      "3 编号步骤 isMultiStep=true"
    );
    assert(
      types.includes("planConfirmed") &&
        events.find((e) => e.type === "planConfirmed").confirmed === false,
      "planConfirmed=false"
    );
    assert(!types.includes("actionStart"), "拒绝后不应执行 actionStart");
    assert(result.success === true, "拒绝返回 success=true（结束）");
    assert(result.finalAnswer.includes("取消"), "finalAnswer 含'取消'");
  }

  // 测试4：单步骤 Plan（1编号 + 1动作）不门控
  console.log("\n=== 测试4: 单步骤 Plan 不门控 ===");
  {
    const session = buildSession();
    const events = [];
    let confirmCalled = false;
    let call = 0;
    mockTextFn = () => {
      call++;
      if (call === 1)
        return "PLAN: 1. 采集信息\nTHOUGHT: 单步\nACTIONS:\n  - echo({})";
      return "THOUGHT: ok\nFINAL_ANSWER: ok";
    };
    await session.run("简单采集", {
      onEvent: (e) => events.push(e),
      confirmPlan: async () => {
        confirmCalled = true;
        return true;
      },
    });
    const planEvent = events.find((e) => e.type === "plan");
    assert(
      planEvent && planEvent.isMultiStep === false,
      "1编号+1动作 isMultiStep=false"
    );
    assert(!confirmCalled, "单步骤不应调用 confirmPlan");
  }

  // 测试5：无 Plan 但 2 个并发动作（无门控，直接执行）
  console.log("\n=== 测试5: 无 Plan 2 并发动作（无门控，直接执行）===");
  {
    const session = buildSession();
    const events = [];
    let call = 0;
    mockTextFn = () => {
      call++;
      if (call === 1) return "THOUGHT: 并发采集\nACTIONS:\n  - echo({})\n  - echo({})";
      return "THOUGHT: ok\nFINAL_ANSWER: done";
    };
    const result = await session.run("并发采集", {
      onEvent: (e) => events.push(e),
    });
    const types = events.map((e) => e.type);
    assert(!types.includes("plan"), "无 PLAN 不触发 plan 事件");
    assert(types.includes("actionStart"), "触发 actionStart");
    assert(types.includes("toolEnd"), "触发 toolEnd");
    assert(result.finalAnswer === "done", "完成");
  }

  // 测试6：ToolExecutor 事件（直接测）
  console.log("\n=== 测试6: ToolExecutor toolStart/toolEnd 事件 ===");
  {
    const registry = buildRegistry();
    const te = new ToolExecutor(
      registry,
      new PermissionManager(async () => true)
    );
    const tevents = [];
    te.on("event", (e) => tevents.push(e.type));
    await te.executeBatch([
      { toolName: "echo", toolArgs: {} },
      { toolName: "echo", toolArgs: {} },
    ]);
    assert(tevents.filter((t) => t === "toolStart").length === 2, "2 个 toolStart");
    assert(tevents.filter((t) => t === "toolEnd").length === 2, "2 个 toolEnd");
  }

  // 测试7：isMultiStepPlan 纯逻辑（通过 Session.getMainAgent 访问 private）
  console.log("\n=== 测试7: isMultiStepPlan 纯逻辑 ===");
  {
    const session = buildSession();
    const agent = session.getMainAgent();
    const f = (plan, a, d) => agent.isMultiStepPlan(plan, a, d);
    assert(f("1. a\n2. b", 0, 0) === true, "2 编号步骤 → true");
    assert(f("1. a\n2. b\n3. c", 0, 0) === true, "3 编号步骤 → true");
    assert(f("1. a", 0, 0) === false, "1 编号步骤 → false");
    assert(f("无编号计划", 0, 0) === false, "无编号+0动作 → false");
    assert(f("无编号计划", 2, 0) === true, "无编号+2动作 → true");
    assert(f("无编号计划", 1, 1) === true, "无编号+1动作+1委派 → true");
    assert(f("1) a\n2) b", 0, 0) === true, "圆括号编号 2 步骤 → true");
    assert(f("1、a\n2、b", 0, 0) === true, "顿号编号 2 步骤 → true");
  }

  console.log(`\n=== 结果: ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error("测试异常:", e);
  process.exit(1);
});
