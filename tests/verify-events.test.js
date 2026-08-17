// 验证事件机制与 Plan 门控（tool_use 协议版）
// mock 策略：替换 dist/llm/client 导出的 model（CommonJS exports.model 可写）
// main-agent.js 持有 require("../llm/client") 同一引用，patch 即生效
// doStream 动态读取 mockStreamFn()，按场景输出 text-delta / tool-call / finish 流片段
//
// 迁移到原生 tool_use 协议后，旧文本协议（THOUGHT/ACTIONS/DELEGATE/FINAL_ANSWER 标记）
// 已移除；本文件验证新的 streamText + tools + stopWhen 事件流。

const client = require("../dist/llm/client");

// 每次调用返回一个流片段数组（LanguageModelV2StreamPart）
let mockStreamFn = () => [];

function makeStream(parts) {
  return new ReadableStream({
    start(controller) {
      for (const p of parts) controller.enqueue(p);
      controller.close();
    },
  });
}

client.model = {
  specificationVersion: "v4",
  provider: "mock",
  modelId: "mock-model",
  doStream: async () => ({
    stream: makeStream(mockStreamFn()),
  }),
};

const { MainAgent } = require("../dist/agents/main-agent");
const { ToolExecutor } = require("../dist/agents/tool-executor");
const { ToolRegistry } = require("../dist/tools/registry");
const { ContextManager } = require("../dist/context/context-manager");
const { Scheduler } = require("../dist/agents/scheduler");
const { PermissionManager } = require("../dist/permissions/permission-manager");
const { Session } = require("../dist/session/session");

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

// 构造一段 tool_use 流：先吐一段思考文本，再调用 final_answer 工具交卷
function streamThinkingThenFinalAnswer(thinking, answer) {
  return [
    { type: "stream-start", warnings: [] },
    { type: "text-start", id: "t1" },
    { type: "text-delta", id: "t1", delta: thinking },
    { type: "text-end", id: "t1" },
    { type: "tool-call", toolCallId: "call_1", toolName: "final_answer", input: JSON.stringify({ answer }) },
    { type: "finish", finishReason: "tool-calls", usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 } },
  ];
}

// 先调用 echo 工具（采集），下一步再 final_answer
function streamEchoOnly() {
  return [
    { type: "stream-start", warnings: [] },
    { type: "tool-call", toolCallId: "call_e", toolName: "echo", input: JSON.stringify({}) },
    { type: "finish", finishReason: "tool-calls", usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 } },
  ];
}

async function main() {
  // 测试1：final_answer 事件流（thinking + finalAnswer + complete）
  console.log("\n=== 测试1: final_answer 事件流 ===");
  {
    const session = buildSession();
    const events = [];
    mockStreamFn = () => streamThinkingThenFinalAnswer("正在计算 1+1", "2");
    const result = await session.run("1+1=?", {
      onEvent: (e) => events.push(e),
    });
    const types = events.map((e) => e.type);
    assert(types.includes("thinking"), "应触发 thinking 事件（textStream delta）");
    assert(types.includes("finalAnswer"), "应触发 finalAnswer 事件");
    assert(types.includes("complete"), "应触发 complete 事件");
    assert(result.success === true, "返回 success=true（final_answer toolCall 命中）");
    assert(
      result.finalAnswer === "2",
      "finalAnswer=2 (实际: " + JSON.stringify(result.finalAnswer) + ")"
    );
  }

  // 测试2：先调用 echo 工具采集，再 final_answer 交卷（验证 tool 循环）
  console.log("\n=== 测试2: 工具调用循环（echo → final_answer）===");
  {
    const session = buildSession();
    const events = [];
    let call = 0;
    mockStreamFn = () => {
      call++;
      if (call === 1) {
        // 第一步：调用 echo
        return streamEchoOnly();
      }
      // 第二步：交卷
      return streamThinkingThenFinalAnswer("已采集", "done");
    };
    const result = await session.run("采集并回答", {
      onEvent: (e) => events.push(e),
    });
    const types = events.map((e) => e.type);
    assert(call === 2, "应执行 2 轮模型调用（echo + final_answer）");
    assert(result.success === true, "返回 success=true");
    assert(result.finalAnswer === "done", "finalAnswer=done");
    assert(
      events.filter((e) => e.type === "toolEnd").length >= 1,
      "应触发 toolEnd 事件（echo 执行）"
    );
  }

  // 测试3：ToolExecutor toolStart/toolEnd 事件（直接测，与主循环解耦）
  console.log("\n=== 测试3: ToolExecutor toolStart/toolEnd 事件 ===");
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

  console.log(`\n=== 结果: ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error("测试异常:", e);
  process.exit(1);
});
