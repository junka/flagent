// 验证超长任务转后台机制（Session.run 层）
// mock 策略：doStream 延迟返回流，模拟长任务；设小 longTaskThresholdMs，
// 断言 onLongTask 在阈值后被触发一次，run 完成后定时器已清理（不重复触发）。

const client = require("../dist/llm/client");

let mockStreamFn = () => [];
let mockDelayMs = 0; // doStream 返回前的延迟（模拟长任务）

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
  doStream: async () => {
    if (mockDelayMs > 0) await new Promise((r) => setTimeout(r, mockDelayMs));
    return { stream: makeStream(mockStreamFn()) };
  },
};

const { ToolRegistry } = require("../dist/tools/registry");
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
    id: "longtest-" + Math.random().toString(36).slice(2, 8),
    toolRegistry: buildRegistry(),
    confirmFn: async () => true,
    maxSteps: 5,
  });
}

let pass = 0;
let fail = 0;
const assert = (cond, msg) => {
  if (cond) { pass++; console.log("  ✓ " + msg); }
  else { fail++; console.log("  ✗ " + msg); }
};

function streamFinalAnswer(answer) {
  return [
    { type: "stream-start", warnings: [] },
    { type: "tool-call", toolCallId: "c1", toolName: "final_answer", input: JSON.stringify({ answer }) },
    { type: "finish", finishReason: "tool-calls", usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 } },
  ];
}

async function main() {
  console.log("\n=== 测试1: 阈值后触发 onLongTask（仅一次）===");
  {
    const session = buildSession();
    // doStream 延迟 80ms（>阈值 30ms），模拟长任务
    mockDelayMs = 80;
    mockStreamFn = () => streamFinalAnswer("done");
    let fireCount = 0;
    let firedAt = 0;
    const t0 = Date.now();
    await session.run("长任务", {
      onEvent: () => {},
      longTaskThresholdMs: 30,
      onLongTask: () => { fireCount++; firedAt = Date.now() - t0; },
    });
    assert(fireCount === 1, `onLongTask 应触发 1 次（实际 ${fireCount}）`);
    // 允许 ±5ms 抖动（setTimeout 可能略早于阈值触发）
    assert(firedAt >= 25 && firedAt < 200, `应在阈值 30ms 附近触发（实际 ${firedAt}ms）`);
    mockDelayMs = 0;
  }

  console.log("\n=== 测试2: 短任务不触发 onLongTask ===");
  {
    const session = buildSession();
    mockDelayMs = 0; // 立即返回
    mockStreamFn = () => streamFinalAnswer("fast");
    let fireCount = 0;
    await session.run("短任务", {
      onEvent: () => {},
      longTaskThresholdMs: 100,
      onLongTask: () => { fireCount++; },
    });
    assert(fireCount === 0, `短任务不应触发 onLongTask（实际 ${fireCount}）`);
  }

  console.log("\n=== 测试3: run 完成后定时器已清理（不重复触发）===");
  {
    const session = buildSession();
    mockDelayMs = 50;
    mockStreamFn = () => streamFinalAnswer("ok");
    let fireCount = 0;
    await session.run("中任务", {
      onEvent: () => {},
      longTaskThresholdMs: 20,
      onLongTask: () => { fireCount++; },
    });
    // run 结束后再等 100ms，确认不再触发
    await new Promise((r) => setTimeout(r, 100));
    assert(fireCount === 1, `run 结束后不应再触发（实际 ${fireCount}）`);
    mockDelayMs = 0;
  }

  console.log(`\n=== 结果: ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch((e) => { console.error("测试异常:", e); process.exit(1); });
