// 验证「挤转后台」并发模型的核心架构不变量：
//   1. SessionManager 可同时持有多个 session，其中一个在后台 run、另一个在前台 run；
//   2. 两个并发 run 落在不同 MainAgent 实例上（每会话独立 agent 图），互不串扰上下文；
//   3. 原 session 后台 run 完成后，persist(原 sessionId) 能持久化其 messages/steps；
//   4. 新 session（前台）的 finalAnswer 不被原 session 的 run 污染。
//
// 这是对齐 Claude Code「后台=独立 dispatched session」模型的关键验证：
// 不在同会话上并发 run，而是新建独立 session 承接新输入。
//
// mock 策略：doStream 用「门闩」控制——第一个 session 的 run 阻塞在门闩上（模拟长任务），
// 期间启动第二个 session 的 run（立即完成），断言两者隔离；随后放开门闩让第一个完成。

const client = require("../dist/llm/client");

/**
 * 按「调用序号」分流的 mock：每次 doStream 调用返回 streamFn(callIdx) 的流。
 * 避免全局可变 streamFn 在并发 run 中串扰（早期版本用全局 fn 会被覆盖，
 * 导致阻塞中的第一个 run 放开后读到第二个 run 的流——纯 mock 工件，非真实泄漏）。
 */
let streamFnByCall = null;
let callIdx = 0;
/** 门闩：resolve 前第一次 doStream 调用一直阻塞，模拟长任务。 */
let gatePromise = null;
function resetGate() { gatePromise = new Promise((r) => { gateResolve = r; }); }
let gateResolve = null;
function openGate() { if (gateResolve) gateResolve(); }

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
    const idx = callIdx++;
    // 第一次 doStream 调用（第一个 session 的长任务）阻塞在门闩上
    if (idx === 0 && gatePromise) await gatePromise;
    const parts = streamFnByCall ? streamFnByCall(idx) : [];
    return { stream: makeStream(parts) };
  },
};

const { ToolRegistry } = require("../dist/tools/registry");
const { SessionManager } = require("../dist/session/session-manager");
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
  console.log("\n=== 测试1: 后台 session 与前台 session 并发，互不串扰 ===");
  {
    const sessionManager = new SessionManager({
      toolRegistry: buildRegistry(),
      confirmFn: async () => true,
      storeDir: "/tmp/flagent-squeeze-test-" + Math.random().toString(36).slice(2, 8),
    });

    // 第一个 session（将作为「原前台任务」被挤转后台）
    const sess1 = await sessionManager.create("长任务A");
    const sess1Id = sess1.id;

    // 按调用序号分流：call 0 → A 的答案（长任务，阻塞门闩）；call 1 → B 的答案（前台新任务）
    callIdx = 0;
    streamFnByCall = (idx) => streamFinalAnswer(idx === 0 ? "A 的最终答案" : "B 的最终答案");
    resetGate();

    // 启动第一个 run（不 await，模拟 CLI 里 bump 后原 session 继续 await 但已在后台）
    const run1Promise = sess1.run("长任务A", { onEvent: () => {} });

    // 等一拍确保 run1 已进入 doStream 阻塞（call 0）
    await new Promise((r) => setTimeout(r, 30));

    // 断言1：此时 sessionManager 仍只有 sess1（尚未 create 新 session）
    assert(sessionManager.getActiveId() === sess1Id, "挤入前 active 应是原 session");

    // 模拟 CLI 的 bump 后行为：新建独立 session 承接新输入
    const sess2 = await sessionManager.create("新任务B");
    const sess2Id = sess2.id;
    assert(sess2Id !== sess1Id, "新 session id 应不同于原 session");
    assert(sessionManager.getActiveId() === sess2Id, "create 后 active 应切到新 session");
    assert(sessionManager.get(sess1Id) !== undefined, "原 session 仍应留在 sessions map 中");

    // 断言2：两个 session 是不同 MainAgent 实例（核心：零竞态前提）
    const ma1 = sess1.getMainAgent();
    const ma2 = sess2.getMainAgent();
    assert(ma1 !== ma2, "两个 session 的 MainAgent 应是不同实例");
    assert(sess1.getContextManager() !== sess2.getContextManager(), "两个 ContextManager 应是不同实例");

    // 放开门闩：run1（call 0）解除阻塞并完成，返回 A 的答案
    openGate();
    const r1 = await run1Promise;
    assert(r1 !== null && r1 !== undefined, "原 session 后台 run 应正常完成");

    // 持久化原 session（模拟 CLI 完成分支的 persist(bumpedSessionId)）
    await sessionManager.persist(sess1Id);

    // 前台 sess2 跑新任务（call 1 → B 的答案，门闩已开放不阻塞）
    const r2 = await sess2.run("新任务B", { onEvent: () => {} });
    assert(r2 !== null && r2 !== undefined, "新 session 前台 run 应正常完成");

    // 断言3：两个 session 的 context 完全隔离——sess1 只含 A 的答案，sess2 只含 B 的答案
    const cm1Msgs = sess1.getContextManager().getMessages();
    const cm2Msgs = sess2.getContextManager().getMessages();
    assert(cm1Msgs !== cm2Msgs, "两 session messages 数组应是不同引用");
    const s1Contents = cm1Msgs.map((m) => String(m.content));
    const s2Contents = cm2Msgs.map((m) => String(m.content));
    assert(!s1Contents.includes("B 的最终答案"), "新 session 的答案 B 不应泄漏到原 session");
    assert(!s2Contents.includes("A 的最终答案"), "原 session 的答案 A 不应泄漏到新 session");
    assert(s1Contents.includes("A 的最终答案"), "原 session 应保留自己的答案 A");
    assert(s2Contents.includes("B 的最终答案"), "新 session 应保留自己的答案 B");
  }

  console.log("\n=== 测试2: persist 持久化非 active session（原后台 session）===");
  {
    const dir = "/tmp/flagent-squeeze-test-" + Math.random().toString(36).slice(2, 8);
    const sessionManager = new SessionManager({
      toolRegistry: buildRegistry(),
      confirmFn: async () => true,
      storeDir: dir,
    });
    const sess1 = await sessionManager.create("原任务");
    const sess1Id = sess1.id;
    callIdx = 0;
    gatePromise = null; // 不阻塞
    streamFnByCall = () => streamFinalAnswer("原答案");
    await sess1.run("原任务", { onEvent: () => {} });

    // 切到新 session（active 变为 sess2）
    const sess2 = await sessionManager.create("新任务");
    assert(sessionManager.getActiveId() === sess2.id, "active 已切到新 session");

    // persist 原 session（非 active）——应能写入磁盘
    await sessionManager.persist(sess1Id);
    const fs = require("fs");
    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json"));
    assert(files.includes(sess1Id + ".json"), "原 session 应已持久化到磁盘");
  }

  console.log(`\n=== 结果: ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch((e) => { console.error("测试异常:", e); process.exit(1); });
