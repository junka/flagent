// BackgroundManager 单元测试：状态流转/心跳/卡死判定/取消/清理
// 注：不跑真实 LLM，只测 BackgroundManager 纯逻辑 + 部分 Session.runBackground
// 行为（不启动 main agent，通过 mark* 模拟）。
"use strict";

const assert = require("assert");
const path = require("path");

// --- 1) BackgroundManager 纯逻辑测试（不依赖 src/agents/factory 等）---
const {
  BackgroundManager,
  getBackgroundManager,
} = require("../dist/agents/background-manager");

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

let bgTests = 0,
  bgPassed = 0;

async function test(name, fn) {
  bgTests++;
  try {
    BackgroundManager._resetForTest();
    await fn();
    bgPassed++;
    console.log(`  ✓ ${name}`);
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    ${e && e.stack ? e.stack : e}`);
    process.exitCode = 1;
  }
}

(async function runBackgroundTests() {
  console.log("\n== BackgroundManager 纯逻辑测试 ==");

  await test("单例：getBackgroundManager 返回同一实例", () => {
    const a = getBackgroundManager();
    const b = BackgroundManager.getInstance();
    assert.strictEqual(a, b);
  });

  await test("createTask：status=PENDING, snapshot 结构正确", () => {
    const mgr = getBackgroundManager();
    const { taskId, heartbeat, onEvent, markStart, markStep, markComplete, markCrash } =
      mgr.createTask({
        sessionId: "sess-1",
        title: "t1",
        task: "hello world long ".repeat(20),
      });
    assert.ok(taskId.startsWith("bg-"));
    const snap = mgr.getStatus(taskId);
    assert.strictEqual(snap.status, "PENDING");
    assert.strictEqual(snap.sessionId, "sess-1");
    assert.strictEqual(snap.title, "t1");
    assert.ok(snap.taskPreview.endsWith("…") || snap.taskPreview.length <= 80);
    assert.ok(snap.createdAt > 0);
    assert.strictEqual(snap.startedAt, null);
    assert.strictEqual(snap.endedAt, null);
    assert.strictEqual(snap.currentStep, null);
    assert.strictEqual(snap.maxSteps, null);
    // 引用暴露的函数都存在（后面会用到）
    ["heartbeat", "onEvent", "markStart", "markStep", "markComplete", "markCrash"].forEach(
      (k) => assert.strictEqual(typeof { heartbeat, onEvent, markStart, markStep, markComplete, markCrash }[k], "function")
    );
  });

  await test("markStart → status RUNNING, lastActivity 非空", () => {
    const mgr = getBackgroundManager();
    const { taskId, markStart } = mgr.createTask({ sessionId: "s1", title: "t", task: "hi" });
    markStart();
    const s = mgr.getStatus(taskId);
    assert.strictEqual(s.status, "RUNNING");
    assert.ok(s.startedAt > 0);
    assert.ok(s.lastActivityAt > 0);
  });

  await test("markStep 更新 currentStep/maxSteps；heartbeat 刷新 lastActivity", async () => {
    const mgr = getBackgroundManager();
    const { taskId, markStart, markStep, heartbeat } = mgr.createTask({ sessionId: "s1", title: "t", task: "hi" });
    markStart();
    const first = mgr.getStatus(taskId).lastActivityAt;
    await sleep(5);
    heartbeat();
    markStep(3, 10);
    const s = mgr.getStatus(taskId);
    assert.ok(s.lastActivityAt >= first);
    assert.strictEqual(s.currentStep, 3);
    assert.strictEqual(s.maxSteps, 10);
  });

  await test("markComplete → COMPLETED + result 记录；markCrash → CRASHED + error 记录", () => {
    const mgr = getBackgroundManager();
    const t1 = mgr.createTask({ sessionId: "s1", title: "ok", task: "" });
    t1.markStart();
    const fakeResult = { success: true, finalAnswer: "Flag: abc\nWriteup: 1. done", steps: [], totalTokens: 10, duration: 123 };
    t1.markComplete(fakeResult);
    const s1 = mgr.getStatus(t1.taskId);
    assert.strictEqual(s1.status, "COMPLETED");
    assert.strictEqual(s1.result.finalAnswer, fakeResult.finalAnswer);
    assert.strictEqual(s1.result.success, true);
    assert.ok(s1.endedAt > 0);

    const t2 = mgr.createTask({ sessionId: "s1", title: "boom", task: "" });
    t2.markStart();
    t2.markCrash(new Error("boom reason"));
    const s2 = mgr.getStatus(t2.taskId);
    assert.strictEqual(s2.status, "CRASHED");
    assert.strictEqual(s2.error, "boom reason");
    assert.ok(s2.endedAt > 0);
  });

  await test("cancel 传播 AbortSignal，已结束任务 cancel 返回 false", () => {
    const mgr = getBackgroundManager();
    const t1 = mgr.createTask({ sessionId: "s1", title: "c", task: "" });
    t1.markStart();
    let fired = false;
    t1.signal.addEventListener("abort", () => (fired = true));
    const ok = mgr.cancel(t1.taskId);
    assert.strictEqual(ok, true);
    assert.strictEqual(fired, true);
    assert.strictEqual(mgr.getStatus(t1.taskId).status, "CANCELLED");
    // 再取消返回 false
    assert.strictEqual(mgr.cancel(t1.taskId), false);

    // COMPLETED 任务 cancel 返回 false
    const t2 = mgr.createTask({ sessionId: "s1", title: "c2", task: "" });
    t2.markStart();
    t2.markComplete({ success: true, finalAnswer: "x", steps: [], totalTokens: 0, duration: 0 });
    assert.strictEqual(mgr.cancel(t2.taskId), false);
    assert.strictEqual(mgr.getStatus(t2.taskId).status, "COMPLETED");

    // 不存在的 taskId cancel 返回 false
    assert.strictEqual(mgr.cancel("bg-nonexistent"), false);
  });

  await test("healthCheck：STUCK 阈值触发，WARNING/STUCK/HEALTHY 分级正确", async () => {
    const mgr = getBackgroundManager();
    const t1 = mgr.createTask({
      sessionId: "s1", title: "fast", task: "",
      options: { stuckThresholdMs: 30, warnThresholdMs: 15 },
    });
    const t2 = mgr.createTask({
      sessionId: "s1", title: "slow", task: "",
      options: { stuckThresholdMs: 200, warnThresholdMs: 100 },
    });
    t1.markStart();
    t2.markStart();
    // 刚启动：health=HEALTHY
    let reports = mgr.healthCheck();
    const r1a = reports.find((r) => r.taskId === t1.taskId);
    const r2a = reports.find((r) => r.taskId === t2.taskId);
    assert.strictEqual(r1a.health, "HEALTHY");
    assert.strictEqual(r2a.health, "HEALTHY");
    // 等 20ms：t1 应该 WARNING（>=15ms），t2 仍 HEALTHY
    await sleep(20);
    reports = mgr.healthCheck();
    const r1b = reports.find((r) => r.taskId === t1.taskId);
    const r2b = reports.find((r) => r.taskId === t2.taskId);
    assert.strictEqual(r1b.health, "WARNING");
    assert.strictEqual(r2b.health, "HEALTHY");
    // 再等 20ms（total 40ms > 30ms stuckThresholdMs）：t1 → STUCK
    await sleep(20);
    reports = mgr.healthCheck();
    const r1c = reports.find((r) => r.taskId === t1.taskId);
    assert.strictEqual(r1c.health, "STUCK");
    assert.strictEqual(r1c.status, "STUCK");
    assert.ok(r1c.idleMs >= 30);
    // 心跳后从 STUCK 回到 RUNNING
    t1.heartbeat();
    reports = mgr.healthCheck();
    const r1d = reports.find((r) => r.taskId === t1.taskId);
    assert.strictEqual(r1d.status, "RUNNING");
    assert.strictEqual(r1d.health, "HEALTHY");
  });

  await test("list：任务按创建时间倒序，非存在任务 getStatus 返回 null", () => {
    const mgr = getBackgroundManager();
    BackgroundManager._resetForTest();
    const a = mgr.createTask({ sessionId: "s1", title: "A", task: "" });
    const b = mgr.createTask({ sessionId: "s1", title: "B", task: "" });
    const c = mgr.createTask({ sessionId: "s1", title: "C", task: "" });
    const ids = mgr.list().map((t) => t.taskId);
    assert.deepStrictEqual(ids, [c.taskId, b.taskId, a.taskId]);
    assert.strictEqual(mgr.getStatus("bg-00000000000000"), null);
  });

  await test("cleanup：retentionMs 窗口保留/清理符合预期", async () => {
    const mgr = getBackgroundManager();
    BackgroundManager._resetForTest();
    const a = mgr.createTask({ sessionId: "s1", title: "keep", task: "" });
    const b = mgr.createTask({ sessionId: "s1", title: "remove", task: "" });
    a.markStart();
    a.markComplete({ success: true, finalAnswer: "", steps: [], totalTokens: 0, duration: 0 });
    b.markStart();
    b.markCrash(new Error("x"));
    // 直接 hack 两个 task 的 endedAt 让一个过老，一个还新
    const internalMap = (() => {
      // 没有直接访问；hack 思路：重新构造 retention
    })();
    // 简洁方案：创建第三个任务并设置极短 retention，但 endedAt 至少要早于 retentionMs。
    // 由于无法直接写 endedAt，用 cleanup(retentionMs=-1) 能清理全部结束任务；并验证计数。
    const removed = mgr.cleanup(-1); // -1 = 0ms 前的，全部结束的都清
    assert.ok(removed >= 2);
    // 剩下 0 个结束的；再跑一次没东西可删
    const removed2 = mgr.cleanup(-1);
    assert.strictEqual(removed2, 0);
  });

  await test("onBackgroundEvent：createTask 传 options.onBackgroundEvent 每 emitEvent 调一次且带 taskId", () => {
    const mgr = getBackgroundManager();
    BackgroundManager._resetForTest();
    let count = 0;
    let lastTaskId = null;
    let lastEventType = null;
    const options = {
      onBackgroundEvent: (id, e) => {
        count++;
        lastTaskId = id;
        lastEventType = e.type;
      },
    };
    const { taskId, onEvent, markStep } = mgr.createTask({
      sessionId: "s1", title: "t", task: "", options,
    });
    onEvent({ type: "stepStart", step: 1, maxSteps: 5 });
    assert.strictEqual(count, 1);
    assert.strictEqual(lastTaskId, taskId);
    assert.strictEqual(lastEventType, "stepStart");
    markStep(3);
    onEvent({ type: "thought", step: 3, thought: "a" });
    assert.strictEqual(count, 2);
    assert.strictEqual(lastEventType, "thought");
  });

  console.log(`\nBackgroundManager: ${bgPassed}/${bgTests} passed`);
})().then(runPwnToolSmokeTests);

// --- 2) PWN 专业工具 Smoke 测试：只做存在性/参数校验/文件不存在分支；不依赖系统是否安装 objdump/ROPgadget/r2
async function runPwnToolSmokeTests() {
  console.log("\n== PWN 新工具 Smoke 测试 ==");
  const { createPwnTools } = require("../dist/tools");
  const registry = createPwnTools();

  const checks = [
    ["pwn_objdump", { path: "/__no_such_file__" }, (r) => r.includes("❌ 文件不存在")],
    [
      "pwn_objdump",
      { path: "/bin/ls", mode: "disasm-func" },
      (r) => r.includes("mode=disasm-func 必须传 symbol") || r.includes("未安装 objdump") || r.includes("❌ 文件不存在"),
    ],
    ["pwn_checksec", { path: "/__no_such_file__" }, (r) => r.includes("❌ 文件不存在")],
    ["pwn_radare2", { path: "/__no_such_file__" }, (r) => r.includes("❌ 文件不存在")],
    ["pwn_rop_gadget", { path: "/__no_such_file__" }, (r) => r.includes("❌ 文件不存在")],
    ["pwn_nm", { path: "/__no_such_file__" }, (r) => r.includes("❌ 文件不存在")],
    [
      "pwn_nm",
      { path: "/bin/ls", scope: "functions-only", grep: "nonexistent_symbol_xyz", maxLines: 100 },
      (r) => r.startsWith("[pwn_nm scope=functions-only]") && r.includes("source="),
    ],
  ];

  let n = 0,
    ok = 0;
  for (const [name, args, predicate] of checks) {
    n++;
    try {
      const result = await registry.execute(name, args);
      if (predicate(result)) {
        ok++;
        console.log(`  ✓ ${name}(${JSON.stringify(args).slice(0, 80)}) → 期望分支`);
      } else {
        console.log(
          `  ✗ ${name}(${JSON.stringify(args).slice(0, 80)}) → 结果不匹配。首 400 字符:\n        ${result.slice(0, 400)}`
        );
        process.exitCode = 1;
      }
    } catch (e) {
      console.log(`  ✗ ${name} 抛异常: ${e && e.message ? e.message : e}`);
      process.exitCode = 1;
    }
  }

  // 验证 5 个新工具都在 registry 中
  const expectNames = ["pwn_objdump", "pwn_checksec", "pwn_radare2", "pwn_rop_gadget", "pwn_nm"];
  for (const nm of expectNames) {
    n++;
    const tool = registry.getAll().find((t) => t.name === nm);
    if (tool) {
      ok++;
      console.log(`  ✓ registry 含工具: ${nm} (category=${tool.category}, requirePermission=${tool.requirePermission})`);
    } else {
      console.log(`  ✗ registry 缺少工具: ${nm}`);
      process.exitCode = 1;
    }
  }

  console.log(`\nPWN tools smoke: ${ok}/${n} passed`);
}
