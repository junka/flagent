// 阶段1 单元测试：ContextManager 并发安全（runLocked 锁 + addMessagesBatch）
// 用高 summaryThresholdTokens 避免触发 summarize（不依赖 LLM）。运行：node tests/stage1.test.js
const { ContextManager } = require("../dist/context");

let pass = 0;
let fail = 0;
const ok = (name, cond) => {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}`); }
};

// 高阈值配置：不触发 summarize，专注于并发写入竞态
const NO_SUMMARY = { summaryThresholdTokens: 1e9, maxContextTokens: 1e9, windowMessages: 5 };

(async () => {
  console.log("\n=== 阶段1：ContextManager 并发安全 ===");

  // ① 并发 20 次 addMessage，断言无丢失（锁串行化写入）
  const cm = new ContextManager(NO_SUMMARY);
  await Promise.all(
    Array.from({ length: 20 }, (_, i) =>
      cm.addMessage({ role: "user", content: `消息${i}` })
    )
  );
  ok("并发 20 次 addMessage 无丢失", cm.getMessages().length === 20);

  // ② addMessagesBatch 批量加入，只触发一次锁
  const cm2 = new ContextManager(NO_SUMMARY);
  await cm2.addMessagesBatch([
    { role: "tool", content: "obs1" },
    { role: "tool", content: "obs2" },
    { role: "tool", content: "obs3" },
  ]);
  ok("addMessagesBatch 批量加入", cm2.getMessages().length === 3);

  // ③ getActiveMessages 尊重 windowMessages
  const cm3 = new ContextManager({ ...NO_SUMMARY, windowMessages: 3 });
  for (let i = 0; i < 7; i++) {
    await cm3.addMessage({ role: "user", content: `m${i}` });
  }
  ok("getActiveMessages 返回最近 window 条", cm3.getActiveMessages().length === 3);
  ok("getActiveMessages 末条正确", cm3.getActiveMessages()[2].content === "m6");

  // ④ 小于 window 时全量返回
  const cm4 = new ContextManager({ ...NO_SUMMARY, windowMessages: 10 });
  await cm4.addMessage({ role: "user", content: "only" });
  ok("小于 window 时全量返回", cm4.getActiveMessages().length === 1);

  // ⑤ getTotalTokens 求和
  ok("getTotalTokens 求和 > 0", cm3.getTotalTokens() > 0);

  // ⑥ clear 清空消息与摘要
  cm3.clear();
  ok("clear 清空消息", cm3.getMessages().length === 0);
  ok("clear 清空摘要", cm3.getSummary() === "");

  // ⑦ 并发 addMessagesBatch 与 addMessage 混合不丢失
  const cm5 = new ContextManager({ ...NO_SUMMARY, windowMessages: 50 });
  await Promise.all([
    cm5.addMessagesBatch([
      { role: "user", content: "a" },
      { role: "user", content: "b" },
    ]),
    cm5.addMessage({ role: "user", content: "c" }),
    cm5.addMessagesBatch([{ role: "user", content: "d" }]),
  ]);
  ok("并发混合写入不丢失", cm5.getMessages().length === 4);

  // ⑧ getMessages 返回副本（外部修改不影响内部）
  const cm6 = new ContextManager(NO_SUMMARY);
  await cm6.addMessage({ role: "user", content: "x" });
  const snapshot = cm6.getMessages();
  snapshot.push({ role: "user", content: "injected", timestamp: 0, tokenCount: 0 });
  ok("getMessages 返回副本", cm6.getMessages().length === 1);

  console.log(`\n=== 结果: ${pass} passed, ${fail} failed ===`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR:", e); process.exit(1); });
