// 阶段10 e2e：会话管理真实运行（LLM）+ 持久化恢复 + 会话隔离
// 用最小工具集（echo）经 SessionManager 驱动真实 MainAgent.run，验证：
//   ① session.run 真实执行（echo 被调用、答案含回显文本）
//   ② 会话隔离（A/B 上下文互不污染，独立 ContextManager 实例）
//   ③ 持久化 + 跨实例 resume 恢复（messages/steps/title 完整还原）
// 需 .env 与网络。运行：node tests/e2e-stage10.test.js
const os = require("os");
const path = require("path");
const fs = require("fs");
const { SessionManager, ToolRegistry } = require("../dist/index");
const { z } = require("zod");

const ECHO_TEXT = "flagent-sess-A";

(async () => {
  // 最小工具集：仅 echo，保证 MainAgent 稳定直接调用（与 e2e-stage9 一致策略）
  const reg = new ToolRegistry();
  reg.register({
    name: "echo",
    description: "回显输入的文本（测试用工具）",
    parameters: z.object({ text: z.string() }),
    category: "test",
    concurrent: true,
    execute: async (args) => `[echo] ${args.text}`,
  });

  const storeDir = fs.mkdtempSync(path.join(os.tmpdir(), "flagent-e2e-s10-"));
  const confirmFn = async () => true;
  const mgr = new SessionManager({ toolRegistry: reg, confirmFn, storeDir });

  // ① 真实运行 session A（LLM）
  const a = await mgr.create("echo-test");
  console.log(`会话 A: ${a.id.slice(0, 8)} (echo-test)`);
  console.log("运行真实 MainAgent（LLM）...\n");
  const task = `请用 echo 工具回显文本 "${ECHO_TEXT}"，然后告诉我 echo 返回了什么。`;
  const result = await mgr.run(task); // 经 manager 运行 → run 后自动持久化 A

  console.log("=== A 最终答案 ===");
  console.log(result.finalAnswer);
  console.log(
    `\n步数: ${result.steps.length}  成功: ${result.success}  耗时: ${(result.duration / 1000).toFixed(1)}s`
  );

  const usedEcho = result.steps.some((s) => s.action.startsWith("TOOL: echo"));
  const hasText = /flagent-sess-A/.test(result.finalAnswer);
  const runOk = result.success && usedEcho && hasText;
  console.log(`\necho 被调用: ${usedEcho}  答案含回显文本: ${hasText}`);

  // ② 会话隔离：B 注入独立消息，A/B 互不污染
  const b = await mgr.create("iso-test");
  b.getContextManager().restoreMessages([{ role: "user", content: "ISOLATION-B" }], "");

  const aMsgs = a.getContextManager().getMessages();
  const bMsgs = b.getContextManager().getMessages();
  const aHasEcho = aMsgs.some((m) => m.content.includes(ECHO_TEXT));
  const aNoB = !aMsgs.some((m) => m.content.includes("ISOLATION-B"));
  const bHasIso = bMsgs.some((m) => m.content.includes("ISOLATION-B"));
  const bNoA = !bMsgs.some((m) => m.content.includes(ECHO_TEXT));
  const independentCtx = a.getContextManager() !== b.getContextManager();
  const isolated = aHasEcho && aNoB && bHasIso && bNoA && independentCtx;
  console.log(
    `\n隔离: A含回显=${aHasEcho} A无B=${aNoB} B含ISOLATION=${bHasIso} B无A=${bNoA} 独立实例=${independentCtx}`
  );

  // ③ 持久化 + 跨实例 resume（模拟重启）
  const aStepsBefore = a.getSteps().length;
  const aMsgCountBefore = aMsgs.length;
  await mgr.switch(a.id);
  await mgr.persistActive();

  const mgr2 = new SessionManager({ toolRegistry: reg, confirmFn, storeDir });
  const restored = await mgr2.resume(a.id);
  const rMsgs = restored.getContextManager().getMessages();
  const restoredOk =
    restored.title === "echo-test" &&
    rMsgs.some((m) => m.content.includes(ECHO_TEXT)) &&
    restored.getSteps().length === aStepsBefore &&
    rMsgs.length === aMsgCountBefore;
  console.log(
    `\n恢复: title=${restored.title} msgs=${rMsgs.length}(原${aMsgCountBefore}) steps=${restored.getSteps().length}(原${aStepsBefore})`
  );

  // 清理临时目录
  try {
    fs.rmSync(storeDir, { recursive: true, force: true });
  } catch {}

  console.log(`\n=== 检测 ===`);
  console.log(`① session.run 真实执行: ${runOk}`);
  console.log(`② 会话隔离: ${isolated}`);
  console.log(`③ 持久化恢复: ${restoredOk}`);

  const success = runOk && isolated && restoredOk;
  console.log(`\n=== 结果: ${success ? "PASS" : "FAIL"} ===`);
  process.exit(success ? 0 : 1);
})().catch((e) => {
  console.error("ERR:", e);
  process.exit(1);
});
