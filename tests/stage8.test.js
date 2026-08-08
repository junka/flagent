// 阶段8 单元测试：PLAN 解析（parseMainReactResponse 的 PLAN 段）
// 阶段8 主体是 prompt 工程（侦察→分类→深挖），可单测的是 PLAN 解析与 plan-only 步骤。
// 无需网络与 LLM。运行：node tests/stage8.test.js
const {
  parseMainReactResponse,
} = require("../dist/agents/react-parser");

let pass = 0;
let fail = 0;
const ok = (name, cond) => {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}`); }
};

(() => {
  console.log("\n=== 阶段8：PLAN 解析 ===");

  // ① 单行 PLAN
  let r = parseMainReactResponse(
    `PLAN: 先并发抓取两个目标再汇总
THOUGHT: 开始侦察
ACTIONS:
  - http_request({"url":"http://a.com"})`
  );
  ok("PLAN 单行解析", r.plan === "先并发抓取两个目标再汇总");
  ok("PLAN 与 THOUGHT 共存", r.thought === "开始侦察");
  ok("PLAN 与 ACTIONS 共存", r.actions.length === 1);

  // ② 多行 PLAN 续行
  r = parseMainReactResponse(
    `PLAN: 第一步并发侦察
第二步基于观察分类
第三步深挖或委派
THOUGHT: 执行第一步`
  );
  ok("PLAN 多行续行", r.plan === "第一步并发侦察\n第二步基于观察分类\n第三步深挖或委派");

  // ③ PLAN + ACTIONS（侦察后深挖）
  r = parseMainReactResponse(
    `PLAN: 侦察 example.com
ACTIONS:
  - web_fetch({"url":"http://example.com"})
  - http_request({"url":"http://example.com"})`
  );
  ok("PLAN + 多 ACTIONS", r.plan === "侦察 example.com" && r.actions.length === 2);

  // ④ 无 PLAN → 空字符串
  r = parseMainReactResponse("THOUGHT: 仅思考\nFINAL_ANSWER: 42");
  ok("无 PLAN 时空字符串", r.plan === "");

  // ⑤ plan-only（仅 PLAN 无动作，对应 plan-only 步骤）
  r = parseMainReactResponse("PLAN: 制定总体方案，下一步开始侦察");
  ok("plan-only 无 actions", r.actions.length === 0);
  ok("plan-only 无 delegates", r.delegates.length === 0);
  ok("plan-only 无 finalAnswer", r.finalAnswer === "");
  ok("plan-only 有 plan", r.plan === "制定总体方案，下一步开始侦察");

  // ⑥ 全角冒号 PLAN
  r = parseMainReactResponse("PLAN：全角冒号方案");
  ok("全角冒号 PLAN", r.plan === "全角冒号方案");

  // ⑦ PLAN 与 SPAWN_AGENT/DELEGATE 共存
  r = parseMainReactResponse(
    `PLAN: 此题为新题，自定义 agent 深挖
SPAWN_AGENT: {"id":"gen-x","name":"X","role":"r","systemPrompt":"s","toolNames":["tool_a"]}
DELEGATE: gen-x`
  );
  ok("PLAN + SPAWN_AGENT + DELEGATE", r.plan !== "" && r.spawnAgents.length === 1 && r.delegates.length === 1);

  // ⑧ FINAL_ANSWER 时无 plan
  r = parseMainReactResponse("THOUGHT: 完成\nFINAL_ANSWER: 答案");
  ok("FINAL_ANSWER 时无 plan", r.plan === "");

  // ⑨ 无键文本 plan 为空
  r = parseMainReactResponse("纯文本无键");
  ok("无键文本 plan 空", r.plan === "");

  console.log(`\n=== 结果: ${pass} passed, ${fail} failed ===`);
  process.exit(fail === 0 ? 0 : 1);
})();
