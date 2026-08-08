// 阶段5 单元测试：公共 ReAct 解析器（parseReactResponse / parseToolCallLine）
// 供 SubAgent 与 MainAgent(单工具回退) 共用。无需网络与 LLM。运行：node tests/stage5.test.js
const {
  parseReactResponse,
  parseToolCallLine,
} = require("../dist/agents/react-parser");

let pass = 0;
let fail = 0;
const ok = (name, cond) => {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}`); }
};

(() => {
  console.log("\n=== 阶段5：ReAct 解析器 ===");

  // ---------- parseReactResponse ----------
  let r = parseReactResponse(
    "THOUGHT: 需要抓取\nACTION: http_request({\"url\":\"http://x.com\"})"
  );
  ok("THOUGHT 解析", r.thought === "需要抓取");
  ok("ACTION 解析", r.action === 'http_request({"url":"http://x.com"})');
  ok("无 FINAL_ANSWER", r.finalAnswer === "");
  ok("无 DELEGATE", r.delegateAgent === "");

  r = parseReactResponse("THOUGHT: 完成\nFINAL_ANSWER: 答案是42");
  ok("FINAL_ANSWER 解析", r.finalAnswer === "答案是42");
  ok("FINAL_ANSWER 时无 action", r.action === "");

  r = parseReactResponse("THOUGHT: 委派\nDELEGATE: web");
  ok("DELEGATE 解析", r.delegateAgent === "web");

  // 多行 THOUGHT 续行
  r = parseReactResponse("THOUGHT: 第一行\n第二行\nACTION: tool_a({})");
  ok("THOUGHT 多行续行", r.thought === "第一行\n第二行");

  // 全角冒号
  r = parseReactResponse("THOUGHT：全角");
  ok("全角冒号 THOUGHT", r.thought === "全角");

  // 全键空文本
  r = parseReactResponse("无任何键的纯文本");
  ok("无键文本全空", r.thought === "" && r.action === "" && r.finalAnswer === "");

  // ---------- parseToolCallLine ----------
  let tc = parseToolCallLine('http_request({"url":"http://x.com","timeout":5000})');
  ok("工具名解析", tc.toolName === "http_request");
  ok("工具参数 url", tc.toolArgs.url === "http://x.com");
  ok("工具参数 timeout", tc.toolArgs.timeout === 5000);

  tc = parseToolCallLine("tool_a()");
  ok("无参数工具名", tc.toolName === "tool_a");
  ok("无参数空对象", JSON.stringify(tc.toolArgs) === "{}");

  tc = parseToolCallLine("not a tool call");
  ok("非工具调用返回空名", tc.toolName === "");

  tc = parseToolCallLine("bad({invalid json})");
  ok("畸形 JSON 返回空对象", tc.toolName === "bad" && JSON.stringify(tc.toolArgs) === "{}");

  // 多行 JSON 参数
  tc = parseToolCallLine('tool_a({\n  "x": 1\n})');
  ok("多行 JSON 参数", tc.toolArgs.x === 1);

  // 带空格的工具调用
  tc = parseToolCallLine('tool_a ({"x": 1})');
  ok("工具名后带空格", tc.toolName === "tool_a" && tc.toolArgs.x === 1);

  console.log(`\n=== 结果: ${pass} passed, ${fail} failed ===`);
  process.exit(fail === 0 ? 0 : 1);
})();
