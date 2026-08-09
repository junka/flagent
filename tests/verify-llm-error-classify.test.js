// 验证 classifyLLMError 对各类 LLM API 错误的分类准确性
// 覆盖：欠费(Arrearage)、额度耗尽(Forbidden)、鉴权(401)、模型不支持(400 model)、网络、未知
const { classifyLLMError } = require("../dist/cli/index");

let passed = 0,
  failed = 0;
function check(cond, msg) {
  if (cond) {
    passed++;
    console.log("  ✓ " + msg);
  } else {
    failed++;
    console.log("  ✗ " + msg);
  }
}

console.log("=== 1) 欠费 Arrearage（statusCode 400 + responseBody code=Arrearage）===");
// 完全复刻用户本次遇到的错误形态
const arrearageErr = {
  message: "Bad Request",
  statusCode: 400,
  responseBody:
    '{"code":"Arrearage","message":"Access denied, please make sure your account is in good standing. For details, see: https://help.aliyun.com/zh/model-studio/error-code#overdue-payment","request_id":"dd4dde8f-7257-9ac0-aa98-e674d124093c"}',
};
const d1 = classifyLLMError(arrearageErr);
check(d1.kind === "arrearage", "kind = arrearage（实际 " + d1.kind + "）");
check(d1.tag.includes("欠费"), "tag 含'欠费'");
check(d1.detail.includes("Arrearage"), "detail 含业务码 Arrearage");
check(d1.detail.includes("in good standing"), "detail 含原始 message");
check(d1.tips.length >= 4, "至少 4 条建议（实际 " + d1.tips.length + "）");
check(d1.tips.some((t) => t.includes("overdue-payment")), "建议含 help 链接（充值指引）");

console.log("\n=== 2) 额度耗尽 Forbidden（statusCode 403 + Free quota exhausted）===");
const quotaErr = {
  message: "Forbidden",
  statusCode: 403,
  responseBody:
    '{"request_id":"x","code":"PERMISSION_DENIED","message":"Free quota exhausted. To continue accessing the model on a paid basis, please add funds or disable the \\"use free tier only\\" mode in the management console."}',
};
const d2 = classifyLLMError(quotaErr);
check(d2.kind === "quota", "kind = quota（实际 " + d2.kind + "）");
check(d2.detail.includes("Free quota exhausted"), "detail 含 Free quota exhausted");
check(d2.tips.some((t) => t.includes("/model")), "建议含 /model 切换");

console.log("\n=== 3) 鉴权失败 401 ====");
const authErr = { message: "Unauthorized", statusCode: 401, responseBody: "" };
const d3 = classifyLLMError(authErr);
check(d3.kind === "auth", "kind = auth（实际 " + d3.kind + "）");
check(d3.tips.some((t) => t.includes("DASHSCOPE_API_KEY")), "建议含环境变量检查");

console.log("\n=== 4) 模型不支持 400 + model not found ====");
const modelErr = {
  message: "Bad Request",
  statusCode: 400,
  responseBody: '{"code":"ModelNotFound","message":"Model deepseek-xxx does not exist"}',
};
const d4 = classifyLLMError(modelErr);
check(d4.kind === "model", "kind = model（实际 " + d4.kind + "）");
check(d4.tips.some((t) => t.includes("{model}")), "建议含 {model} 占位符（CLI 层替换）");

console.log("\n=== 5) 网络 ECONNREFUSED ====");
const netErr = { message: "fetch failed: ECONNREFUSED 127.0.0.1:443", statusCode: 0 };
const d5 = classifyLLMError(netErr);
check(d5.kind === "network", "kind = network（实际 " + d5.kind + "）");
check(d5.tips.some((t) => t.includes("{baseUrl}")), "建议含 {baseUrl} 占位符");

console.log("\n=== 6) 普通错误（非 LLM API 级）归类 unknown ====");
const plainErr = new Error("some internal bug");
const d6 = classifyLLMError(plainErr);
check(d6.kind === "unknown", "kind = unknown（实际 " + d6.kind + "）");
check(d6.detail === "some internal bug", "detail 保留原始 message");

console.log("\n=== 7) 中文欠费关键字 ====");
const cnErr = { message: "请求失败", statusCode: 400, responseBody: '{"message":"账户欠费，请充值后重试"}' };
const d7 = classifyLLMError(cnErr);
check(d7.kind === "arrearage", "中文'欠费'识别为 arrearage（实际 " + d7.kind + "）");

console.log("\n=== 8) responseBody 非法 JSON 降级 ====");
const badJsonErr = { message: "Bad Request", statusCode: 400, responseBody: "<<not json>> 欠费通知" };
const d8 = classifyLLMError(badJsonErr);
check(d8.kind === "arrearage", "非 JSON body 含'欠费'也能识别（实际 " + d8.kind + "）");

console.log("\n=== 结果: " + passed + " passed, " + failed + " failed ===");
process.exit(failed > 0 ? 1 : 0);
