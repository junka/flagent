// 边界场景与错误处理补充测试（覆盖度分析识别的缺口）
// 无需网络与 LLM。运行：node tests/edge-cases.test.js
const { z } = require("zod");
const { ToolRegistry } = require("../dist/tools");
const { ToolExecutor } = require("../dist/agents/tool-executor");
const { Scheduler } = require("../dist/agents/scheduler");
const { SubAgent } = require("../dist/agents/sub-agent");
const { MainAgent } = require("../dist/agents/main-agent");
const { ContextManager } = require("../dist/context");
const {
  PermissionManager,
} = require("../dist/permissions/permission-manager");
const {
  parseReactResponse,
  parseToolCallLine,
  parseMainReactResponse,
} = require("../dist/agents/react-parser");

let pass = 0;
let fail = 0;
const ok = (name, cond) => {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name}`); }
};

const NO_SUMMARY = { summaryThresholdTokens: 1e9, maxContextTokens: 1e9, windowMessages: 5 };

function makeReg() {
  const reg = new ToolRegistry();
  reg.register({ name: "read_a", description: "只读a", parameters: z.object({ x: z.string().optional() }), category: "info", concurrent: true, execute: async (a) => `a:${a.x || "-"}` });
  reg.register({ name: "write_b", description: "写b", parameters: z.object({ v: z.number() }), category: "file", requirePermission: true, execute: async (a) => `b:${a.v}` });
  reg.register({ name: "plain_c", description: "普通c", parameters: z.object({}), category: "info", execute: async () => "c" });
  return reg;
}

(async () => {
  // ============ ToolRegistry 边界 ============
  console.log("\n=== ToolRegistry 边界 ===");
  const reg = makeReg();

  let threw = false;
  try { reg.register({ name: "read_a", description: "dup", parameters: z.object({}), execute: async () => "" }); } catch (e) { threw = true; }
  ok("重复注册抛错", threw);

  ok("get 未知返回 undefined", reg.get("nope") === undefined);

  threw = false;
  try { await reg.execute("nope", {}); } catch (e) { threw = true; }
  ok("execute 未知工具抛错", threw);

  threw = false;
  try { await reg.execute("write_b", { v: "不是数字" }); } catch (e) { threw = true; }
  ok("execute 参数校验失败抛错", threw);

  reg.unregister("plain_c");
  ok("unregister 后 get 为 undefined", reg.get("plain_c") === undefined);

  const info = reg.getByCategory("info");
  ok("getByCategory 过滤", info.length === 1 && info[0].name === "read_a");

  ok("getNames 含已注册", reg.getNames().includes("read_a") && reg.getNames().includes("write_b"));

  const descs = reg.getToolDescriptions();
  ok("getToolDescriptions 结构", descs.length === 2 && descs[0].name && descs[0].parameters);

  // ---- zodToJsonSchema 推断（覆盖度分析发现的 bug：zod v4 _def.typeName 不可靠）----
  const regSchema = new ToolRegistry();
  regSchema.register({
    name: "t",
    description: "d",
    parameters: z.object({ s: z.string(), n: z.number(), b: z.boolean(), a: z.array(z.string()), opt: z.string().optional() }),
    execute: async () => "",
  });
  const schema = regSchema.getToolDescriptions()[0].parameters;
  ok("zodToJsonSchema object 类型", schema.type === "object");
  ok("zodToJsonSchema string 推断", schema.properties.s.type === "string");
  ok("zodToJsonSchema number 推断", schema.properties.n.type === "number");
  ok("zodToJsonSchema boolean 推断", schema.properties.b.type === "boolean");
  ok("zodToJsonSchema array 推断", schema.properties.a.type === "array");
  ok("zodToJsonSchema array items 推断", schema.properties.a.items.type === "string");
  ok("zodToJsonSchema optional 解包为 string", schema.properties.opt.type === "string");
  ok("zodToJsonSchema properties 数量正确", Object.keys(schema.properties).length === 5);

  // ============ ToolExecutor 错误处理 ============
  console.log("\n=== ToolExecutor 错误处理 ===");
  const reg3 = new ToolRegistry();
  reg3.register({ name: "boom", description: "会抛错", parameters: z.object({}), category: "t", concurrent: true, execute: async () => { throw new Error("炸了"); } });
  reg3.register({ name: "ok_tool", description: "ok", parameters: z.object({}), category: "t", concurrent: true, execute: async () => "ok" });
  reg3.register({ name: "perm_tool", description: "需权限", parameters: z.object({}), category: "t", requirePermission: true, execute: async () => "perm-ok" });
  reg3.register({ name: "validated", description: "v", parameters: z.object({ required: z.string() }), category: "t", concurrent: true, execute: async (a) => a.required });

  const ex = new ToolExecutor(reg3, undefined, 8);
  const er = await ex.executeBatch([{ toolName: "boom", toolArgs: {} }]);
  ok("工具抛错被捕获 success:false", er[0].success === false && /炸了/.test(er[0].result));

  const er2 = await ex.executeBatch([{ toolName: "validated", toolArgs: {} }]);
  ok("zod 校验失败被捕获 success:false", er2[0].success === false);

  // 混合顺序保持：not_found + denied + success
  const pm = new PermissionManager(async () => false);
  const ex2 = new ToolExecutor(reg3, pm, 8);
  const er3 = await ex2.executeBatch([
    { toolName: "nope", toolArgs: {} },
    { toolName: "perm_tool", toolArgs: {} },
    { toolName: "ok_tool", toolArgs: {} },
  ]);
  ok("混合顺序[0] not_found", er3[0].toolName === "nope" && er3[0].success === false);
  ok("混合顺序[1] denied skipped", er3[1].toolName === "perm_tool" && er3[1].skipped === true);
  ok("混合顺序[2] success", er3[2].toolName === "ok_tool" && er3[2].success === true);

  // requirePermission + concurrent 同时为 true：权限串行确认后仍执行（记录行为）
  reg3.register({ name: "both", description: "权限+并发", parameters: z.object({}), category: "t", requirePermission: true, concurrent: true, execute: async () => "both-ok" });
  const pmAllow = new PermissionManager(async () => true);
  const ex3 = new ToolExecutor(reg3, pmAllow, 8);
  const er4 = await ex3.executeBatch([{ toolName: "both", toolArgs: {} }]);
  ok("requirePermission+concurrent 批准后执行", er4[0].success === true && er4[0].result === "both-ok");

  // ============ PermissionManager 拒绝并发 ============
  console.log("\n=== PermissionManager 拒绝并发 ===");
  let denyCount = 0;
  const pmD = new PermissionManager(async () => { denyCount++; await new Promise((r) => setTimeout(r, 5)); return false; });
  const dres = await Promise.all([pmD.check("x", {}), pmD.check("x", {})]);
  ok("拒绝并发全部返回 false", dres.every((x) => x === false));
  ok("拒绝并发各弹一次（拒绝不记忆）", denyCount === 2);
  ok("拒绝后不 approved", !pmD.isApproved("x"));

  // getApproved 返回副本
  const pmC = new PermissionManager(async () => true);
  await pmC.check("a", {});
  const arr = pmC.getApproved();
  arr.push("injected");
  ok("getApproved 返回副本（外部修改不影响内部）", pmC.getApproved().length === 1);

  // ============ Scheduler 边界 ============
  console.log("\n=== Scheduler 边界 ===");
  const sreg = makeReg();
  const sexec = new ToolExecutor(sreg, undefined, 4);
  const sch = new Scheduler(sreg, sexec);

  // dispatchConcurrent 空数组
  const empty = await sch.dispatchConcurrent([]);
  ok("dispatchConcurrent 空数组返回空", Array.isArray(empty) && empty.length === 0);

  // dispatchConcurrent 多个未找到都失败（不触发 LLM）
  const mix = await sch.dispatchConcurrent([
    { agentId: "not_exist_1", task: "x" },
    { agentId: "not_exist_2", task: "y" },
  ]);
  ok("dispatchConcurrent 多个未找到都失败", mix.length === 2 && mix.every((m) => !m.success));

  // route() 单 agent 直接路由（无 LLM fast-path）
  const singleSch = new Scheduler(sreg, sexec);
  const singleAgent = new SubAgent({
    id: "only", name: "唯一", role: "r", systemPrompt: "s",
    toolNames: ["read_a"], contextManager: new ContextManager(NO_SUMMARY), toolExecutor: sexec, maxSteps: 3,
  }, sreg);
  singleSch.registerAgent(singleAgent);
  const routed = await singleSch.route("任意任务");
  ok("单 agent 直接路由无 LLM", routed.agent.id === "only" && routed.decision.agentId === "only");
  ok("单 agent 路由原因含直接路由", /直接路由/.test(routed.decision.reason));

  // registerDynamicAgent 重复 toolNames（当前不去重，记录行为）
  sch.registerDynamicAgent({ id: "gen-dup", name: "d", role: "r", systemPrompt: "s", toolNames: ["read_a", "read_a", "write_b"] });
  const dup = sch.getAgent("gen-dup");
  ok("重复 toolNames 保留（不去重）", dup.toolNames.length === 3);
  sch.unregisterDynamicAgent("gen-dup");

  // ============ Parser 边界 ============
  console.log("\n=== Parser 边界 ===");
  let r = parseMainReactResponse("thought: 小写\nactions:\n  - read_a({\"x\":\"1\"})");
  ok("小写键 parseMainReactResponse", r.thought === "小写" && r.actions.length === 1);

  r = parseReactResponse("Thought: 混合大小写\nAction: read_a({})");
  ok("混合大小写 parseReactResponse", r.thought === "混合大小写" && r.action === "read_a({})");

  r = parseMainReactResponse("THOUGHT: 思考\n\n\nACTIONS:\n  - read_a({})");
  ok("段间空行不影响解析", r.thought === "思考" && r.actions.length === 1);

  let tc = parseToolCallLine('read_a({"x":"1","obj":{"k":42}})');
  ok("嵌套 JSON 参数", tc.toolArgs.obj.k === 42);

  r = parseReactResponse("THOUGHT: 委派\nDELEGATE: web\nFINAL_ANSWER: 同时");
  ok("DELEGATE+FINAL_ANSWER 共存", r.delegateAgent === "web" && r.finalAnswer === "同时");

  r = parseMainReactResponse("THOUGHT: 只有思考");
  ok("仅 THOUGHT 其余全空", r.thought === "只有思考" && r.actions.length === 0 && r.delegates.length === 0 && r.plan === "" && r.finalAnswer === "" && r.spawnAgents.length === 0);

  tc = parseToolCallLine('  read_a({"x":"1"})  ');
  ok("前后空格的工具调用", tc.toolName === "read_a");

  tc = parseToolCallLine('tool_x({  "a" : 1 , "b" : "2" })');
  ok("JSON 内多余空格", tc.toolArgs.a === 1 && tc.toolArgs.b === "2");

  // ============ SubAgent 工具越权 ============
  console.log("\n=== SubAgent 工具越权 ===");
  const saReg = makeReg();
  const saExec = new ToolExecutor(saReg, undefined, 4);
  const agent = new SubAgent({
    id: "test-sa", name: "测试", role: "测试员", systemPrompt: "s",
    toolNames: ["read_a"], contextManager: new ContextManager(NO_SUMMARY), toolExecutor: saExec, maxSteps: 3,
  }, saReg);

  // executeScoped 是 private，编译后运行时可访问
  const deniedScoped = await agent.executeScoped("write_b", { v: 1 });
  ok("越权工具被拒绝", /工具越权/.test(deniedScoped));

  const allowedScoped = await agent.executeScoped("read_a", { x: "hi" });
  ok("允许的工具经 toolExecutor 执行", allowedScoped === "a:hi");

  // 无 toolExecutor 时走 registry.execute
  const agent2 = new SubAgent({
    id: "test-sa2", name: "测试2", role: "r", systemPrompt: "s",
    toolNames: ["read_a"], contextManager: new ContextManager(NO_SUMMARY),
  }, saReg);
  const noExec = await agent2.executeScoped("read_a", { x: "noexec" });
  ok("无 toolExecutor 走 registry.execute", noExec === "a:noexec");

  const noExecDenied = await agent2.executeScoped("write_b", {});
  ok("无 toolExecutor 越权仍拒绝", /工具越权/.test(noExecDenied));

  // registry.execute 抛错时返回失败串
  const agent3 = new SubAgent({
    id: "test-sa3", name: "测试3", role: "r", systemPrompt: "s",
    toolNames: ["read_a"], contextManager: new ContextManager(NO_SUMMARY),
  }, saReg);
  const errExec = await agent3.executeScoped("read_a", { x: 123 }); // x 应为 string，zod 校验失败
  ok("registry.execute 失败返回错误串", /工具执行失败/.test(errExec));

  // ============ MainAgent.buildDelegateTask ============
  console.log("\n=== MainAgent.buildDelegateTask ===");
  const maReg = makeReg();
  const maSch = new Scheduler(maReg, new ToolExecutor(maReg, undefined, 4));
  const ma = new MainAgent(new ContextManager(NO_SUMMARY), maReg, maSch, undefined, 5);
  // buildDelegateTask 是 private，运行时可访问
  const dt = ma.buildDelegateTask("主控思考", "原始任务");
  ok("buildDelegateTask 格式", dt === "主控思考\n\n[原始任务上下文] 原始任务");

  // ============ ContextManager 边界 ============
  console.log("\n=== ContextManager 边界 ===");
  const def = new ContextManager();
  await def.addMessage({ role: "user", content: "hi" });
  ok("默认配置可工作", def.getMessages().length === 1);
  ok("默认 windowMessages=10", def.getActiveMessages().length === 1);

  const ec = new ContextManager(NO_SUMMARY);
  await ec.addMessage({ role: "user", content: "" });
  ok("空内容仍加入", ec.getMessages().length === 1 && ec.getMessages()[0].content === "");

  // window 边界：消息数===window 返回全部
  const wb = new ContextManager({ ...NO_SUMMARY, windowMessages: 3 });
  for (let i = 0; i < 3; i++) await wb.addMessage({ role: "user", content: `m${i}` });
  ok("消息数===window 返回全部", wb.getActiveMessages().length === 3);

  ok("getSummary 默认空串", new ContextManager().getSummary() === "");

  // 消息含 timestamp/tokenCount 字段
  const msg = ec.getMessages()[0];
  ok("消息含 timestamp", typeof msg.timestamp === "number");
  ok("消息含 tokenCount", typeof msg.tokenCount === "number");

  console.log(`\n=== 结果: ${pass} passed, ${fail} failed ===`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error("ERR:", e); process.exit(1); });
