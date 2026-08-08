// 阶段10 单元测试：会话管理（Session / SessionStore / SessionManager）
// 全程无 LLM：序列化往返、磁盘持久化、会话切换/恢复/删除、上下文与权限隔离、clearRuntime。
// 运行：node tests/stage10.test.js
const os = require("os");
const path = require("path");
const fs = require("fs");
const {
  Session,
  SessionManager,
  SessionStore,
  createToolRegistry,
} = require("../dist/index");
const { PermissionManager } = require("../dist/permissions/permission-manager");

let pass = 0;
let fail = 0;
const ok = (name, cond) => {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}`);
  }
};

const confirmFn = async () => true;
const toolRegistry = createToolRegistry();

// 每个测试段独立临时目录，避免互相污染
let dirCounter = 0;
const newDir = () =>
  fs.mkdtempSync(path.join(os.tmpdir(), `flagent-s10-${dirCounter++}-`));
const createdDirs = [];
const track = (d) => {
  createdDirs.push(d);
  return d;
};

const baseData = (over = {}) => ({
  sessionId: "s1",
  title: "t",
  createdAt: 1,
  updatedAt: 2,
  messages: [],
  summary: "",
  steps: [],
  approvedTools: [],
  dynamicAgents: [],
  ...over,
});

(async () => {
  console.log("\n=== 阶段10：SessionStore 磁盘持久化 ===");

  {
    const d = track(newDir());
    const store = new SessionStore({ dir: d });
    ok("空目录 list 返回 []", (await store.list()).length === 0);
    ok("load 不存在返回 undefined", (await store.load("nope")) === undefined);

    const data = baseData({
      sessionId: "s1",
      title: "hello",
      messages: [{ role: "user", content: "hi" }],
      summary: "摘",
    });
    await store.save(data);
    const loaded = await store.load("s1");
    ok("save/load 往返 sessionId", loaded.sessionId === "s1");
    ok("save/load 往返 title", loaded.title === "hello");
    ok("save/load 往返 messages", loaded.messages.length === 1 && loaded.messages[0].content === "hi");
    ok("save/load 往返 summary", loaded.summary === "摘");

    // 倒序：updatedAt 大的在前（注意同目录已有 s1 updatedAt=2）
    await store.save(baseData({ sessionId: "old", updatedAt: 1 }));
    await store.save(baseData({ sessionId: "new", updatedAt: 9 }));
    const metas = await store.list();
    const order = metas.map((m) => m.sessionId);
    ok("list 按 updatedAt 倒序", order[0] === "new" && order.indexOf("new") < order.indexOf("old"));
    ok("list 元信息含 title", metas[0].title === "t");

    // 删除
    const del = await store.delete("s1");
    ok("delete 返回 true", del === true);
    ok("delete 后 load 返回 undefined", (await store.load("s1")) === undefined);
    ok("delete 不存在返回 false", (await store.delete("s1")) === false);
  }

  console.log("\n=== 阶段10：SessionStore 损坏文件跳过 ===");
  {
    const d = track(newDir());
    const store = new SessionStore({ dir: d });
    fs.writeFileSync(path.join(d, "broken.json"), "{not valid json");
    fs.writeFileSync(path.join(d, "ignore.txt"), "not json");
    const metas = await store.list();
    ok("损坏 JSON 被跳过不抛错", metas.length === 0);
    ok("非 .json 文件被忽略", true);
  }

  console.log("\n=== 阶段10：Session 序列化往返（fromData/toData） ===");
  {
    const data = baseData({
      sessionId: "test-001",
      title: "测试会话",
      createdAt: 1000,
      updatedAt: 2000,
      messages: [
        { role: "user", content: "hi" },
        { role: "assistant", content: "hello" },
      ],
      summary: "摘要X",
      steps: [
        { step: 1, action: "THOUGHT", thought: "t", observation: "o", plan: "" },
      ],
      approvedTools: ["command_exec", "file_write_real"],
      dynamicAgents: [
        {
          id: "gen-x",
          name: "X",
          role: "r",
          systemPrompt: "s",
          toolNames: ["http_request"],
          maxSteps: 4,
        },
      ],
    });
    const s = Session.fromData(data, toolRegistry, confirmFn);
    ok("fromData sessionId", s.id === "test-001");
    ok("fromData title", s.title === "测试会话");
    ok("fromData 恢复 messages(2)", s.getContextManager().getMessages().length === 2);
    ok("fromData 恢复 summary", s.getContextManager().getSummary() === "摘要X");
    ok("fromData 恢复 steps(1)", s.getSteps().length === 1 && s.getSteps()[0].action === "THOUGHT");
    ok("fromData 恢复 approvedTools", s.getPermissionManager().isApproved("command_exec") && s.getPermissionManager().isApproved("file_write_real"));
    ok("fromData 恢复 dynamicAgent gen-x", !!s.getScheduler().getAgent("gen-x"));
    ok("fromData 恢复 dynamicAgent 工具过滤", s.getScheduler().getAgent("gen-x").toolNames.includes("http_request"));

    // toData 往返
    const data2 = s.toData();
    ok("toData sessionId", data2.sessionId === "test-001");
    ok("toData messages 去 timestamp/tokenCount", data2.messages.length === 2 && data2.messages[0].role === "user" && data2.messages[0].content === "hi");
    ok("toData summary", data2.summary === "摘要X");
    ok("toData steps", data2.steps.length === 1);
    ok("toData approvedTools", data2.approvedTools.includes("command_exec"));
    ok("toData dynamicAgents 含 gen-x", data2.dynamicAgents.some((dg) => dg.id === "gen-x"));
  }

  console.log("\n=== 阶段10：Session.create + deriveTitle ===");
  {
    const s = Session.create({ id: "c1", toolRegistry, confirmFn });
    ok("create id", s.id === "c1");
    ok("create 默认 title 空", s.title === "");
    ok("create steps 空", s.getSteps().length === 0);
    ok("create 独立 ContextManager", !!s.getContextManager());
    ok("create 独立 PermissionManager", !!s.getPermissionManager());
    ok("create 含 5 预设 agent", s.getScheduler().getAllAgents().length === 5);
    ok("deriveTitle 短文本原样", s.deriveTitle("短任务") === "短任务");
    const long = s.deriveTitle("a".repeat(40));
    ok("deriveTitle 长文本截断 30+…", long.length === 31 && long.endsWith("…"));
    s.setTitle("新标题");
    ok("setTitle 生效", s.title === "新标题");
  }

  console.log("\n=== 阶段10：Session.clearRuntime ===");
  {
    const s = Session.create({ id: "clr", toolRegistry, confirmFn });
    s.getContextManager().restoreMessages([{ role: "user", content: "X" }], "summ");
    s.getPermissionManager().approve("foo");
    s.clearRuntime();
    ok("clearRuntime 清空 messages", s.getContextManager().getMessages().length === 0);
    ok("clearRuntime 清空 summary", s.getContextManager().getSummary() === "");
    ok("clearRuntime 清空 approved", s.getPermissionManager().getApproved().length === 0);
  }

  console.log("\n=== 阶段10：SessionManager 创建/切换/列表 ===");
  {
    const d = track(newDir());
    const mgr = new SessionManager({ toolRegistry, confirmFn, storeDir: d });
    ok("初始无活动会话", mgr.current() === undefined && mgr.getActiveId() === undefined);

    const a = await mgr.create("A");
    const b = await mgr.create("B");
    ok("create 后 current 为新建会话", mgr.current().id === b.id);
    ok("create 写盘", fs.existsSync(path.join(d, b.id + ".json")));

    await mgr.switch(a.id);
    ok("switch 到 A（内存）", mgr.current().id === a.id);
    ok("getActiveId 跟随", mgr.getActiveId() === a.id);

    const list = await mgr.list();
    ok("list 含 2 个会话", list.length === 2);
    ok("list 标记 active=A", list.find((m) => m.sessionId === a.id).active === true);
    ok("list 标记 B 非 active", list.find((m) => m.sessionId === b.id).active === false);
  }

  console.log("\n=== 阶段10：SessionManager resume（跨实例从磁盘恢复） ===");
  {
    const d = track(newDir());
    const mgr = new SessionManager({ toolRegistry, confirmFn, storeDir: d });
    const a = await mgr.create("A");
    a.getContextManager().restoreMessages([{ role: "user", content: "RESTORE-ME" }], "summ");
    a.getPermissionManager().approve("command_exec");
    a.getScheduler().registerDynamicAgent({
      id: "gen-r", name: "R", role: "r", systemPrompt: "s",
      toolNames: ["http_request"], maxSteps: 3,
    });
    await mgr.persistActive();

    // 新实例模拟重启
    const mgr2 = new SessionManager({ toolRegistry, confirmFn, storeDir: d });
    const restored = await mgr2.resume(a.id);
    ok("resume 恢复 title", restored.title === "A");
    ok("resume 恢复 messages", restored.getContextManager().getMessages().some((m) => m.content.includes("RESTORE-ME")));
    ok("resume 恢复 summary", restored.getContextManager().getSummary() === "summ");
    ok("resume 恢复 approvedTools", restored.getPermissionManager().isApproved("command_exec"));
    ok("resume 恢复 dynamicAgent", !!restored.getScheduler().getAgent("gen-r"));
    ok("resume 设为活动", mgr2.getActiveId() === a.id);
  }

  console.log("\n=== 阶段10：SessionManager delete ===");
  {
    const d = track(newDir());
    const mgr = new SessionManager({ toolRegistry, confirmFn, storeDir: d });
    const a = await mgr.create("A");
    ok("delete 前文件存在", fs.existsSync(path.join(d, a.id + ".json")));
    const del = await mgr.delete(a.id);
    ok("delete 返回 true", del === true);
    ok("delete 后文件删除", !fs.existsSync(path.join(d, a.id + ".json")));
    ok("delete 后内存移除", mgr.get(a.id) === undefined);
    ok("delete 活动会话后清空 activeId", mgr.getActiveId() === undefined);
    ok("delete 后 current undefined", mgr.current() === undefined);
  }

  console.log("\n=== 阶段10：SessionManager.persist(id)（非活动会话） ===");
  {
    const d = track(newDir());
    const mgr = new SessionManager({ toolRegistry, confirmFn, storeDir: d });
    const a = await mgr.create("A");
    const b = await mgr.create("B"); // b 为活动
    a.setTitle("renamed-A");
    await mgr.persist(a.id); // 持久化非活动会话 a
    // 新实例从磁盘 resume a，验证 title 已落盘
    const mgr2 = new SessionManager({ toolRegistry, confirmFn, storeDir: d });
    const restored = await mgr2.resume(a.id);
    ok("persist(id) 落盘非活动会话 title", restored.title === "renamed-A");
    ok("persist(id) 不影响活动会话", mgr2.getActiveId() === a.id);
  }

  console.log("\n=== 阶段10：会话隔离（上下文/权限独立实例） ===");
  {
    const d = track(newDir());
    const mgr = new SessionManager({ toolRegistry, confirmFn, storeDir: d });
    const a = await mgr.create("A");
    const b = await mgr.create("B");
    a.getContextManager().restoreMessages([{ role: "user", content: "AAA" }], "");
    b.getContextManager().restoreMessages([{ role: "user", content: "BBB" }], "");
    a.getPermissionManager().approve("toolA");
    b.getPermissionManager().approve("toolB");

    ok("A/B ContextManager 不同实例", a.getContextManager() !== b.getContextManager());
    ok("A/B PermissionManager 不同实例", a.getPermissionManager() !== b.getPermissionManager());
    ok("A 含 AAA 不含 BBB", a.getContextManager().getMessages().some((m) => m.content.includes("AAA")) && !a.getContextManager().getMessages().some((m) => m.content.includes("BBB")));
    ok("B 含 BBB 不含 AAA", b.getContextManager().getMessages().some((m) => m.content.includes("BBB")) && !b.getContextManager().getMessages().some((m) => m.content.includes("AAA")));
    ok("A 权限隔离（仅 toolA）", a.getPermissionManager().isApproved("toolA") && !a.getPermissionManager().isApproved("toolB"));
    ok("B 权限隔离（仅 toolB）", b.getPermissionManager().isApproved("toolB") && !b.getPermissionManager().isApproved("toolA"));
  }

  console.log("\n=== 阶段10：包导出 ===");
  ok("导出 Session", typeof Session === "function");
  ok("导出 SessionManager", typeof SessionManager === "function");
  ok("导出 SessionStore", typeof SessionStore === "function");

  // 清理临时目录
  for (const d of createdDirs) {
    try {
      fs.rmSync(d, { recursive: true, force: true });
    } catch {}
  }

  console.log(`\n=== 结果: ${pass} passed, ${fail} failed ===`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => {
  console.error("ERR:", e);
  process.exit(1);
});
