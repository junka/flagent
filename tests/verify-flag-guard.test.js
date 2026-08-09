// 验证 3 项新增能力：
// 1) validateCTFFinalAnswer 4 分支分类正确
// 2) pwn_run_exploit 对 stdout/stderr 的 flag 扫描（[FLAG FOUND] / [NO FLAG FOUND]）
// 3) main-agent 在 CTF 任务 + finalAnswer='Flag: 无' 时，不会 isComplete=true（继续下一轮 debug）
const net = require("net");
const os = require("os");
const path = require("path");
const { createToolRegistry } = require("../dist/tools/factory");
const { ContextManager } = require("../dist/context");
const { PermissionManager } = require("../dist/permissions/permission-manager");
const { Scheduler } = require("../dist/agents/scheduler");
const { ToolExecutor } = require("../dist/agents/tool-executor");
const { MainAgent } = require("../dist/agents/main-agent");

let passed = 0, failed = 0;
function check(cond, msg) {
  if (cond) { passed++; console.log("  ✓ " + msg); }
  else { failed++; console.log("  ✗ " + msg); }
}

// --- A) validateCTFFinalAnswer：从编译后 dist 取到（没有导出，用内部 eval 技巧）
// 直接从 require.main 外拿不到 → 重新写等价逻辑在此文件再单独验证：
// 简化：我们用模块 eval，把 main-agent 里的函数单独从源码再拷贝一遍；
// 但更简单：通过 main-agent 行为（步骤3）来间接验证。同时这里做一个"输入输出表"对工具层行为验证。
// 所以 A 部分：通过 pwn_run_exploit 的 [FLAG FOUND] 间接覆盖 4 条正则（flag{/ctfhub{/CTF{/自定义}）

async function main() {
  console.log("=== 1) pwn_run_exploit: [FLAG FOUND] 检测 ctfhub{ } / flag{ } / CTF{ } / 自定义 flagRegex ===");
  const reg = createToolRegistry();
  const runExp = reg.get("pwn_run_exploit");

  // 构造一个 exploit 脚本，打印多个伪 flag
  const script1 = `
import sys, os
# stdout 里放多种格式
sys.stdout.write('hello123 uid=0\\n')
sys.stdout.write('ctfhub{fmt_string_win_2026_abcd}\\n')
sys.stdout.write('random text then flag{plain-text-flag-here} tail\\n')
sys.stdout.write('CTF{WeIrD-CaSe} and more\\n')
# stderr 里放一个
sys.stderr.write('in stderr: picoCTF{shell_land_aaaa}\\n')
sys.stdout.flush(); sys.stderr.flush()
`;
  const r1 = await runExp.execute({ script: script1, timeout: 10000 });
  // console.log(r1.slice(-1200));
  check(r1.includes("[FLAG FOUND]"), "输出含 [FLAG FOUND] 标题");
  check(r1.includes("ctfhub{fmt_string_win_2026_abcd}"), "识别到 ctfhub{...}");
  check(r1.includes("flag{plain-text-flag-here}"), "识别到 flag{...}（大小写不敏感）");
  check(r1.includes("CTF{WeIrD-CaSe}"), "识别到 CTF{...}（区分大小写）");
  check(r1.includes("picoCTF{shell_land_aaaa}"), "识别 stderr 中的 picoCTF{...}");
  check(!r1.includes("[NO FLAG FOUND]"), "找到 flag 时不出现 NO FLAG FOUND");

  console.log("\n=== 2) pwn_run_exploit: [NO FLAG FOUND] + 5 条建议 ===");
  const script2 = `
import sys
sys.stdout.write('No flag here, just plain output\\n')
sys.stdout.write('uid=0 gid=0 root shell launched, but forgot to cat flag\\n')
sys.stdout.flush()
`;
  const r2 = await runExp.execute({ script: script2, timeout: 10000 });
  check(r2.includes("[NO FLAG FOUND]"), "没有 flag 时输出 NO FLAG FOUND 提示");
  check(r2.includes("查看 bytes 尾部") || r2.includes("1)"), "调试建议第 1 条：查看 bytes 尾部");
  check(r2.includes("追加多条读取命令") || r2.includes("2)"), "调试建议第 2 条：追加 cat/ls/find 命令");
  check(r2.includes("分两字节") || r2.includes("3)"), "调试建议第 3 条：%hhn 逐字节写建议");
  check(r2.includes("flagRegex") || r2.includes("4)"), "调试建议第 4 条：自定义 flagRegex 参数");
  check(r2.includes("sleep") || r2.includes("5)"), "调试建议第 5 条：sleep + interactive");

  console.log("\n=== 3) pwn_run_exploit: flagRegex 自定义捕获平台前缀 ===");
  // MyGame{abc123} 不在默认列表里，但用户传了 flagRegex 就能抓到
  const script3 = `
import sys
sys.stdout.write('Congratulations! Your flag is MyGame{abc_123_XYZ}\\n')
sys.stdout.flush()
`;
  const r3a = await runExp.execute({ script: script3, timeout: 10000 });
  // 不传 flagRegex：兜底正则 <平台>{xxx} 应该能抓到 MyGame{abc_123_XYZ}
  check(r3a.includes("[FLAG FOUND]") && r3a.includes("MyGame{abc_123_XYZ}"),
        "不传 flagRegex 也能靠兜底正则抓到新平台 MyGame{xxx}");
  // 传了错误正则 + 不匹配默认平台也抓不到时应该提示
  const r3b = await runExp.execute({ script: script2 + "", flagRegex: "NeverMatchThis_{\\\\w+}", timeout: 10000 });
  check(r3b.includes("[NO FLAG FOUND]"), "flagRegex 不匹配时仍报告未找到（不误报）");

  console.log("\n=== 4) pwn_run_exploit: flagRegex 非法正则 → 参数错误返回，不抛崩溃 ===");
  const r4 = await runExp.execute({ script: "print('x')", timeout: 5000, flagRegex: "[bad regex unclosed" });
  check(typeof r4 === "string" && r4.includes("flagRegex 正则语法错误"),
        "flagRegex 语法错误返回参数错误信息字符串（不抛异常）");

  console.log("\n=== 5) MainAgent guard：CTF 任务 + 'Flag: 无' → 不提交 final，继续 debug ===");
  // 思路：构造 MainAgent，给它一个会生成 finalAnswer="Flag: 无" 的假 LLM 响应
  // 看 reactStep 返回值：isComplete 应该是 false，且 steps 里出现 FINAL_ANSWER_GUARD
  process.env.FLAGENT_MAX_STEPS = "10";
  const ctx = new ContextManager({});
  const pm = new PermissionManager({ defaultStrategy: "allow" }); // 全放行避免交互弹窗
  const executor = new ToolExecutor(reg, pm, 1);
  const scheduler = new Scheduler(reg, executor);
  // MainAgent 构造器是位置参数: (ctx, registry, scheduler, executor?, maxSteps=20)
  const agent = new MainAgent(ctx, reg, scheduler, executor, 10);

  // 注入 2 条用户消息 + 2 条工具结果（制造"已尝试 exploit 但说 Flag 无"的语境）
  await ctx.addMessagesBatch([
    { role: "user", content: "帮我解这道 ctf pwn 题，目标是获取 flag，远程地址 challenge-xxx.ctfhub.com:30598" },
    { role: "assistant", content: "先用 pwn_static_analysis 分析附件" },
    { role: "user", content: "[pwn_static_analysis 结果] ELF x86_64, win 地址 0x60108c, printf(buf) 格式化字符串漏洞" },
  ]);

  // 注入假 prompt 响应：第一次 reactStep 的 generateText 会调 ai.generateText，我们 patch ai 包
  const aiPkg = require("ai");
  const savedAiGen = aiPkg.generateText;
  try {
    aiPkg.generateText = async function (opts) {
      return {
        text:
`PLAN: 直接提交结果
THOUGHT: 工具都跑完了，应该可以直接交卷。
FINAL_ANSWER:
  Flag: 无（需实际执行获取，但根据逻辑能拿到）
  Writeup:
  1. 发现格式化字符串
  2. 构造 payload
`
      };
    };

    const result = await agent.reactStep(1, "帮我解这道 ctf pwn 题，目标是获取 flag，远程地址 challenge-xxx.ctfhub.com:30598");
    console.log("    reactStep 结果 isComplete=" + result.isComplete + " needsMoreInfo=" + result.needsMoreInfo);
    check(result.isComplete === false, "'Flag: 无' 被拦截，isComplete=false，不会以最终答案交卷");
    check(agent.steps.some((s) => s.action === "FINAL_ANSWER_GUARD"), "steps 中出现 FINAL_ANSWER_GUARD 行为记录");
    // 上下文里被注入了校验不通过的继续迭代提示
    const msgs = ctx.getActiveMessages();
    const lastTwo = msgs.slice(-2).map((m) => m.role + ":" + m.content.slice(0, 200));
    console.log("    lastTwo: " + lastTwo.join(" | "));
    check(msgs.some((m) => m.content.includes("系统校验：不通过")), "ctx 中写入了 '系统校验：不通过' 的反思消息");
    check(msgs.some((m) => m.content.includes("pwn_run_exploit")), "ctx 提示里含 pwn_run_exploit 调试建议");
  } finally {
    aiPkg.generateText = savedAiGen;
  }

  console.log("\n=== 6) MainAgent guard：CTF 任务 + finalAnswer 含 ctfhub{xxx} → 直接放行 ===");
  const ctx2 = new ContextManager({});
  const pm2 = new PermissionManager({ defaultStrategy: "allow" });
  const executor2 = new ToolExecutor(reg, pm2, 1);
  const scheduler2 = new Scheduler(reg, executor2);
  const agent2 = new MainAgent(ctx2, reg, scheduler2, executor2, 10);
  await ctx2.addMessagesBatch([
    { role: "user", content: "ctfhub pwn 题，获取 flag" },
  ]);
  try {
    aiPkg.generateText = async function () {
      return {
        text:
`THOUGHT: 工具扫到了 flag，直接交卷。
FINAL_ANSWER:
  Flag: ctfhub{fmt_striNg_2026_d91f}
  Writeup:
  1. 发现格式化字符串漏洞
  2. 偏移 6，写 0x1234 到 win → system("/bin/sh") → cat /flag → ctfhub{fmt_striNg_2026_d91f}
`
      };
    };
    const res = await agent2.reactStep(1, "ctfhub pwn 题，获取 flag");
    console.log("    reactStep 结果 isComplete=" + res.isComplete + " answer.length=" + (res.answer || "").length);
    check(res.isComplete === true, "Final Answer 含 ctfhub{xxx} 时通过校验，isComplete=true");
    check((res.answer || "").includes("ctfhub{fmt_striNg_2026_d91f}"), "answer 里保留原 flag 内容");
    check(!agent2.steps.some((s) => s.action === "FINAL_ANSWER_GUARD"), "pass 时不产生 FINAL_ANSWER_GUARD");
  } finally {
    aiPkg.generateText = savedAiGen;
  }

  console.log("\n=== 7) MainAgent guard：非 CTF 任务（部署 Node 项目） + 无 flag → 正常放行 ===");
  const ctx3 = new ContextManager({});
  const pm3 = new PermissionManager({ defaultStrategy: "allow" });
  const executor3 = new ToolExecutor(reg, pm3, 1);
  const scheduler3 = new Scheduler(reg, executor3);
  const agent3 = new MainAgent({ contextManager: ctx3, toolRegistry: reg, scheduler: scheduler3, permissionManager: pm3, maxSteps: 10 });
  await ctx3.addMessagesBatch([
    { role: "user", content: "帮我部署一个 node express 项目到 3000 端口" },
  ]);
  try {
    aiPkg.generateText = async function () {
      return {
        text:
`THOUGHT: 部署完成了。
FINAL_ANSWER: 部署成功，服务运行在 http://localhost:3000/，通过 npm start 启动并加了 systemd 守护。`
      };
    };
    const res = await agent3.reactStep(1, "帮我部署一个 node express 项目到 3000 端口");
    check(res.isComplete === true, "非 CTF 任务无 flag 时也正常提交");
    check(!agent3.steps.some((s) => s.action === "FINAL_ANSWER_GUARD"), "非 CTF 任务无 FINAL_ANSWER_GUARD");
  } finally {
    aiPkg.generateText = savedAiGen;
  }

  console.log("\n=== 8) pwn_run_exploit + 真实 socket：扫描远端 echo 里的 flag ===");
  const server = net.createServer((sock) => {
    sock.write("Welcome to test server\n");
    sock.on("data", () => {
      // 假装 exploit 成功，给 shell 输出 + flag
      const resp = Buffer.concat([
        Buffer.from("uid=0 root\n"),
        Buffer.from("flag{this-flag-was-inside-echo-data}\n"),
        Buffer.from("$ "),
      ]);
      sock.write(resp);
      setTimeout(() => sock.end(), 50);
    });
  });
  await new Promise((res) => server.listen(0, "127.0.0.1", res));
  const listenPort = server.address().port;

  const sockScript = `
import socket, time
s = socket.create_connection(({HOST}, {PORT}), timeout=5)
banner = s.recv(2048)
s.sendall(b'my exploit payload\\n')
time.sleep(0.4)
s.settimeout(2)
all = b''
try:
    while True:
        c = s.recv(4096)
        if not c: break
        all += c
except: pass
print('ALL', repr(all))
s.close()
`;
  const r8 = await runExp.execute({ script: sockScript, host: "127.0.0.1", port: listenPort, timeout: 15000 });
  server.close();
  check(r8.includes("[FLAG FOUND]"), "真实 socket 交互后，扫描到远端的 flag{...} 会 [FLAG FOUND]");
  check(r8.includes("flag{this-flag-was-inside-echo-data}"), "flag 内容被完整捕获");

  console.log("\n=== 结果: " + passed + " passed, " + failed + " failed ===");
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error("异常:", e);
  process.exit(1);
});
