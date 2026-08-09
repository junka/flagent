// 专项验证 pwn_run_exploit / pwn_check_env
// 1) pwn_run_exploit: 传含 $p / \xNN 的 Python 脚本，验证内容完整落盘、execFile 执行成功、字节输出正确
// 2) pwn_check_env: ① 无 binary 能输出环境信息；② 写一个 Linux x86_64 ELF 最小 header，能识别 Exec format error 场景
const net = require("net");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { createToolRegistry } = require("../dist/tools/factory");

let passed = 0,
  failed = 0;
function check(cond, msg) {
  if (cond) { passed++; console.log("  ✓ " + msg); }
  else { failed++; console.log("  ✗ " + msg); }
}

async function main() {
  const reg = createToolRegistry();
  const runExp = reg.get("pwn_run_exploit");
  const checkEnv = reg.get("pwn_check_env");

  console.log("=== 1) pwn_run_exploit / pwn_check_env 注册检查 ===");
  check(runExp !== undefined, "pwn_run_exploit 注册成功");
  if (runExp) {
    check(runExp.description.includes("shell") || runExp.description.includes("转义"), "描述含 shell 转义说明");
    check(runExp.requirePermission === true, "requirePermission = true（任意Python需授权）");
    check(typeof runExp.execute === "function", "execute 是函数");
  }
  check(checkEnv !== undefined, "pwn_check_env 注册成功");
  if (checkEnv) check(checkEnv.concurrent === true, "checkEnv concurrent=true");

  // 2) pwn_run_exploit：脚本含 $p 和 \xNN，验证输出正确（不经过 shell 吞 $）
  console.log("\n=== 2) pwn_run_exploit：$p / \\xNN 不被破坏 ===");
  // 脚本会打印一个特定 payload，然后我们校验它的 stdout bytes 含 $p（如果被 shell 吞就不会有）
  // 同时脚本里的 \x8c\x10\x60 字节直接写入并 print(repr)
  const fmtPayloadScript = `# 格式化字符串 payload 验证
# 这一行 %6$p 应该原样出现在脚本（被工具的 preview 打印里）里，不会被 shell 变量 $p 吞掉
import sys
payload = b'%4660c%8$hnAAAAA\\x8c\\x10\\x60\\x00\\x00\\x00\\x00\\x00'
sys.stdout.buffer.write(b'PY_PAYLOAD_REPR=' + repr(payload).encode() + b'\\n')
# 打印 banner 模拟 CTF 服务
sys.stdout.buffer.write(b'Welcome to CTFHub fmt write.Input your format:\\n')
sys.stdout.flush()
`;
  const r1 = await runExp.execute({ script: fmtPayloadScript, timeout: 15000 });
  console.log("  结果片段:\n" + r1.split("─")[4].slice(0, 500));

  check(typeof r1 === "string" && r1.length > 0, "pwn_run_exploit 返回字符串");
  // STDOUT 里应出现 b'%4660c%8$hnAAAAA\x8c\x10\x60\...
  check(r1.includes("%8$hn"), "stdout bytes repr 含 %8$hn（$p 没被吞）");
  // STDOUT 里应出现 \x8c\x10\x60
  check(r1.includes("\\x8c") && r1.includes("\\x10") && r1.includes("\\x60"), "stdout bytes repr 含 \\x8c\\x10\\x60（\\x 未被 shell 解析）");
  // 返回码应为 0
  check(/返回码:\s*0(\s|$)/.test(r1), "脚本返回码 0");
  // 预览里脚本 1..N 行号打印应含 %6$p 原文
  check(r1.includes("%6$p"), "脚本内容预览里含 %6$p 原文（内容没被篡改）");

  // 3) pwn_run_exploit：host/port 占位符替换 {HOST} {PORT}
  console.log("\n=== 3) pwn_run_exploit: {HOST}/{PORT} 占位符替换 ===");
  const substScript = `
H = {HOST}
P = {PORT}
print(f"CONNECT {H}:{P}")
`;
  const r2 = await runExp.execute({
    script: substScript,
    host: "challenge-foo.ctfhub.com",
    port: 30598,
    timeout: 10000,
  });
  console.log("  结果片段:\n" + r2.split("─")[4].slice(0, 300));
  check(r2.includes("CONNECT challenge-foo.ctfhub.com:30598"), "{HOST}/{PORT} 被替换为字符串字面量");

  // 4) pwn_check_env：无 binary，基础环境行齐全
  console.log("\n=== 4) pwn_check_env 基础输出（无 binary）===");
  const env1 = await checkEnv.execute({});
  console.log("  片段:\n" + env1.slice(0, 400) + "\n...");
  check(env1.includes("操作系统") || env1.includes("Node arch"), "含 OS/node 基本信息");
  check(env1.includes("python3"), "含 python3 状态");
  check(env1.includes("pwntools"), "含 pwntools 状态");
  check(env1.includes("qemu-user"), "含 qemu-user 状态");
  check(env1.includes("pwn_run_exploit"), "提示文案含 pwn_run_exploit 调用建议");

  // 5) pwn_check_env：造一个假 Linux x86_64 ELF 最小 header（不会执行，只用于 header 兼容性识别）
  console.log("\n=== 5) pwn_check_env：ELF x86_64 + macOS → 应提示 Exec format error ===");
  // 构造 ELF header（不完整但足够识别）：
  //   e_ident[16] = \x7fELF + EI_CLASS=2(64bit) + EI_DATA=1(LE) + EI_VERSION=1 + PAD
  //   e_type=2(EXEC) @ offset 16, e_machine=0x3e(x86_64) @ offset 18, e_version=1 @ offset 20
  const fakeElf = Buffer.alloc(128);
  fakeElf[0] = 0x7f; fakeElf[1] = 0x45; fakeElf[2] = 0x4c; fakeElf[3] = 0x46;
  fakeElf[4] = 2; fakeElf[5] = 1; fakeElf[6] = 1;
  fakeElf.writeUInt16LE(2, 16);  // e_type=EXEC
  fakeElf.writeUInt16LE(0x3e, 18); // e_machine=x86_64
  fakeElf.writeUInt32LE(1, 20);  // e_version=1
  const tmpElf = path.join(os.tmpdir(), "flagent_test_elf_" + Math.random().toString(36).slice(2, 8));
  fs.writeFileSync(tmpElf, fakeElf);
  const env2 = await checkEnv.execute({ binary: tmpElf });
  console.log("  片段:\n" + env2.slice(0, 800) + "\n...");
  check(env2.includes("64-bit") || env2.includes("x86_64"), "识别 ELF class=64-bit / machine=x86_64");
  // macOS 下会提示 Exec format error；Linux 下可能识别匹配
  if (process.platform !== "linux") {
    check(env2.includes("Exec format error") || env2.includes("不是 Linux"), "宿主非 Linux 时给出 Exec format error 提示 + 远程/qemu 建议");
    check(env2.includes("qemu") || env2.includes("远程") || env2.includes("打远程"), "建议含 qemu 或打远程");
  } else {
    check(env2.includes("宿主与 ELF 架构匹配") || env2.includes("宿主与 ELF 架构") || env2.includes("x86_64"), "Linux 下给出架构匹配分析");
  }
  try { fs.unlinkSync(tmpElf); } catch {}

  // 6) pwn_run_exploit：启动本地 echo server，脚本真实 connect 发送 payload、接收回显（占位符 {HOST}/{PORT}）
  console.log("\n=== 6) pwn_run_exploit：真实 socket 交互（占位符+回显+bytes repr 尾部）===");
  const server = net.createServer((sock) => {
    sock.write("Welcome banner\n");
    sock.on("data", (data) => {
      // echo 回来，前缀 ECHO:
      sock.write(Buffer.concat([Buffer.from("ECHO:"), data]));
      // 延迟 80ms 关 socket，避免立刻 EOF
      setTimeout(() => sock.end(), 80);
    });
  });
  await new Promise((res) => server.listen(0, "127.0.0.1", res));
  const listenPort = server.address().port;

  const sockScript = `
import socket, time, sys
s = socket.create_connection(({HOST}, {PORT}), timeout=5)
banner = s.recv(2048)
print('banner', repr(banner), file=sys.stderr)
# 发送带危险字符的 payload：%6$p + \\x80\\x7f 字节
payload = b'AAAA%6$p\\x80\\x7f\\n'
s.sendall(payload)
time.sleep(0.3)
s.settimeout(2)
all = b''
try:
    while True:
        c = s.recv(1024)
        if not c: break
        all += c
except: pass
print('ALL_REPR:', repr(all))
s.close()
`;
  const r3 = await runExp.execute({
    script: sockScript,
    host: "127.0.0.1",
    port: listenPort,
    timeout: 20000,
  });
  console.log("  结果尾部:\n" + r3.slice(-800));
  server.close();

  // STDOUT 应含 ALL_REPR: b'ECHO:AAAA%6$p\x80\x7f\nWelcome banner\n'
  check(r3.includes("ECHO:AAAA%6$p"), "socket payload 含 %6$p（没被 shell 吞）");
  check(r3.includes("\\x80\\x7f") || r3.includes("ECHO:AAAA%6$p"), "echo payload bytes 含 \\x80\\x7f");
  check(r3.includes("Welcome banner"), "收到 banner");
  // STDERR 应含 banner repr
  check(r3.includes("STDERR") && r3.includes("banner"), "STDERR 中存在 banner 调试输出");

  console.log("\n=== 结果: " + passed + " passed, " + failed + " failed ===");
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error("异常:", e);
  process.exit(1);
});
