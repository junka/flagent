// 验证 nc_remote_client 超时保护：timeout=5（误传秒数）不会导致 505ms 超时
// 启动本地 TCP echo server，用工具连接，验证能正常收发
const net = require("net");
const { createToolRegistry } = require("../dist/tools/factory");

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

async function main() {
  console.log("=== nc_remote_client 超时保护测试 ===");

  // 1) 启动本地 TCP echo server（收到数据后原样返回 + banner）
  const server = net.createServer((sock) => {
    // 先发 banner
    sock.write("Welcome to test echo server\n");
    // echo 收到的数据
    sock.on("data", (data) => {
      sock.write("ECHO: " + data);
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  console.log("  本地 echo server 已启动，端口 " + port);

  const reg = createToolRegistry();
  const ncr = reg.get("nc_remote_client");

  // 2) 测试 timeout=5（模拟 LLM 误传秒数）：不应 505ms 超时，应能连上并收到 banner
  console.log("\n--- 测试 timeout=5（误传秒数，应被提升到 1000ms）---");
  const t0 = Date.now();
  let result1;
  let threw1 = false;
  try {
    result1 = await ncr.execute({
      host: "127.0.0.1",
      port: port,
      timeout: 5, // 误传！以前会导致 505ms 超时
      retries: 1,
      bannerFirst: true,
    });
  } catch (e) {
    threw1 = true;
    result1 = e.message;
  }
  const elapsed1 = Date.now() - t0;
  console.log("  耗时: " + elapsed1 + "ms");
  console.log("  结果: " + result1.slice(0, 200));

  check(!threw1, "timeout=5 不抛异常");
  check(result1.includes("已连接"), "timeout=5 仍能成功连接（不被 505ms 误杀）");
  check(result1.includes("Welcome to test echo server"), "能收到 server banner");
  check(!result1.includes("505ms"), "不再出现 505ms 超时");
  check(elapsed1 < 5000, "总耗时 < 5s（连接握手应快速成功，不再卡超时）");

  // 3) 测试正常 timeout=3000 + sendData
  console.log("\n--- 测试 timeout=3000 + sendData='hello' ---");
  let result2;
  try {
    result2 = await ncr.execute({
      host: "127.0.0.1",
      port: port,
      sendData: "hello",
      timeout: 3000,
      retries: 1,
      bannerFirst: false,
    });
  } catch (e) {
    result2 = e.message;
  }
  console.log("  结果: " + result2.slice(0, 200));
  check(result2.includes("已连接"), "正常 timeout 能连接");
  check(result2.includes("ECHO: hello"), "能收到 echo 回显");

  // 4) 测试连接不存在的端口：应报连接错误（而非超时），且用 connectTimeout
  console.log("\n--- 测试连接不存在端口（应快速报 ECONNREFUSED）---");
  const t2 = Date.now();
  let result3;
  try {
    result3 = await ncr.execute({
      host: "127.0.0.1",
      port: 1, // 不可达端口
      timeout: 6000,
      retries: 1,
      bannerFirst: false,
    });
  } catch (e) {
    result3 = e.message;
  }
  const elapsed3 = Date.now() - t2;
  console.log("  耗时: " + elapsed3 + "ms");
  console.log("  结果: " + result3.slice(0, 200));
  check(result3.includes("ECONNREFUSED") || result3.includes("错误"), "不可达端口报连接错误");
  check(elapsed3 < 5000, "不可达端口快速失败（<5s，不等连接超时）");

  server.close();
  console.log("\n=== 结果: " + passed + " passed, " + failed + " failed ===");
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error("测试异常:", e);
  process.exit(1);
});
