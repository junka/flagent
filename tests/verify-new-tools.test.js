// 7 套新 CTF 工具 Smoke 测试：验证工具注册/元数据/文件不存在分支
"use strict";

const assert = require("assert");
const { createToolRegistry } = require("../dist/tools");

const registry = createToolRegistry();

// 预期 7 套新工具的完整清单
const expected = {
  forensics: [
    { name: "disk_forensics", perm: false },
    { name: "filesystem_analyze", perm: false },
    { name: "registry_analyze", perm: false },
    { name: "log_forensics", perm: false },
    { name: "timeline_reconstruct", perm: false },
    { name: "volatility_plugin", perm: true },
    { name: "pcap_deep_analyze", perm: false },
  ],
  mobile: [
    { name: "apk_deep_analysis", perm: false },
    { name: "dex_decompile", perm: false },
    { name: "smali_edit", perm: true },
    { name: "frida_hook", perm: true },
    { name: "ipa_analysis", perm: false },
    { name: "ssl_pinning_bypass", perm: false },
  ],
  blockchain: [
    { name: "sol_disassemble", perm: false },
    { name: "evm_decompile", perm: false },
    { name: "contract_audit", perm: false },
    { name: "reentrancy_test", perm: false },
    { name: "slither_scan", perm: false },
    { name: "tx_trace_analyze", perm: false },
    { name: "rpc_query", perm: false },
  ],
  osint: [
    { name: "web_search_real", perm: false },
    { name: "whois_lookup", perm: false },
    { name: "social_media_search", perm: false },
    { name: "geo_locate", perm: false },
    { name: "image_exif_analyze", perm: false },
    { name: "reverse_image_search", perm: false },
    { name: "subdomain_enum", perm: false },
    { name: "wayback_lookup", perm: false },
  ],
  cloud: [
    { name: "iam_enum", perm: false },
    { name: "s3_bucket_scan", perm: false },
    { name: "container_escape_test", perm: true },
    { name: "k8s_attack", perm: true },
    { name: "cloud_metadata_exploit", perm: false },
    { name: "terraform_audit", perm: false },
  ],
  iot: [
    { name: "firmware_extract", perm: false },
    { name: "binwalk_scan", perm: false },
    { name: "uart_jtag_detect", perm: false },
    { name: "mqtt_analyze", perm: false },
    { name: "coap_analyze", perm: false },
    { name: "iot_protocol_fuzz", perm: true },
  ],
  aiml: [
    { name: "prompt_injection_test", perm: false },
    { name: "jailbreak_test", perm: false },
    { name: "model_inversion", perm: false },
    { name: "adversarial_sample", perm: true },
    { name: "data_poison_detect", perm: false },
    { name: "llm_leak_test", perm: false },
  ],
};

let total = 0, passed = 0;

function test(name, fn) {
  total++;
  try {
    fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (e) {
    console.log(`  ✗ ${name}: ${e.message}`);
    process.exitCode = 1;
  }
}

console.log("\n== 7 套新 CTF 工具 Smoke 测试 ==");

// 1. 验证工具注册和元数据
for (const [category, tools] of Object.entries(expected)) {
  test(`${category}: ${tools.length} 个工具全部注册且 category/perm 正确`, () => {
    for (const t of tools) {
      const tool = registry.get(t.name);
      assert.ok(tool, `工具 ${t.name} 未注册`);
      assert.strictEqual(tool.category, category, `工具 ${t.name} category=${tool.category} 应为 ${category}`);
      assert.strictEqual(
        tool.requirePermission === true,
        t.perm,
        `工具 ${t.name} requirePermission=${tool.requirePermission} 应为 ${t.perm}`
      );
    }
  });
}

// 2. 文件不存在分支测试（针对需要文件路径的工具）
const fileNotFoundTools = [
  ["disk_forensics", { image_path: "/__no_such_file__" }],
  ["filesystem_analyze", { path: "/__no_such_file__" }],
  ["registry_analyze", { hive_path: "/__no_such_file__" }],
  ["log_forensics", { log_path: "/__no_such_file__" }],
  ["timeline_reconstruct", { path: "/__no_such_file__" }],
  ["volatility_plugin", { image_path: "/__no_such_file__", plugin: "pslist" }],
  ["pcap_deep_analyze", { pcap_path: "/__no_such_file__" }],
  ["apk_deep_analysis", { apk_path: "/__no_such_file__" }],
  ["dex_decompile", { dex_path: "/__no_such_file__" }],
  ["smali_edit", { apk_path: "/__no_such_file__", action: "decompile" }],
  ["ipa_analysis", { ipa_path: "/__no_such_file__" }],
  ["image_exif_analyze", { image_path: "/__no_such_file__" }],
  ["reverse_image_search", { image_path: "/__no_such_file__" }],
  ["firmware_extract", { firmware_path: "/__no_such_file__" }],
  ["binwalk_scan", { firmware_path: "/__no_such_file__" }],
  ["contract_audit", { contract_path: "/__no_such_file__" }],
  ["reentrancy_test", { contract_path: "/__no_such_file__" }],
  ["slither_scan", { contract_path: "/__no_such_file__" }],
  ["terraform_audit", { project_path: "/__no_such_dir__" }],
];

for (const [name, args] of fileNotFoundTools) {
  test(`${name}: 文件不存在 → 返回错误提示`, async () => {
    const tool = registry.get(name);
    const result = await tool.execute(args);
    assert.ok(
      result.includes("❌") || result.includes("不存在") || result.includes("未找到") || result.includes("No such"),
      `${name} 应返回文件不存在提示，实际: ${result.slice(0, 200)}`
    );
  });
}

// 3. 非文件类工具基本可用性测试
test("uart_jtag_detect: guide 模式返回指南", async () => {
  const tool = registry.get("uart_jtag_detect");
  const result = await tool.execute({ mode: "guide" });
  assert.ok(result.length > 50, `uart_jtag_detect guide 应返回有内容的指南`);
});

test("ssl_pinning_bypass: 生成 Frida 脚本", async () => {
  const tool = registry.get("ssl_pinning_bypass");
  const result = await tool.execute({ platform: "android", method: "frida", package: "com.test.app" });
  assert.ok(result.includes("Frida") || result.includes("script") || result.includes("OkHttp"), `应返回 Frida 脚本`);
});

test("web_search_real: 参数校验正常", async () => {
  const tool = registry.get("web_search_real");
  // 只验证不抛异常即可（实际搜索可能超时）
  assert.ok(tool.parameters, "web_search_real 应有 parameters schema");
});

test("cloud_metadata_exploit: check 模式", async () => {
  const tool = registry.get("cloud_metadata_exploit");
  const result = await tool.execute({ mode: "check" });
  assert.ok(typeof result === "string" && result.length > 10, `应返回检测结果`);
});

// 4. 验证总工具数（原 66 + 新 46 = 112，加 default 6 = ~118，但不强制精确）
test("总工具数 >= 100", () => {
  const count = registry.getAll().length;
  assert.ok(count >= 100, `工具总数应 >= 100，实际 ${count}`);
  console.log(`    总工具数: ${count}`);
});

// 5. 验证 12 个 SubAgent 都有对应工具
test("12 个 category 均有工具", () => {
  const categories = ["web", "pwn", "reverse", "crypto", "misc", "forensics", "mobile", "blockchain", "osint", "cloud", "iot", "aiml"];
  for (const cat of categories) {
    const tools = registry.getByCategory(cat);
    assert.ok(tools.length > 0, `category "${cat}" 应至少有 1 个工具`);
  }
  console.log(`    12 个 category: ${categories.map(c => `${c}(${registry.getByCategory(c).length})`).join(", ")}`);
});

console.log(`\nNew tools smoke: ${passed}/${total} passed`);
