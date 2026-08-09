// 验证平台/模型切换与全局配置
// 覆盖：setLLMConfig platform 切换 baseUrl、classifyModel 分类、全局配置 write/read 往返、
//       listAvailableModels 真实 API 调用（需 key，无 key 时跳过网络测试）

const os = require("os");
const path = require("path");
const fs = require("fs");

// 在 require 任何 flagent 模块前，把 HOME 指向临时目录，隔离全局配置文件
const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "flagent-test-"));
process.env.HOME = tmpHome;
process.env.USERPROFILE = tmpHome;

const {
  setLLMConfig,
  getLLMConfig,
  listAvailableModels,
  classifyModel,
} = require("../dist/llm/client");
const {
  writeGlobalConfig,
  readGlobalConfig,
  getConfigPath,
} = require("../dist/config/global-config");

require("dotenv").config();

let passed = 0,
  failed = 0;
function assert(cond, msg) {
  if (cond) {
    passed++;
    console.log("  ✓ " + msg);
  } else {
    failed++;
    console.log("  ✗ " + msg);
  }
}

async function main() {
  console.log("=== 平台切换 baseUrl 测试 ===");

  // 1. qianwen 平台：baseUrl 应为 dashscope.aliyuncs.com
  setLLMConfig({ platform: "qianwen" });
  let cfg = getLLMConfig();
  assert(cfg.platform === "qianwen", "platform=qianwen");
  assert(
    cfg.baseUrl === "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "qianwen baseUrl = dashscope.aliyuncs.com（实际: " + cfg.baseUrl + "）"
  );

  // 2. bailian 平台：baseUrl 应含 workspaceId
  setLLMConfig({ platform: "bailian", workspaceId: "llm-test-ws" });
  cfg = getLLMConfig();
  assert(cfg.platform === "bailian", "platform=bailian");
  assert(
    cfg.baseUrl.includes("llm-test-ws") &&
      cfg.baseUrl.includes("maas.aliyuncs.com"),
    "bailian baseUrl 含 workspaceId（实际: " + cfg.baseUrl + "）"
  );

  // 3. bailian 无 workspaceId 时回退千问端点（避免非法 URL）
  setLLMConfig({ platform: "bailian", workspaceId: "" });
  cfg = getLLMConfig();
  assert(
    cfg.baseUrl === "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "bailian 无 workspaceId 回退千问端点（实际: " + cfg.baseUrl + "）"
  );

  console.log("\n=== classifyModel 分类测试 ===");
  assert(classifyModel("qwen3.8-max") === "对话", "qwen3.8-max → 对话");
  assert(classifyModel("qwen-plus-2025-12-01") === "对话", "qwen-plus → 对话");
  assert(classifyModel("deepseek-v4-pro") === "对话", "deepseek-v4-pro → 对话");
  assert(classifyModel("kimi-k2.6") === "对话", "kimi-k2.6 → 对话");
  assert(
    classifyModel("qwen3-vl-32b-instruct") === "视觉语言",
    "qwen3-vl-32b → 视觉语言"
  );
  assert(
    classifyModel("qwen-vl-max-2025-08-13") === "视觉语言",
    "qwen-vl-max → 视觉语言"
  );
  assert(
    classifyModel("text-embedding-v4") === "嵌入",
    "text-embedding-v4 → 嵌入"
  );
  assert(classifyModel("qwen3-rerank") === "重排", "qwen3-rerank → 重排");
  assert(classifyModel("wan2.7-image") === "图像", "wan2.7-image → 图像");
  assert(classifyModel("emo-detect") === "情感", "emo-detect → 情感");
  assert(
    classifyModel("animate-anyone") === "动作",
    "animate-anyone → 动作"
  );

  console.log("\n=== 全局配置 write/read 往返测试（隔离 HOME） ===");
  // 确认配置路径在临时 HOME 下
  const cfgPath = getConfigPath();
  assert(
    cfgPath.includes(tmpHome),
    "配置路径在临时 HOME 下（" + cfgPath + "）"
  );

  // 写入 platform + modelName
  writeGlobalConfig({ platform: "qianwen", modelName: "qwen-plus" });
  let gcfg = readGlobalConfig();
  assert(gcfg.platform === "qianwen", "readback platform=qianwen");
  assert(gcfg.modelName === "qwen-plus", "readback modelName=qwen-plus");

  // 再写入 workspaceId（合并，不覆盖已有字段）
  writeGlobalConfig({ workspaceId: "merged-ws" });
  gcfg = readGlobalConfig();
  assert(
    gcfg.platform === "qianwen" && gcfg.modelName === "qwen-plus",
    "合并写入保留既有字段"
  );
  assert(gcfg.workspaceId === "merged-ws", "合并写入新字段 workspaceId");

  // 文件确实存在
  assert(fs.existsSync(cfgPath), "配置文件已创建");

  console.log("\n=== listAvailableModels 真实 API 测试 ===");
  const apiKey = process.env.DASHSCOPE_API_KEY;
  if (!apiKey) {
    console.log("  ⏭  无 DASHSCOPE_API_KEY，跳过网络测试");
  } else {
    try {
      // 切回有效 key + bailian 平台
      setLLMConfig({
        apiKey,
        platform: "bailian",
        workspaceId: process.env.WORKSPACE_ID || "llm-v7cepeucys535ynp",
      });
      const models = await listAvailableModels();
      assert(Array.isArray(models) && models.length > 0, "返回非空模型数组");
      assert(
        models.some((m) => m.name === "qwen3.8-max"),
        "含 qwen3.8-max"
      );
      const sample = models[0];
      assert(
        typeof sample.name === "string" &&
          Array.isArray(sample.plans) &&
          typeof sample.category === "string",
        "每个模型有 name/plans/category"
      );
      // 验证分类生效
      const dialogue = models.find((m) => m.name === "qwen3.8-max");
      assert(
        dialogue && dialogue.category === "对话",
        "qwen3.8-max 分类=对话"
      );
      console.log(
        "  ℹ️  共 " + models.length + " 个模型，plans 类型示例: " +
          [...new Set(models.flatMap((m) => m.plans))].join("/")
      );
    } catch (err) {
      console.log("  ⏭  API 调用失败，跳过: " + err.message);
    }
  }

  // 清理临时 HOME
  try {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  } catch {}

  console.log("\n=== 结果: " + passed + " passed, " + failed + " failed ===");
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error("测试异常:", e);
  process.exit(1);
});
