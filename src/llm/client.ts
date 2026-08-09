import { createOpenAI } from "@ai-sdk/openai";
import { type LanguageModel } from "ai";
import dotenv from "dotenv";
import {
  readGlobalConfig,
  type Platform,
  type GlobalConfig,
} from "../config/global-config";

// quiet: 抑制 dotenv 17 的 "injected env" 启动提示，避免干扰 CLI 输出
dotenv.config({ quiet: true });

export type { Platform };

export interface ModelInfo {
  name: string;
  plans: string[]; // ptu_v2 / mu / cu（部署方案类型，API 无 token 单价）
  category: string; // 对话 / 视觉语言 / 嵌入 / 重排 / 图像 / 情感 / 动作
}

export interface LLMConfig {
  platform: Platform;
  apiKey: string;
  workspaceId: string;
  modelName: string;
  baseUrl: string;
}

// ---- 初始化：环境变量 > 全局配置(~/.flagent/config.json) > .env > 默认值 ----
const globalCfg: Partial<GlobalConfig> = readGlobalConfig() || {};

let PLATFORM: Platform =
  (process.env.PLATFORM as Platform | undefined) || globalCfg.platform || "bailian";
let API_KEY: string =
  process.env.DASHSCOPE_API_KEY || globalCfg.apiKey || "";
let WORKSPACE_ID: string =
  process.env.WORKSPACE_ID || globalCfg.workspaceId || "";
let MODEL_NAME: string =
  process.env.MODEL_NAME || globalCfg.modelName || "qwen3.8-max";

/**
 * 按 platform 分流 baseUrl：
 * - qianwen：https://dashscope.aliyuncs.com/compatible-mode/v1（无需 workspaceId）
 * - bailian：https://{workspaceId}.cn-beijing.maas.aliyuncs.com/compatible-mode/v1（需 workspaceId）
 * 无 workspaceId 时回退千问端点，避免拼出非法 URL（CLI 全局安装且未配置时）。
 */
function computeBaseUrl(platform: Platform, workspaceId: string): string {
  if (platform === "qianwen" || !workspaceId) {
    return "https://dashscope.aliyuncs.com/compatible-mode/v1";
  }
  return `https://${workspaceId}.cn-beijing.maas.aliyuncs.com/compatible-mode/v1`;
}

let BASE_URL = computeBaseUrl(PLATFORM, WORKSPACE_ID);
let dashscopeProvider = createOpenAI({ apiKey: API_KEY, baseURL: BASE_URL });

/**
 * 当前被所有 `import { model }` 消费的 LanguageModel 实例。
 * ESM 的活绑定语义：当下面 setLLMConfig 对 `model` 重新赋值时，
 * 所有已经 import 的引用都会看到新值。
 */
export let model: LanguageModel = dashscopeProvider(MODEL_NAME);

/**
 * 读取当前 LLM 配置快照（CLI BANNER / VSCode 状态查看等使用）。
 */
export function getLLMConfig(): LLMConfig {
  return {
    platform: PLATFORM,
    apiKey: API_KEY,
    workspaceId: WORKSPACE_ID,
    modelName: MODEL_NAME,
    baseUrl: BASE_URL,
  };
}

/**
 * 局部覆盖 LLM 配置。未提供字段保持当前值。
 * platform 变化时按新 platform 重算 baseUrl（qianwen 忽略 workspaceId）。
 * 主要调用者：VSCode 扩展初始化 & 配置变更回调；CLI /platform /model 命令。
 */
export function setLLMConfig(
  partial: Partial<
    Pick<LLMConfig, "platform" | "apiKey" | "workspaceId" | "modelName" | "baseUrl">
  >
): LLMConfig {
  if (partial.platform !== undefined) PLATFORM = partial.platform;
  if (partial.apiKey !== undefined) API_KEY = partial.apiKey;
  if (partial.workspaceId !== undefined) WORKSPACE_ID = partial.workspaceId;
  if (partial.modelName !== undefined) MODEL_NAME = partial.modelName;

  // baseUrl：显式传入优先；否则 platform 或 workspaceId 变化时按当前值重算
  if (partial.baseUrl !== undefined) {
    BASE_URL = partial.baseUrl;
  } else if (partial.platform !== undefined || partial.workspaceId !== undefined) {
    BASE_URL = computeBaseUrl(PLATFORM, WORKSPACE_ID);
  }

  dashscopeProvider = createOpenAI({ apiKey: API_KEY, baseURL: BASE_URL });
  model = dashscopeProvider(MODEL_NAME);
  return getLLMConfig();
}

/**
 * 拉取平台可用模型列表。
 * GET https://dashscope.aliyuncs.com/api/v1/deployments/models?page_no=1&page_size=100&version=v1.0&model_source=base
 * 返回模型名 + plans 类型（ptu_v2/mu/cu）+ 分类。
 * 注：API 仅返回部署方案类型，无 token 调用单价。
 */
export async function listAvailableModels(): Promise<ModelInfo[]> {
  const url =
    "https://dashscope.aliyuncs.com/api/v1/deployments/models?page_no=1&page_size=100&version=v1.0&model_source=base";
  const resp = await fetch(url, {
    headers: {
      Authorization: `Bearer ${API_KEY}`,
      "Content-Type": "application/json",
    },
  });
  if (!resp.ok) {
    throw new Error(
      `模型列表 API 请求失败: ${resp.status} ${resp.statusText}`
    );
  }
  const data: any = await resp.json();
  const models: Array<{ model_name: string; plans: Array<{ plan: string }> }> =
    data?.output?.models || [];
  return models.map((m) => ({
    name: m.model_name,
    plans: (m.plans || []).map((p) => p.plan).filter(Boolean),
    category: classifyModel(m.model_name),
  }));
}

/** 按 model_name 关键词分类，便于 /model 命令分组展示。导出供测试验证。 */
export function classifyModel(name: string): string {
  const n = name.toLowerCase();
  if (n.includes("embedding")) return "嵌入";
  if (n.includes("rerank")) return "重排";
  if (n.includes("wanx") || n.includes("wan2") || n.includes("image"))
    return "图像";
  if (n.includes("emo")) return "情感";
  if (n.includes("animate")) return "动作";
  if (n.includes("vl")) return "视觉语言";
  return "对话";
}

export { dashscopeProvider, API_KEY, WORKSPACE_ID, MODEL_NAME, BASE_URL, PLATFORM };
