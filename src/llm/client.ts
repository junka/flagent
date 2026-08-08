import { createOpenAI } from "@ai-sdk/openai";
import { type LanguageModel } from "ai";
import dotenv from "dotenv";

dotenv.config();

export interface LLMConfig {
  apiKey: string;
  workspaceId: string;
  modelName: string;
  baseUrl: string;
}

let API_KEY = process.env.DASHSCOPE_API_KEY || "";
let WORKSPACE_ID = process.env.WORKSPACE_ID || "";
let MODEL_NAME = process.env.MODEL_NAME || "qwen3.8-max";

function computeBaseUrl(workspaceId: string): string {
  return `https://${workspaceId}.cn-beijing.maas.aliyuncs.com/compatible-mode/v1`;
}

let BASE_URL = computeBaseUrl(WORKSPACE_ID);
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
    apiKey: API_KEY,
    workspaceId: WORKSPACE_ID,
    modelName: MODEL_NAME,
    baseUrl: BASE_URL,
  };
}

/**
 * 局部覆盖 LLM 配置。未提供字段保持当前值。
 * 主要调用者：VSCode 扩展初始化 & 配置变更回调（让会话使用用户设置的 key）。
 * 注：WORKSPACE_ID 变化会重算 BASE_URL，空字符串的 apiKey 不会抛错（由运行时 API 调用自然失败提示用户）。
 */
export function setLLMConfig(
  partial: Partial<Pick<LLMConfig, "apiKey" | "workspaceId" | "modelName" | "baseUrl">>
): LLMConfig {
  if (partial.apiKey !== undefined) API_KEY = partial.apiKey;
  if (partial.workspaceId !== undefined) {
    WORKSPACE_ID = partial.workspaceId;
    // workspaceId 变更：baseUrl 默认随 workspaceId 重算；只有显式传 baseUrl 才覆盖
    if (partial.baseUrl === undefined) BASE_URL = computeBaseUrl(WORKSPACE_ID);
  }
  if (partial.baseUrl !== undefined) BASE_URL = partial.baseUrl;
  if (partial.modelName !== undefined) MODEL_NAME = partial.modelName;

  dashscopeProvider = createOpenAI({ apiKey: API_KEY, baseURL: BASE_URL });
  model = dashscopeProvider(MODEL_NAME);
  return getLLMConfig();
}

export { dashscopeProvider, API_KEY, WORKSPACE_ID, MODEL_NAME, BASE_URL };
