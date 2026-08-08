import { ToolRegistry } from "./registry";
import {
  createWebTools,
  createPwnTools,
  createReverseTools,
  createCryptoTools,
  createMiscTools,
} from "./index";

/**
 * 构建共享、无状态的工具注册表（5 套 CTF 工具全量注册）。
 * 工具定义不含运行态，跨会话复用，整个进程只构建一次。
 */
export function createToolRegistry(): ToolRegistry {
  const toolRegistry = new ToolRegistry();
  for (const t of createWebTools().getAll()) toolRegistry.register(t);
  for (const t of createPwnTools().getAll()) toolRegistry.register(t);
  for (const t of createReverseTools().getAll()) toolRegistry.register(t);
  for (const t of createCryptoTools().getAll()) toolRegistry.register(t);
  for (const t of createMiscTools().getAll()) toolRegistry.register(t);
  return toolRegistry;
}
