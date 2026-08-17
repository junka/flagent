import { ToolRegistry } from "./registry";
import {
  createWebTools,
  createWebAdvancedTools,
  createDatabaseTools,
  createPwnTools,
  createReverseTools,
  createCryptoTools,
  createMiscTools,
  createForensicsTools,
  createMobileTools,
  createBlockchainTools,
  createOsintTools,
  createCloudTools,
  createIotTools,
  createAimlTools,
  createLinuxSecurityTools,
  createEncodingExtTools,
  createCipherExtTools,
  createMiscCtfTools,
  createCryptoExtTools,
  createRceTools,
} from "./index";

/**
 * 构建共享、无状态的工具注册表（12 套 CTF 工具全量注册）。
 * 工具定义不含运行态，跨会话复用，整个进程只构建一次。
 */
export function createToolRegistry(): ToolRegistry {
  const toolRegistry = new ToolRegistry();
  for (const t of createWebTools().getAll()) toolRegistry.register(t);
  for (const t of createWebAdvancedTools().getAll()) toolRegistry.register(t);
  for (const t of createDatabaseTools().getAll()) toolRegistry.register(t);
  for (const t of createPwnTools().getAll()) toolRegistry.register(t);
  for (const t of createReverseTools().getAll()) toolRegistry.register(t);
  for (const t of createCryptoTools().getAll()) toolRegistry.register(t);
  for (const t of createMiscTools().getAll()) toolRegistry.register(t);
  for (const t of createForensicsTools().getAll()) toolRegistry.register(t);
  for (const t of createMobileTools().getAll()) toolRegistry.register(t);
  for (const t of createBlockchainTools().getAll()) toolRegistry.register(t);
  for (const t of createOsintTools().getAll()) toolRegistry.register(t);
  for (const t of createCloudTools().getAll()) toolRegistry.register(t);
  for (const t of createIotTools().getAll()) toolRegistry.register(t);
  for (const t of createAimlTools().getAll()) toolRegistry.register(t);
  for (const t of createLinuxSecurityTools().getAll()) toolRegistry.register(t);
  for (const t of createEncodingExtTools().getAll()) toolRegistry.register(t);
  for (const t of createCipherExtTools().getAll()) toolRegistry.register(t);
  for (const t of createMiscCtfTools().getAll()) toolRegistry.register(t);
  for (const t of createCryptoExtTools().getAll()) toolRegistry.register(t);
  for (const t of createRceTools().getAll()) toolRegistry.register(t);
  return toolRegistry;
}
