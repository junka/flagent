// 全局配置：CLI 作为 npm 全局包时的配置真相源（~/.flagent/config.json）。
// VSCode 扩展不走此文件（用自身 settings.json）。
// 配置优先级：环境变量 DASHSCOPE_API_KEY > 全局配置 apiKey > 项目 .env > 默认值

import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  renameSync,
  chmodSync,
} from "fs";
import { homedir } from "os";
import { join } from "path";

export type Platform = "qianwen" | "bailian";

export interface GlobalConfig {
  platform: Platform;
  modelName: string;
  workspaceId: string; // 百炼平台用；千问平台忽略
  apiKey?: string; // 可选；优先级低于环境变量 DASHSCOPE_API_KEY
}

const CONFIG_DIR = join(homedir(), ".flagent");
const CONFIG_FILE = join(CONFIG_DIR, "config.json");

/** 确保 ~/.flagent/ 目录存在（0o700 权限，保护可能写入的 apiKey）。 */
export function ensureConfigDir(): void {
  if (!existsSync(CONFIG_DIR)) {
    mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  }
}

/** 读取全局配置；文件不存在或解析失败返回 null（由调用方回退默认值）。 */
export function readGlobalConfig(): Partial<GlobalConfig> | null {
  try {
    if (!existsSync(CONFIG_FILE)) return null;
    const raw = readFileSync(CONFIG_FILE, "utf-8");
    const data = JSON.parse(raw);
    return data && typeof data === "object" ? data : null;
  } catch {
    return null;
  }
}

/**
 * 合并写入全局配置（原子写：先写 .tmp 再 rename，避免半写损坏）。
 * 返回写入后的完整配置（合并 readGlobalConfig + partial）。
 */
export function writeGlobalConfig(
  partial: Partial<GlobalConfig>
): Partial<GlobalConfig> {
  ensureConfigDir();
  const current = readGlobalConfig() || {};
  const merged = { ...current, ...partial };
  const tmp = CONFIG_FILE + ".tmp";
  writeFileSync(tmp, JSON.stringify(merged, null, 2), { mode: 0o600 });
  renameSync(tmp, CONFIG_FILE);
  try {
    chmodSync(CONFIG_FILE, 0o600);
  } catch {
    // chmod 失败非致命（Windows 等平台无意义）
  }
  return merged;
}

/** 配置文件路径（测试/调试用）。 */
export function getConfigPath(): string {
  return CONFIG_FILE;
}
