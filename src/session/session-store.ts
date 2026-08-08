// 会话磁盘持久化：每个会话一个 JSON 文件，存 .flagent/sessions/<id>.json。
// 损坏文件 warn 跳过不抛，不阻断启动。

import fs from "fs/promises";
import path from "path";
import type { SessionData, SessionMeta } from "./session-data";

export interface SessionStoreOptions {
  dir?: string; // 默认 path.resolve(process.cwd(), ".flagent/sessions")
}

export class SessionStore {
  private dir: string;

  constructor(opts: SessionStoreOptions = {}) {
    this.dir = opts.dir ?? path.resolve(process.cwd(), ".flagent/sessions");
  }

  getDir(): string {
    return this.dir;
  }

  private filePath(id: string): string {
    return path.join(this.dir, `${id}.json`);
  }

  async ensureDir(): Promise<void> {
    await fs.mkdir(this.dir, { recursive: true });
  }

  /** 列出所有会话元信息（按 updatedAt 倒序）。损坏文件跳过。 */
  async list(): Promise<SessionMeta[]> {
    await this.ensureDir();
    let files: string[];
    try {
      files = await fs.readdir(this.dir);
    } catch {
      return [];
    }
    const metas: SessionMeta[] = [];
    for (const f of files) {
      if (!f.endsWith(".json")) continue;
      try {
        const raw = await fs.readFile(path.join(this.dir, f), "utf8");
        const data = JSON.parse(raw) as SessionData;
        metas.push({
          sessionId: data.sessionId,
          title: data.title,
          updatedAt: data.updatedAt,
        });
      } catch (e) {
        console.warn(
          `[SessionStore] 跳过损坏的会话文件 ${f}: ${(e as Error).message}`
        );
      }
    }
    metas.sort((a, b) => b.updatedAt - a.updatedAt);
    return metas;
  }

  /** 读取单个会话；不存在返回 undefined。 */
  async load(id: string): Promise<SessionData | undefined> {
    try {
      const raw = await fs.readFile(this.filePath(id), "utf8");
      return JSON.parse(raw) as SessionData;
    } catch (e: any) {
      if (e.code === "ENOENT") return undefined;
      console.warn(`[SessionStore] 读取会话 ${id} 失败: ${e.message}`);
      return undefined;
    }
  }

  async save(data: SessionData): Promise<void> {
    await this.ensureDir();
    await fs.writeFile(
      this.filePath(data.sessionId),
      JSON.stringify(data, null, 2),
      "utf8"
    );
  }

  /** 删除会话文件；不存在返回 false。 */
  async delete(id: string): Promise<boolean> {
    try {
      await fs.unlink(this.filePath(id));
      return true;
    } catch (e: any) {
      if (e.code === "ENOENT") return false;
      throw e;
    }
  }
}
