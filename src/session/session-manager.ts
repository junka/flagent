// SessionManager：管理活动会话集合 + 磁盘持久化 + 切换/恢复。
// CLI 直接消费者。toolRegistry 跨会话共享；每会话独立 agent 图。

import { randomUUID } from "crypto";
import type { ToolRegistry } from "../tools/registry";
import type { ConfirmFn } from "../permissions/permission-manager";
import type { AgentResult } from "../agents/main-agent";
import { SessionStore } from "./session-store";
import { Session } from "./session";
import type { SessionMeta } from "./session-data";

export interface SessionManagerOptions {
  toolRegistry: ToolRegistry;
  confirmFn: ConfirmFn;
  storeDir?: string;
  maxSteps?: number;
}

export interface SessionListItem extends SessionMeta {
  active: boolean;
}

export class SessionManager {
  private toolRegistry: ToolRegistry;
  private confirmFn: ConfirmFn;
  private maxSteps?: number;
  private store: SessionStore;
  private sessions = new Map<string, Session>();
  private activeSessionId: string | undefined;

  constructor(opts: SessionManagerOptions) {
    this.toolRegistry = opts.toolRegistry;
    this.confirmFn = opts.confirmFn;
    this.maxSteps = opts.maxSteps;
    this.store = new SessionStore({ dir: opts.storeDir });
  }

  getStoreDir(): string {
    return this.store.getDir();
  }

  /** 新建会话并切为活动；立即持久化。 */
  async create(title?: string): Promise<Session> {
    const id = randomUUID();
    const session = Session.create({
      id,
      title,
      toolRegistry: this.toolRegistry,
      confirmFn: this.confirmFn,
      maxSteps: this.maxSteps,
    });
    this.sessions.set(id, session);
    this.activeSessionId = id;
    await this.persistActive();
    return session;
  }

  current(): Session | undefined {
    return this.activeSessionId ? this.sessions.get(this.activeSessionId) : undefined;
  }

  get(id: string): Session | undefined {
    return this.sessions.get(id);
  }

  getActiveId(): string | undefined {
    return this.activeSessionId;
  }

  /** 列出磁盘会话（合并 active 标记）。 */
  async list(): Promise<SessionListItem[]> {
    const disk = await this.store.list();
    return disk.map((m) => ({
      ...m,
      active: m.sessionId === this.activeSessionId,
    }));
  }

  /** 切换活动会话：内存有则切，无则从磁盘 resume。 */
  async switch(id: string): Promise<Session> {
    if (this.sessions.has(id)) {
      this.activeSessionId = id;
      return this.sessions.get(id)!;
    }
    return this.resume(id);
  }

  /** 从磁盘加载会话到内存并切为活动。 */
  async resume(id: string): Promise<Session> {
    if (this.sessions.has(id)) {
      this.activeSessionId = id;
      return this.sessions.get(id)!;
    }
    const data = await this.store.load(id);
    if (!data) throw new Error(`会话 ${id} 不存在`);
    const session = Session.fromData(data, this.toolRegistry, this.confirmFn);
    this.sessions.set(id, session);
    this.activeSessionId = id;
    return session;
  }

  /** 删除会话（内存 + 磁盘）；删的是当前会话则清空 activeId。 */
  async delete(id: string): Promise<boolean> {
    this.sessions.delete(id);
    if (this.activeSessionId === id) this.activeSessionId = undefined;
    return this.store.delete(id);
  }

  /** 执行任务：无活动会话则自动新建；run 后持久化。 */
  async run(task: string): Promise<AgentResult> {
    if (!this.current()) await this.create();
    const result = await this.current()!.run(task);
    await this.persistActive();
    return result;
  }

  /** 持久化当前活动会话。 */
  async persistActive(): Promise<void> {
    if (this.activeSessionId) await this.persist(this.activeSessionId);
  }

  /** 持久化指定内存会话（rename 等修改非活动会话时用）；不在内存则 no-op。 */
  async persist(id: string): Promise<void> {
    const s = this.sessions.get(id);
    if (s) await this.store.save(s.toData());
  }

  /** 直接列出磁盘会话元信息（不含 active 标记）。 */
  async listFromDisk(): Promise<SessionMeta[]> {
    return this.store.list();
  }
}
