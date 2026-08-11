// BackgroundManager：管理后台运行的 Agent 任务，提供健康检查/卡死检测/取消。
// 设计目标：
//   - Session.run() 仍阻塞（兼容旧代码）；新增 Session.runBackground() 返回 taskId，任务在后台 Promise 中推进
//   - 每个 BackgroundTask 有状态机：PENDING → RUNNING → COMPLETED / CRASHED / CANCELLED
//                                              ↘ STUCK（超时无活动，用户可选 kill / 继续等待）
//   - 心跳：MainAgent 每 emitEvent / ToolExecutor 每 toolStart-toolEnd / stepStart-stepEnd
//           都会调用 heartbeat() 刷新 lastActivityAt；超过 stuckThresholdMs 判定 STUCK
//   - 取消：AbortController 信号向下传播到 LLM generateText() 与 ToolExecutor
//   - 健康检查：healthCheck() 遍历所有 RUNNING 任务，计算 "距最近活动时间"，
//              > warnThreshold 标记 WARNING；> stuckThreshold 标记 STUCK

import { EventEmitter } from "events";
import type { AgentResult } from "./main-agent";
import type { AgentEvent } from "./agent-events";

export type BackgroundTaskStatus =
  | "PENDING"
  | "RUNNING"
  | "STUCK"
  | "COMPLETED"
  | "CRASHED"
  | "CANCELLED";

export interface BackgroundTaskSnapshot {
  taskId: string;
  sessionId: string;
  title: string;
  taskPreview: string;
  status: BackgroundTaskStatus;
  createdAt: number;
  startedAt: number | null;
  endedAt: number | null;
  lastActivityAt: number | null;
  currentStep: number | null;
  maxSteps: number | null;
  /** 距最近活动毫秒数（仅 RUNNING / STUCK 有意义） */
  idleMs: number | null;
  result?: AgentResult;
  error?: string;
}

export interface BackgroundOptions {
  /** 无活动多久判定卡死，默认 5 分钟 */
  stuckThresholdMs?: number;
  /** 无活动多久预警，默认 90 秒 */
  warnThresholdMs?: number;
  /** 单个工具默认超时毫秒，默认 2 分钟 */
  toolTimeoutMs?: number;
  /** 后台任务专用事件回调（携带 taskId）；避免与 Session.RunOptions.onEvent 同名冲突。 */
  onBackgroundEvent?: (taskId: string, event: AgentEvent) => void;
}

interface InternalTask {
  taskId: string;
  sessionId: string;
  title: string;
  taskPreview: string;
  status: BackgroundTaskStatus;
  createdAt: number;
  /** 插入序号：同一 createdAt 的任务按此字段倒序，确保创建越后越靠前（稳定排序）。 */
  insertSeq: number;
  startedAt: number | null;
  endedAt: number | null;
  lastActivityAt: number | null;
  currentStep: number | null;
  maxSteps: number | null;
  stuckThresholdMs: number;
  warnThresholdMs: number;
  toolTimeoutMs: number;
  abortController: AbortController;
  userOnEvent?: (taskId: string, event: AgentEvent) => void;
  promise?: Promise<AgentResult>;
  result?: AgentResult;
  error?: string;
}

export class BackgroundManager extends EventEmitter {
  private static _instance: BackgroundManager | null = null;
  private tasks: Map<string, InternalTask> = new Map();

  private constructor() {
    super();
  }

  static getInstance(): BackgroundManager {
    if (!BackgroundManager._instance) {
      BackgroundManager._instance = new BackgroundManager();
    }
    return BackgroundManager._instance;
  }

  /** 仅用于测试：重置单例。生产环境不调用。 */
  static _resetForTest(): void {
    if (BackgroundManager._instance) {
      for (const t of BackgroundManager._instance.tasks.values()) {
        try { t.abortController.abort(); } catch {}
      }
      BackgroundManager._instance.removeAllListeners();
      BackgroundManager._instance.tasks.clear();
    }
    BackgroundManager._instance = null;
  }

  /**
   * 创建一个后台任务（但不启动），返回 taskId。
   * 调用方需要自己把 promise 跑起来（通过 executeFn）。
   * 这么设计是为了避免 BackgroundManager 依赖 Session（避免循环 import）。
   */
  createTask(init: {
    sessionId: string;
    title: string;
    task: string;
    options?: BackgroundOptions;
  }): {
    taskId: string;
    signal: AbortSignal;
    heartbeat: () => void;
    onEvent: (event: AgentEvent) => void;
    toolTimeoutMs: number;
    bindPromise: (p: Promise<AgentResult>) => void;
    markStart: () => void;
    markStep: (step: number, maxSteps?: number) => void;
    markComplete: (result: AgentResult) => void;
    markCrash: (err: Error) => void;
  } {
    const taskId =
      "bg-" +
      Date.now().toString(36) +
      Math.random().toString(36).slice(2, 8);
    const task: InternalTask = {
      taskId,
      sessionId: init.sessionId,
      title: init.title,
      taskPreview:
        init.task.length > 80 ? init.task.slice(0, 80) + "…" : init.task,
      status: "PENDING",
      createdAt: Date.now(),
      insertSeq: this.tasks.size,
      startedAt: null,
      endedAt: null,
      lastActivityAt: null,
      currentStep: null,
      maxSteps: null,
      stuckThresholdMs: init.options?.stuckThresholdMs ?? 5 * 60 * 1000,
      warnThresholdMs: init.options?.warnThresholdMs ?? 90 * 1000,
      toolTimeoutMs: init.options?.toolTimeoutMs ?? 2 * 60 * 1000,
      abortController: new AbortController(),
      userOnEvent: init.options?.onBackgroundEvent,
    };
    this.tasks.set(taskId, task);

    const heartbeat = () => {
      const t = this.tasks.get(taskId);
      if (!t) return;
      t.lastActivityAt = Date.now();
      // 从 STUCK 恢复活动时降回 RUNNING
      if (t.status === "STUCK") t.status = "RUNNING";
      this.emit("heartbeat", taskId);
    };

    const onEvent = (event: AgentEvent) => {
      heartbeat();
      const t = this.tasks.get(taskId);
      if (!t) return;
      if (event.type === "stepStart") {
        t.currentStep = event.step;
        t.maxSteps = event.maxSteps;
      }
      try { task.userOnEvent?.(taskId, event); } catch {}
      this.emit("event", taskId, event);
    };

    const bindPromise = (p: Promise<AgentResult>) => {
      task.promise = p.catch((err) => {
        markCrash(err);
        throw err;
      }).then((r) => {
        markComplete(r);
        return r;
      });
    };

    const markStart = () => {
      const t = this.tasks.get(taskId);
      if (!t) return;
      t.status = "RUNNING";
      t.startedAt = Date.now();
      t.lastActivityAt = Date.now();
      this.emit("statusChange", taskId, "RUNNING");
    };

    const markStep = (step: number, maxSteps?: number) => {
      const t = this.tasks.get(taskId);
      if (!t) return;
      t.currentStep = step;
      if (maxSteps != null) t.maxSteps = maxSteps;
      heartbeat();
    };

    const markComplete = (result: AgentResult) => {
      const t = this.tasks.get(taskId);
      if (!t) return;
      t.status = "COMPLETED";
      t.endedAt = Date.now();
      t.result = result;
      this.emit("statusChange", taskId, "COMPLETED", result);
    };

    const markCrash = (err: Error) => {
      const t = this.tasks.get(taskId);
      if (!t) return;
      t.status = "CRASHED";
      t.endedAt = Date.now();
      t.error = err && err.message ? err.message : String(err);
      this.emit("statusChange", taskId, "CRASHED", t.error);
    };

    return {
      taskId,
      signal: task.abortController.signal,
      heartbeat,
      onEvent,
      toolTimeoutMs: task.toolTimeoutMs,
      bindPromise,
      markStart,
      markStep,
      markComplete,
      markCrash,
    };
  }

  /** 取消任务（传播 AbortSignal）。成功取消返回 true；已结束的返回 false。 */
  cancel(taskId: string): boolean {
    const t = this.tasks.get(taskId);
    if (!t) return false;
    if (
      t.status === "COMPLETED" ||
      t.status === "CRASHED" ||
      t.status === "CANCELLED"
    ) {
      return false;
    }
    try { t.abortController.abort(new Error("Task cancelled by user")); } catch {}
    t.status = "CANCELLED";
    t.endedAt = Date.now();
    this.emit("statusChange", taskId, "CANCELLED");
    return true;
  }

  /** 获取单个任务快照。 */
  getStatus(taskId: string): BackgroundTaskSnapshot | null {
    const t = this.tasks.get(taskId);
    return t ? this._snapshot(t) : null;
  }

  /** 列出所有任务快照（按创建时间倒序）。 */
  list(): BackgroundTaskSnapshot[] {
    // 先按 tasks.insertSeq 获得排序（避免 createdAt 同毫秒不稳定）
    const values = Array.from(this.tasks.values());
    values.sort((a, b) => b.createdAt - a.createdAt || b.insertSeq - a.insertSeq);
    return values.map((t) => this._snapshot(t));
  }

  /**
   * 健康检查：遍历 RUNNING 任务，按 idleMs 将 STUCK 的任务自动标记（仅当从未标记过）。
   * 返回：每个任务的健康报告。
   */
  healthCheck(): Array<
    BackgroundTaskSnapshot & { health: "HEALTHY" | "WARNING" | "STUCK" | "IDLE" }
  > {
    const now = Date.now();
    return Array.from(this.tasks.values())
      .map((t) => {
        let health: "HEALTHY" | "WARNING" | "STUCK" | "IDLE" = "IDLE";
        if (t.status === "RUNNING" || t.status === "STUCK") {
          const idle = t.lastActivityAt ? now - t.lastActivityAt : now - (t.startedAt || now);
          if (idle >= t.stuckThresholdMs) {
            if (t.status !== "STUCK") {
              t.status = "STUCK";
              this.emit("statusChange", t.taskId, "STUCK");
            }
            health = "STUCK";
          } else if (idle >= t.warnThresholdMs) {
            health = "WARNING";
          } else {
            health = "HEALTHY";
          }
        }
        return { ...this._snapshot(t), health };
      })
      .sort((a, b) => b.createdAt - a.createdAt);
  }

  /** 清理已结束超过 retentionMs 的任务（默认 24h）。返回清理数量。 */
  cleanup(retentionMs = 24 * 60 * 60 * 1000): number {
    const now = Date.now();
    let removed = 0;
    for (const [id, t] of this.tasks) {
      if (
        (t.status === "COMPLETED" || t.status === "CRASHED" || t.status === "CANCELLED") &&
        t.endedAt != null &&
        now - t.endedAt > retentionMs
      ) {
        this.tasks.delete(id);
        removed++;
      }
    }
    return removed;
  }

  // ---- helpers ----
  private _get(taskId: string): InternalTask | undefined {
    return this.tasks.get(taskId);
  }

  private _snapshot(t: InternalTask): BackgroundTaskSnapshot {
    const now = Date.now();
    const idleMs =
      t.status === "RUNNING" || t.status === "STUCK"
        ? t.lastActivityAt
          ? now - t.lastActivityAt
          : t.startedAt
          ? now - t.startedAt
          : null
        : null;
    return {
      taskId: t.taskId,
      sessionId: t.sessionId,
      title: t.title,
      taskPreview: t.taskPreview,
      status: t.status,
      createdAt: t.createdAt,
      startedAt: t.startedAt,
      endedAt: t.endedAt,
      lastActivityAt: t.lastActivityAt,
      currentStep: t.currentStep,
      maxSteps: t.maxSteps,
      idleMs,
      result: t.result,
      error: t.error,
    };
  }
}

/** 方便的公共函数：获取 BackgroundManager 单例。 */
export function getBackgroundManager(): BackgroundManager {
  return BackgroundManager.getInstance();
}
