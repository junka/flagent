// Session：单个分析会话，封装一整套 agent 图 + 元信息 + 序列化/反序列化。
// 每会话独立 ContextManager/MainAgent/PermissionManager/Scheduler；共享 ToolRegistry。

import type { ToolRegistry } from "../tools/registry";
import type { ConfirmFn } from "../permissions/permission-manager";
import { PermissionManager } from "../permissions/permission-manager";
import { createAgentSystem, type AgentSystem } from "../agents/factory";
import type { MainAgent, AgentResult, AgentStep } from "../agents/main-agent";
import type { Scheduler } from "../agents/scheduler";
import type { ContextManager } from "../context/context-manager";
import type { SessionData } from "./session-data";
import type {
  AgentEvent,
  ConfirmPlanFn,
} from "../agents/agent-events";
import {
  getBackgroundManager,
  type BackgroundOptions,
  type BackgroundTaskSnapshot,
} from "../agents/background-manager";
export type { BackgroundOptions, BackgroundTaskSnapshot };

/** 运行选项：流式事件回调与 Plan 门控确认回调，全部可选（旧调用零改动）。 */
export interface RunOptions {
  /** 实时事件回调（思考/Plan/工具执行/最终答案等）。 */
  onEvent?: (event: AgentEvent) => void;
  /** 多步骤 Plan 执行前的确认回调；返回 false 取消。 */
  confirmPlan?: ConfirmPlanFn;
}

export interface SessionCreateInit {
  id: string;
  title?: string;
  toolRegistry: ToolRegistry;
  confirmFn: ConfirmFn;
  maxSteps?: number;
}

export class Session {
  readonly id: string;
  title: string;
  readonly createdAt: number;
  updatedAt: number;
  private mainAgent: MainAgent;
  private scheduler: Scheduler;
  private contextManager: ContextManager;
  private permissionManager: PermissionManager;
  private toolRegistry: ToolRegistry;
  private steps: AgentStep[]; // 跨 run 累积历史

  private constructor(args: {
    id: string;
    title: string;
    createdAt: number;
    updatedAt: number;
    system: AgentSystem;
    toolRegistry: ToolRegistry;
    steps: AgentStep[];
  }) {
    this.id = args.id;
    this.title = args.title;
    this.createdAt = args.createdAt;
    this.updatedAt = args.updatedAt;
    this.mainAgent = args.system.mainAgent;
    this.scheduler = args.system.scheduler;
    this.contextManager = args.system.contextManager;
    this.permissionManager = args.system.permissionManager;
    this.toolRegistry = args.toolRegistry;
    this.steps = args.steps;
  }

  /** 新建空会话：独立 PermissionManager + createAgentSystem。 */
  static create(init: SessionCreateInit): Session {
    const permissionManager = new PermissionManager(init.confirmFn);
    const system = createAgentSystem({
      toolRegistry: init.toolRegistry,
      permissionManager,
      maxSteps: init.maxSteps,
    });
    const now = Date.now();
    return new Session({
      id: init.id,
      title: init.title ?? "",
      createdAt: now,
      updatedAt: now,
      system,
      toolRegistry: init.toolRegistry,
      steps: [],
    });
  }

  /** 从持久化数据重建：预置 approved → 建 agent 图 → 恢复消息 → 重注册动态 agent → 恢复 steps。 */
  static fromData(
    data: SessionData,
    toolRegistry: ToolRegistry,
    confirmFn: ConfirmFn
  ): Session {
    const permissionManager = new PermissionManager(confirmFn);
    for (const t of data.approvedTools) permissionManager.approve(t);
    const system = createAgentSystem({ toolRegistry, permissionManager });
    system.contextManager.restoreMessages(data.messages, data.summary);
    for (const cfg of data.dynamicAgents) {
      try {
        system.scheduler.registerDynamicAgent(cfg);
      } catch (e) {
        console.warn(
          `[Session] 恢复动态 agent ${cfg.id} 失败: ${(e as Error).message}`
        );
      }
    }
    system.mainAgent.setSteps(data.steps);
    return new Session({
      id: data.sessionId,
      title: data.title,
      createdAt: data.createdAt,
      updatedAt: data.updatedAt,
      system,
      toolRegistry,
      steps: [...data.steps],
    });
  }

  /** 执行任务：首次自动派生 title，累积 steps，更新 updatedAt。可选流式事件与 Plan 门控。 */
  async run(task: string, options?: RunOptions): Promise<AgentResult> {
    if (!this.title) this.title = this.deriveTitle(task);

    // 桥接事件：监听 mainAgent + toolExecutor 的 "event" 通道，转发给 onEvent
    const onEvent = options?.onEvent;
    const toolExecutor = this.mainAgent.getToolExecutor();
    let mainHandler: ((e: AgentEvent) => void) | undefined;
    let toolHandler: ((e: AgentEvent) => void) | undefined;
    if (onEvent) {
      mainHandler = (e: AgentEvent) => onEvent(e);
      this.mainAgent.on("event", mainHandler);
      if (toolExecutor) {
        toolHandler = (e: AgentEvent) => onEvent(e);
        toolExecutor.on("event", toolHandler);
      }
    }
    // Plan 门控回调注入
    if (options?.confirmPlan) {
      this.mainAgent.setConfirmPlanFn(options.confirmPlan);
    }

    try {
      const result = await this.mainAgent.run(task);
      // MainAgent.run 每次重置自身 steps；Session 是跨 run 历史真相源，累积保留
      this.steps = [...this.steps, ...result.steps];
      this.updatedAt = Date.now();
      return result;
    } finally {
      // 清理监听，避免跨 run 累积；重置 confirmPlanFn
      if (mainHandler) this.mainAgent.off("event", mainHandler);
      if (toolHandler && toolExecutor) toolExecutor.off("event", toolHandler);
      if (options?.confirmPlan) this.mainAgent.setConfirmPlanFn(undefined);
    }
  }

  /**
   * 后台执行任务，立即返回 taskId。任务在 Promise 中推进，可通过
   * getBackgroundStatus / cli 的 /bg /status 查看进度，/kill 取消。
   * 完成/崩溃/取消都会更新任务状态，结果存 BackgroundManager 供轮询。
   */
  runBackground(task: string, options?: RunOptions & BackgroundOptions): string {
    const mgr = getBackgroundManager();
    const {
      taskId,
      signal,
      heartbeat,
      onEvent,
      toolTimeoutMs,
      bindPromise,
      markStart,
      markStep,
      markComplete,
      markCrash,
    } = mgr.createTask({
      sessionId: this.id,
      title: this.title || this.deriveTitle(task),
      task,
      options,
    });

    // 异步启动：不 await，调用方拿到 taskId 就离开
    const promise = (async (): Promise<AgentResult> => {
      // 桥接事件：监听 mainAgent + toolExecutor 的 "event" 通道
      const onEventLocal = options?.onEvent;
      const toolExecutor = this.mainAgent.getToolExecutor();
      let mainHandler: ((e: AgentEvent) => void) | undefined;
      let toolHandler: ((e: AgentEvent) => void) | undefined;
      const localEmit = (e: AgentEvent): void => {
        onEvent(e); // Background 先记心跳
        try { onEventLocal?.(e); } catch {}
        if (e.type === "stepStart") markStep(e.step, e.maxSteps);
      };
      mainHandler = (e: AgentEvent) => localEmit(e);
      this.mainAgent.on("event", mainHandler);
      if (toolExecutor) {
        toolHandler = (e: AgentEvent) => localEmit(e);
        toolExecutor.on("event", toolHandler);
      }
      try {
        // Plan 门控回调注入
        if (options?.confirmPlan) this.mainAgent.setConfirmPlanFn(options.confirmPlan);
        this.mainAgent.setHeartbeatCallback(heartbeat);

        if (!this.title) this.title = this.deriveTitle(task);
        markStart();

        const result = await this.mainAgent.run(task, { signal, toolTimeoutMs });
        // MainAgent.run 每次重置自身 steps；Session 是跨 run 历史真相源，累积保留
        this.steps = [...this.steps, ...result.steps];
        this.updatedAt = Date.now();
        markComplete(result);
        return result;
      } catch (err: any) {
        const eObj = err instanceof Error ? err : new Error(String(err));
        markCrash(eObj);
        throw eObj;
      } finally {
        if (mainHandler) this.mainAgent.off("event", mainHandler);
        if (toolHandler && toolExecutor) toolExecutor.off("event", toolHandler);
        if (options?.confirmPlan) this.mainAgent.setConfirmPlanFn(undefined);
        this.mainAgent.setHeartbeatCallback(undefined);
      }
    })();
    bindPromise(promise);
    return taskId;
  }

  /** 查询指定后台任务状态（本会话的）；若 taskId 属于别的会话也能拿到（通用视图）。 */
  getBackgroundStatus(taskId: string): BackgroundTaskSnapshot | null {
    return getBackgroundManager().getStatus(taskId);
  }

  /** 序列化为可持久化结构（messages 去 timestamp/tokenCount）。 */
  toData(): SessionData {
    return {
      sessionId: this.id,
      title: this.title,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
      messages: this.contextManager
        .getMessages()
        .map((m) => ({ role: m.role, content: m.content })),
      summary: this.contextManager.getSummary(),
      steps: this.steps,
      approvedTools: this.permissionManager.getApproved(),
      dynamicAgents: this.scheduler.getDynamicAgentConfigs(),
    };
  }

  /** 从任务文本派生标题（前 30 字，超长加省略号）。 */
  deriveTitle(task: string): string {
    const t = task.trim().replace(/\s+/g, " ");
    return t.slice(0, 30) + (t.length > 30 ? "…" : "");
  }

  getMainAgent(): MainAgent {
    return this.mainAgent;
  }
  getScheduler(): Scheduler {
    return this.scheduler;
  }
  getContextManager(): ContextManager {
    return this.contextManager;
  }
  getPermissionManager(): PermissionManager {
    return this.permissionManager;
  }
  getSteps(): AgentStep[] {
    return [...this.steps];
  }
  setTitle(title: string): void {
    this.title = title;
  }

  /** 清运行态：context + 权限记忆（不清 steps 历史，与既有 /clear 语义一致）。 */
  clearRuntime(): void {
    this.contextManager.clear();
    this.permissionManager.reset();
  }
}
