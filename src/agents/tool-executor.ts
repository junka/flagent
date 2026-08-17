// 统一工具执行入口：MainAgent 与 SubAgent 都通过它执行工具，统一权限与并发策略。
// ① 串行确认所有 requirePermission 工具（PermissionManager 自带锁）
// ② 拒绝的标记 skipped 不执行
// ③ concurrent:true 的只读采集并发执行；其余串行（保守，避免副作用冲突）
// ④ 保持原顺序返回
// 通过 EventEmitter 实时推送 toolStart/toolEnd，供 CLI 流式打印并发执行过程。

import { EventEmitter } from "events";
import { ToolRegistry } from "../tools/registry";
import { PermissionManager } from "../permissions/permission-manager";

export interface PlannedAction {
  toolName: string;
  toolArgs: Record<string, any>;
}

export interface ActionResult {
  toolName: string;
  toolArgs: Record<string, any>;
  success: boolean;
  result: string;
  skipped?: boolean; // 权限拒绝
}

type Permit = { ok: boolean; reason: "ok" | "denied" | "not_found" };

export class ToolExecutor extends EventEmitter {
  private concurrencyLimit: number;

  constructor(
    private toolRegistry: ToolRegistry,
    private permissionManager?: PermissionManager,
    concurrencyLimit = 8
  ) {
    super();
    // 并发工具在途上限，避免一次大批只读采集耗尽 FD/连接/内存
    this.concurrencyLimit = Math.max(1, concurrencyLimit);
  }

  async executeBatch(
    actions: PlannedAction[],
    options?: { signal?: AbortSignal; toolTimeoutMs?: number }
  ): Promise<ActionResult[]> {
    if (actions.length === 0) return [];

    const signal = options?.signal;
    const toolTimeoutMs = options?.toolTimeoutMs;

    const throwIfAborted = (): void => {
      if (signal?.aborted) {
        throw signal.reason instanceof Error
          ? signal.reason
          : new Error("Task aborted");
      }
    };
    throwIfAborted();

    // ① 串行确认副作用工具（提示逐个出现，顺序确定）
    const permits = await this.checkPermissions(actions);

    const results: ActionResult[] = new Array(actions.length);

    // ② 预填 not_found / denied，收集待执行项
    const toRun: Array<{ a: PlannedAction; i: number }> = [];
    for (let i = 0; i < actions.length; i++) {
      const a = actions[i];
      const p = permits[i];
      if (p.reason === "not_found") {
        results[i] = {
          toolName: a.toolName,
          toolArgs: a.toolArgs,
          success: false,
          result: `[工具未找到] ${a.toolName}`,
        };
      } else if (!p.ok) {
        results[i] = {
          toolName: a.toolName,
          toolArgs: a.toolArgs,
          success: false,
          result: `[权限拒绝] ${a.toolName} 未获执行许可`,
          skipped: true,
        };
      } else {
        toRun.push({ a, i });
      }
    }

    // ③ concurrent:true 并发执行；其余串行
    const concurrentOnes = toRun.filter((x) =>
      this.toolRegistry.isConcurrent(x.a.toolName)
    );
    const serialOnes = toRun.filter(
      (x) => !this.toolRegistry.isConcurrent(x.a.toolName)
    );

    const wrap = async (x: { a: PlannedAction; i: number }): Promise<void> => {
      throwIfAborted();
      results[x.i] = await this.runOne(x.a, { signal, toolTimeoutMs });
    };

    // 并发组限流执行（避免 FD/连接耗尽）；串行组顺序执行（副作用保守）
    await this.runWithLimit(concurrentOnes.map((x) => () => wrap(x)));
    for (const x of serialOnes) {
      await wrap(x);
    }

    return results;
  }

  /**
   * 执行单个工具（供 AI SDK tool_use 协议的 execute 回调调用）。
   * 复用 runOne 的超时/取消/事件 emit，并补单工具权限检查。
   * 返回结果字符串；权限拒绝/未找到/执行失败统一返回中文提示串（让模型据此继续推理）。
   */
  async executeOne(
    action: PlannedAction,
    opts?: { signal?: AbortSignal; toolTimeoutMs?: number }
  ): Promise<ActionResult> {
    // 单工具权限检查（PermissionManager 自带锁，串行化）
    if (!this.toolRegistry.get(action.toolName)) {
      const r: ActionResult = {
        toolName: action.toolName,
        toolArgs: action.toolArgs,
        success: false,
        result: `[工具未找到] ${action.toolName}`,
        skipped: true,
      };
      return r;
    }
    if (
      this.permissionManager &&
      this.toolRegistry.requiresPermission(action.toolName)
    ) {
      const ok = await this.permissionManager.check(action.toolName, action.toolArgs);
      if (!ok) {
        const r: ActionResult = {
          toolName: action.toolName,
          toolArgs: action.toolArgs,
          success: false,
          result: `[权限拒绝] 用户未授权执行 ${action.toolName}`,
          skipped: true,
        };
        this.emit("event", { type: "toolStart", action });
        this.emit("event", { type: "toolEnd", result: r });
        return r;
      }
    }
    return this.runOne(action, opts);
  }

  // 信号量限流：最多 concurrencyLimit 个任务在途
  // JS 单线程下 idx++ 是原子的（读改写之间无 await），无竞态
  private async runWithLimit(tasks: Array<() => Promise<void>>): Promise<void> {
    if (tasks.length === 0) return;
    let idx = 0;
    const workerCount = Math.min(this.concurrencyLimit, tasks.length);
    const workers = Array.from({ length: workerCount }, async () => {
      while (idx < tasks.length) {
        const i = idx++;
        await tasks[i]();
      }
    });
    await Promise.all(workers);
  }

  private async runOne(
    a: PlannedAction,
    opts?: { signal?: AbortSignal; toolTimeoutMs?: number }
  ): Promise<ActionResult> {
    const signal = opts?.signal;
    const toolTimeoutMs = opts?.toolTimeoutMs;
    this.emit("event", { type: "toolStart", action: a });
    try {
      let resultP: Promise<string> = this.toolRegistry.execute(a.toolName, a.toolArgs);

      // 超时包装：仅当 toolTimeoutMs > 0 时生效
      if (toolTimeoutMs && toolTimeoutMs > 0) {
        resultP = Promise.race([
          resultP,
          new Promise<string>((_, rej) =>
            setTimeout(
              () => rej(new Error(`工具执行超时 (>${toolTimeoutMs}ms)`)),
              toolTimeoutMs
            )
          ),
        ]);
      }

      // 取消信号包装：signal 触发立即 reject
      if (signal) {
        resultP = Promise.race([
          resultP,
          new Promise<string>((_, rej) => {
            const onAbort = () => {
              rej(
                signal!.reason instanceof Error
                  ? (signal!.reason as Error)
                  : new Error("Task aborted")
              );
            };
            if (signal.aborted) {
              onAbort();
              return;
            }
            signal.addEventListener("abort", onAbort, { once: true });
          }).finally(() => {
            try {
              signal.removeEventListener("abort", () => {});
            } catch {}
          }),
        ]);
      }

      const result = await resultP;
      const r: ActionResult = {
        toolName: a.toolName,
        toolArgs: a.toolArgs,
        success: true,
        result,
      };
      this.emit("event", { type: "toolEnd", result: r });
      return r;
    } catch (err: any) {
      const r: ActionResult = {
        toolName: a.toolName,
        toolArgs: a.toolArgs,
        success: false,
        result: `[工具执行失败] ${err && err.message ? err.message : String(err)}`,
      };
      this.emit("event", { type: "toolEnd", result: r });
      return r;
    }
  }

  private async checkPermissions(actions: PlannedAction[]): Promise<Permit[]> {
    const permits: Permit[] = [];
    for (const a of actions) {
      if (!this.toolRegistry.get(a.toolName)) {
        permits.push({ ok: false, reason: "not_found" });
        continue;
      }
      if (
        this.permissionManager &&
        this.toolRegistry.requiresPermission(a.toolName)
      ) {
        const ok = await this.permissionManager.check(a.toolName, a.toolArgs);
        permits.push({ ok, reason: ok ? "ok" : "denied" });
      } else {
        permits.push({ ok: true, reason: "ok" });
      }
    }
    return permits;
  }
}
