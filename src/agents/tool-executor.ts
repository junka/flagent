// 统一工具执行入口：MainAgent 与 SubAgent 都通过它执行工具，统一权限与并发策略。
// ① 串行确认所有 requirePermission 工具（PermissionManager 自带锁）
// ② 拒绝的标记 skipped 不执行
// ③ concurrent:true 的只读采集并发执行；其余串行（保守，避免副作用冲突）
// ④ 保持原顺序返回

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

export class ToolExecutor {
  private concurrencyLimit: number;

  constructor(
    private toolRegistry: ToolRegistry,
    private permissionManager?: PermissionManager,
    concurrencyLimit = 8
  ) {
    // 并发工具在途上限，避免一次大批只读采集耗尽 FD/连接/内存
    this.concurrencyLimit = Math.max(1, concurrencyLimit);
  }

  async executeBatch(actions: PlannedAction[]): Promise<ActionResult[]> {
    if (actions.length === 0) return [];

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

    // 并发组限流执行（避免 FD/连接耗尽）；串行组顺序执行（副作用保守）
    await this.runWithLimit(
      concurrentOnes.map(
        (x) => async () => {
          results[x.i] = await this.runOne(x.a);
        }
      )
    );
    for (const x of serialOnes) {
      results[x.i] = await this.runOne(x.a);
    }

    return results;
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

  private async runOne(a: PlannedAction): Promise<ActionResult> {
    try {
      const result = await this.toolRegistry.execute(a.toolName, a.toolArgs);
      return { toolName: a.toolName, toolArgs: a.toolArgs, success: true, result };
    } catch (err: any) {
      return {
        toolName: a.toolName,
        toolArgs: a.toolArgs,
        success: false,
        result: `[工具执行失败] ${err.message}`,
      };
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
