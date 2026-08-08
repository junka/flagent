// 权限管理器：对带副作用的工具（requirePermission:true）进行逐次/记忆式确认。
// 记忆粒度=工具名：同一工具在本会话确认一次后不再询问（如 command_exec）。
// promptLock 串行化提示，避免并发委派多 agent 时权限询问交错。

export type ConfirmFn = (
  toolName: string,
  args: Record<string, any>
) => Promise<boolean>;

export class PermissionManager {
  private approved: Set<string> = new Set();
  private promptLock: Promise<void> = Promise.resolve();
  private confirmFn: ConfirmFn;

  constructor(confirmFn: ConfirmFn) {
    this.confirmFn = confirmFn;
  }

  /**
   * 检查工具是否获得执行许可。
   * - 已在本会话批准 → 直接放行（记忆生效，fast-path 无锁同步读，JS 单线程安全）
   * - 未批准 → 双检锁：锁内 re-check 后再询问，避免并发触发同一工具时重复弹窗；
   *   确认则记入 approved 并放行，拒绝则返回 false
   */
  async check(toolName: string, args: Record<string, any>): Promise<boolean> {
    if (this.approved.has(toolName)) {
      return true;
    }
    return this.runLocked(async () => {
      // 锁内复检：并发场景下前一个调用可能已批准该工具
      if (this.approved.has(toolName)) {
        return true;
      }
      const granted = await this.confirmFn(toolName, args);
      if (granted) {
        this.approved.add(toolName);
      }
      return granted;
    });
  }

  isApproved(toolName: string): boolean {
    return this.approved.has(toolName);
  }

  /** 直接批准某工具（会话重载时恢复已批准记忆，不走 confirmFn）。 */
  approve(toolName: string): void {
    this.approved.add(toolName);
  }

  /** 本会话已批准的工具名列表（供 /permissions 命令展示） */
  getApproved(): string[] {
    return Array.from(this.approved);
  }

  /** 清空记忆（/clear 时调用） */
  reset(): void {
    this.approved.clear();
  }

  // Promise 链式锁：reject 也释放，避免锁死
  private runLocked<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.promptLock.then(fn, fn);
    this.promptLock = next.then(
      () => undefined,
      () => undefined
    );
    return next;
  }
}
