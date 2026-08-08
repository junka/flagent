// 侧边栏会话树：列出所有会话（按 updatedAt 倒序），活跃会话高亮，点击切换。
import * as vscode from "vscode";
import type { SessionManager, SessionListItem } from "../session";

/** 单个会话节点。 */
export class SessionTreeItem extends vscode.TreeItem {
  constructor(public readonly meta: SessionListItem) {
    super(meta.title || "(未命名)", vscode.TreeItemCollapsibleState.None);
    this.id = meta.sessionId;
    this.description = this.fmtRelative(meta.updatedAt);
    this.tooltip = new vscode.MarkdownString(
      `**${meta.title || "(未命名)"}**\n\n` +
        `ID: \`${meta.sessionId.slice(0, 8)}\`\n\n` +
        `更新: ${new Date(meta.updatedAt).toLocaleString()}`
    );
    // 活跃会话实心蓝点，其余空心
    this.iconPath = meta.active
      ? new vscode.ThemeIcon("circle-filled", new vscode.ThemeColor("charts.blue"))
      : new vscode.ThemeIcon("circle-outline");
    this.contextValue = meta.active ? "activeSession" : "session";
    // 点击即切换（活跃会话再点为 no-op）
    this.command = {
      command: "flagent.session.switch",
      title: "切换到该会话",
      arguments: [meta.sessionId],
    };
  }

  /** 相对时间描述。 */
  private fmtRelative(ts: number): string {
    const diff = Date.now() - ts;
    const min = 60_000;
    const hour = 60 * min;
    const day = 24 * hour;
    if (diff < min) return "刚刚";
    if (diff < hour) return `${Math.floor(diff / min)}分钟前`;
    if (diff < day) return `${Math.floor(diff / hour)}小时前`;
    if (diff < 7 * day) return `${Math.floor(diff / day)}天前`;
    const d = new Date(ts);
    return `${d.getMonth() + 1}/${d.getDate()}`;
  }
}

/**
 * 会话树数据源。无子级（扁平列表）。
 * getManager 注入而非持引用，避免与 extension 初始化顺序耦合。
 */
export class SessionTreeProvider implements vscode.TreeDataProvider<SessionListItem> {
  private _onDidChange = new vscode.EventEmitter<SessionListItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChange.event;

  constructor(private getManager: () => SessionManager | undefined) {}

  refresh(): void {
    this._onDidChange.fire(undefined);
  }

  getTreeItem(element: SessionListItem): vscode.TreeItem {
    return new SessionTreeItem(element);
  }

  async getChildren(element?: SessionListItem): Promise<SessionListItem[]> {
    if (element) return []; // 扁平结构，无子节点
    const mgr = this.getManager();
    if (!mgr) return [];
    try {
      return await mgr.list();
    } catch {
      return [];
    }
  }
}
