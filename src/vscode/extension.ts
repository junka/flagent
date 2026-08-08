import * as vscode from "vscode";
import * as path from "path";
import * as os from "os";
import { createToolRegistry, setLLMConfig, getLLMConfig, type LLMConfig } from "..";
import { SessionManager, type SessionListItem } from "../session";
import { SessionTreeProvider } from "./session-tree-provider";

const ACTIVE_STATE_KEY = "flagent.activeSession";

export class FlagentExtension {
  private sessionManager: SessionManager | undefined;
  private treeProvider: SessionTreeProvider;
  private treeView: vscode.TreeView<SessionListItem> | undefined;
  private outputChannel: vscode.OutputChannel;
  private webviewPanel: vscode.WebviewPanel | undefined;
  private disposables: vscode.Disposable[] = [];
  private running = false;

  constructor(private context: vscode.ExtensionContext) {
    this.outputChannel = vscode.window.createOutputChannel("Flagent Multi-Agent");
    context.subscriptions.push(this.outputChannel);

    // ① 启动先从 VSCode 设置覆盖 LLM 配置（优先级 > 项目根 .env）
    this.applyConfigFromVSCode();

    this.initializeSessionManager();
    this.treeProvider = new SessionTreeProvider(() => this.sessionManager);
    this.registerCommands();
    this.setupTreeView();
    this.setupWebview();

    // ② 配置变更事件（用户改 settings.json 即时生效，无需重启窗口）
    const cfgSub = vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("flagent")) {
        this.applyConfigFromVSCode();
      }
    });
    this.context.subscriptions.push(cfgSub);

    // 异步恢复上次活动会话（不阻塞激活）
    this.restoreLastActive().then(() => this.refreshTree());

    const cfg = getLLMConfig();
    this.outputChannel.appendLine(
      `Flagent 扩展已激活  workspaceId=${cfg.workspaceId} model=${cfg.modelName} key=${cfg.apiKey ? "✓" : "✗"}`
    );
  }

  /** 构建 SessionManager：共享工具注册表 + VSCode 原生权限确认 + 工作区 .flagent/sessions。 */
  private initializeSessionManager(): void {
    const toolRegistry = createToolRegistry();
    const confirmFn = async (
      toolName: string,
      args: Record<string, any>
    ): Promise<boolean> => {
      const argStr = JSON.stringify(args).slice(0, 200);
      const choice = await vscode.window.showWarningMessage(
        `Flagent 权限请求: 工具 "${toolName}"\n参数: ${argStr}`,
        { modal: true },
        "允许（本会话记忆）",
        "拒绝"
      );
      return choice === "允许（本会话记忆）";
    };
    const ws = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    const base = ws ?? os.homedir();
    const storeDir = path.join(base, ".flagent", "sessions");
    this.sessionManager = new SessionManager({ toolRegistry, confirmFn, storeDir });
  }

  private setupTreeView(): void {
    this.treeView = vscode.window.createTreeView("flagent.sessions", {
      treeDataProvider: this.treeProvider,
      showCollapseAll: false,
    });
    this.disposables.push(this.treeView);
  }

  private registerCommands(): void {
    const reg = <T>(id: string, fn: (arg?: T) => any) => {
      const d = vscode.commands.registerCommand(id, fn);
      this.disposables.push(d);
    };

    reg<string | undefined>("flagent.session.new", () => this.newSession());
    reg<string | undefined>("flagent.session.switch", (id?: string) =>
      this.switchSession(id)
    );
    reg<string | undefined>("flagent.session.delete", (id?: string) =>
      this.deleteSession(id)
    );
    reg<string | undefined>("flagent.session.rename", (id?: string) =>
      this.renameSession(id)
    );
    reg("flagent.session.refresh", () => this.refreshTree());
    reg("flagent.chat", () => this.showChatInput());
    reg("flagent.showPanel", () => this.showWebviewPanel());
    reg("flagent.openWebview", () => this.showWebviewPanel());
    reg("flagent.analyzeSelection", () => this.analyzeSelectedCode());
    reg("flagent.clearContext", () => this.clearContext());
    reg("flagent.showStatus", () => this.showStatus());
    reg("flagent.reloadLLMConfig", () => this.reloadLLMConfig());

    for (const d of this.disposables) {
      this.context.subscriptions.push(d);
    }
  }

  private setupWebview(): void {
    // webview 按需在 showWebviewPanel 中创建
  }

  // ---------- 会话命令 ----------

  private async newSession(): Promise<void> {
    const mgr = this.requireManager();
    if (!mgr) return;
    const title = await vscode.window.showInputBox({
      prompt: "新会话标题（可留空，首问后自动命名）",
      placeHolder: "例如：web 第1题",
    });
    if (title === undefined) return; // 取消
    const session = await mgr.create(title.trim() || undefined);
    await this.setActive(session.id);
    vscode.window.showInformationMessage(
      `已新建会话：${session.title || "(未命名)"}`
    );
  }

  private async switchSession(argId?: string): Promise<void> {
    const mgr = this.requireManager();
    if (!mgr) return;
    const id = await this.resolveSessionId(argId, "选择要切换的会话");
    if (!id) return;
    await this.setActive(id);
    const cur = mgr.current();
    vscode.window.showInformationMessage(
      `已切换到会话：${cur?.title || "(未命名)"}`
    );
  }

  private async deleteSession(argId?: string): Promise<void> {
    const mgr = this.requireManager();
    if (!mgr) return;
    const id = await this.resolveSessionId(argId, "选择要删除的会话");
    if (!id) return;
    const list = await mgr.list();
    const target = list.find((m) => m.sessionId === id);
    const confirm = await vscode.window.showWarningMessage(
      `确认删除会话"${target?.title || "(未命名)"}"？此操作不可恢复。`,
      { modal: true },
      "删除"
    );
    if (confirm !== "删除") return;
    const wasActive = mgr.getActiveId() === id;
    await mgr.delete(id);
    if (wasActive) {
      const remaining = await mgr.list();
      if (remaining.length > 0) {
        await this.setActive(remaining[0].sessionId);
      } else {
        await this.context.workspaceState.update(ACTIVE_STATE_KEY, undefined);
        await this.refreshWebview();
      }
    }
    this.refreshTree();
  }

  private async renameSession(argId?: string): Promise<void> {
    const mgr = this.requireManager();
    if (!mgr) return;
    const id = argId ?? mgr.getActiveId();
    if (!id) {
      vscode.window.showInformationMessage("无活动会话");
      return;
    }
    const session = mgr.get(id);
    if (!session) {
      vscode.window.showWarningMessage(`会话不在内存，无法重命名: ${id.slice(0, 8)}`);
      return;
    }
    const title = await vscode.window.showInputBox({
      prompt: "新标题",
      value: session.title,
    });
    if (title === undefined) return; // 取消
    session.setTitle(title.trim());
    await mgr.persist(id);
    this.refreshTree();
    if (mgr.getActiveId() === id) await this.refreshWebview();
  }

  // ---------- 既有命令（改为作用于当前会话） ----------

  private async showChatInput(): Promise<void> {
    const mgr = this.requireManager();
    if (!mgr) return;
    const input = await vscode.window.showInputBox({
      prompt: "向 Flagent 多智能体系统提问",
      placeHolder: "输入你的问题...",
    });
    if (!input) return;
    await this.ensureApiKey();

    this.outputChannel.appendLine(`\n👤 用户: ${input}`);
    this.outputChannel.appendLine("🤖 正在处理...");
    try {
      const result = await mgr.run(input);
      await this.afterRun(mgr);
      this.outputChannel.appendLine(`\n✅ 回答: ${result.finalAnswer}`);
      this.outputChannel.appendLine(
        `📊 统计: ${result.steps.length}步, ${result.totalTokens}tokens, ${(result.duration / 1000).toFixed(1)}s`
      );
      vscode.window.showInformationMessage(
        `回答: ${result.finalAnswer.slice(0, 100)}${result.finalAnswer.length > 100 ? "..." : ""}`
      );
    } catch (error: any) {
      this.outputChannel.appendLine(`❌ 错误: ${error.message}`);
      vscode.window.showErrorMessage(`执行失败: ${error.message}`);
    }
  }

  private async analyzeSelectedCode(): Promise<void> {
    const mgr = this.requireManager();
    if (!mgr) return;
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showWarningMessage("请先打开一个文件");
      return;
    }
    const selectedText = editor.document.getText(editor.selection);
    if (!selectedText.trim()) {
      vscode.window.showWarningMessage("请先选择要分析的代码");
      return;
    }
    const task = `请分析以下代码并提供改进建议：\n\n${selectedText}`;
    await this.ensureApiKey();
    this.outputChannel.appendLine(`\n🔍 分析选中代码...`);
    try {
      const result = await mgr.run(task);
      await this.afterRun(mgr);
      this.outputChannel.appendLine(`\n📝 分析结果:\n${result.finalAnswer}`);
      const choice = await vscode.window.showInformationMessage(
        `分析完成: ${result.finalAnswer.slice(0, 60)}...`,
        "查看详情"
      );
      if (choice === "查看详情") this.outputChannel.show();
    } catch (error: any) {
      vscode.window.showErrorMessage(`分析失败: ${error.message}`);
    }
  }

  private async clearContext(): Promise<void> {
    const mgr = this.requireManager();
    if (!mgr) return;
    const session = mgr.current();
    if (!session) {
      vscode.window.showInformationMessage("无活动会话");
      return;
    }
    session.clearRuntime();
    await mgr.persistActive();
    this.refreshTree();
    await this.refreshWebview();
    vscode.window.showInformationMessage("当前会话的对话历史与权限记忆已清除");
  }

  private showStatus(): void {
    const mgr = this.sessionManager;
    if (!mgr) return;
    const session = mgr.current();
    if (!session) {
      this.outputChannel.appendLine("无活动会话");
      this.outputChannel.show();
      return;
    }
    const cm = session.getContextManager();
    const llm = getLLMConfig();
    const status = `
╔══════════════════════════════════════╗
║       Flagent 系统状态               ║
╠══════════════════════════════════════╣
║  会话: ${session.title || "(未命名)"} (${session.id.slice(0, 8)})
║  上下文消息数: ${cm.getMessages().length}
║  总 Token 数: ${cm.getTotalTokens()}
║  历史摘要: ${cm.getSummary() ? "已生成" : "无"}
║  已批准工具: ${session.getPermissionManager().getApproved().length}
╠══════════════════════════════════════╣
║  LLM workspace: ${llm.workspaceId}
║  LLM model:     ${llm.modelName}
║  LLM API Key:   ${llm.apiKey ? "✓ 已设置 (" + llm.apiKey.length + " 位)" : "✗ 未设置，请在设置 flagent.apiKey 中填写"}
╚══════════════════════════════════════╝
`;
    this.outputChannel.appendLine(status);
    this.outputChannel.show();
  }

  // ---------- webview（绑定当前会话） ----------

  private showWebviewPanel(): void {
    if (this.webviewPanel) {
      this.webviewPanel.reveal(vscode.ViewColumn.Beside, true);
      return;
    }
    this.webviewPanel = vscode.window.createWebviewPanel(
      "flagentChat",
      "Flagent 多智能体对话",
      vscode.ViewColumn.Beside,
      { enableScripts: true, retainContextWhenHidden: true }
    );
    this.webviewPanel.webview.html = this.getWebviewContent();
    this.webviewPanel.webview.onDidReceiveMessage(
      async (message) => {
        if (message.type !== "query") return;
        await this.handleWebviewQuery(message.content);
      },
      undefined,
      this.disposables
    );
    this.webviewPanel.onDidDispose(() => {
      this.webviewPanel = undefined;
    });
    this.refreshWebview();
  }

  private async handleWebviewQuery(content: string): Promise<void> {
    const mgr = this.requireManager();
    if (!mgr || this.running) return;
    await this.ensureApiKey();
    this.running = true;
    this.postToWebview({ type: "status", content: "正在思考..." });
    try {
      const result = await mgr.run(content);
      this.postToWebview({
        type: "response",
        content: result.finalAnswer,
        stats: {
          steps: result.steps.length,
          tokens: result.totalTokens,
          duration: result.duration,
          success: result.success,
        },
      });
      await this.afterRun(mgr);
    } catch (error: any) {
      this.postToWebview({ type: "error", content: error.message });
    } finally {
      this.running = false;
    }
  }

  /** run 后同步：记忆活动会话、刷新树与面板标题。 */
  private async afterRun(mgr: SessionManager): Promise<void> {
    const id = mgr.getActiveId();
    if (id) await this.context.workspaceState.update(ACTIVE_STATE_KEY, id);
    this.refreshTree();
    if (this.webviewPanel) {
      const cur = mgr.current();
      this.webviewPanel.title = cur
        ? `Flagent: ${cur.title || "(未命名)"}`
        : "Flagent 多智能体对话";
    }
  }

  /** 切到指定会话：内存有则切、无则 resume；记忆 activeId；刷新树与 webview。 */
  private async setActive(id: string): Promise<void> {
    const mgr = this.sessionManager;
    if (!mgr) return;
    await mgr.switch(id);
    await this.context.workspaceState.update(ACTIVE_STATE_KEY, id);
    this.refreshTree();
    await this.refreshWebview();
  }

  /** 把当前会话的消息历史推给 webview（切换/打开/清除时重建视图）。 */
  private async refreshWebview(): Promise<void> {
    if (!this.webviewPanel) return;
    const session = this.sessionManager?.current();
    this.webviewPanel.title = session
      ? `Flagent: ${session.title || "(未命名)"}`
      : "Flagent 多智能体对话";
    const messages = session ? session.getContextManager().getMessages() : [];
    this.postToWebview({
      type: "history",
      title: session?.title || "",
      messages: messages.map((m) => ({ role: m.role, content: m.content })),
    });
  }

  private postToWebview(msg: any): void {
    this.webviewPanel?.webview.postMessage(msg);
  }

  // ---------- 辅助 ----------

  private requireManager(): SessionManager | undefined {
    if (!this.sessionManager) {
      vscode.window.showErrorMessage("Flagent 会话管理器未初始化");
    }
    return this.sessionManager;
  }

  private refreshTree(): void {
    this.treeProvider.refresh();
  }

  /** 把命令入参（可能是全 id 或短前缀，或 undefined）解析为全 id；无入参则弹出选择。 */
  private async resolveSessionId(
    argId: string | undefined,
    placeHolder: string
  ): Promise<string | undefined> {
    const mgr = this.requireManager();
    if (!mgr) return undefined;
    const list = await mgr.list();
    if (list.length === 0) {
      vscode.window.showInformationMessage("暂无会话，请先新建");
      return undefined;
    }
    if (argId) {
      const match = list.find(
        (m) => m.sessionId === argId || m.sessionId.startsWith(argId)
      );
      if (!match) {
        vscode.window.showWarningMessage(`未找到会话: ${argId.slice(0, 8)}`);
      }
      return match?.sessionId;
    }
    const pick = await vscode.window.showQuickPick(
      list.map((m) => ({
        label: m.title || "(未命名)",
        description: m.sessionId.slice(0, 8),
        detail: new Date(m.updatedAt).toLocaleString(),
        id: m.sessionId,
      })),
      { placeHolder }
    );
    return pick?.id;
  }

  private async restoreLastActive(): Promise<void> {
    const mgr = this.sessionManager;
    if (!mgr) return;
    const lastId = this.context.workspaceState.get<string>(ACTIVE_STATE_KEY);
    if (!lastId) return;
    try {
      const list = await mgr.list();
      if (list.some((m) => m.sessionId === lastId)) {
        await mgr.resume(lastId);
      }
    } catch {
      // 静默：恢复失败不影响激活
    }
  }

  // ---------- LLM 配置接入 ----------

  /**
   * 从 VSCode 设置读取 flagent.apiKey / workspaceId / model，注入到 LLM 客户端。
   * 空字符串或未设置的字段不覆盖（保留 .env 中的默认值）。
   */
  private applyConfigFromVSCode(): LLMConfig {
    const cfg = vscode.workspace.getConfiguration("flagent");
    const apiKey = cfg.get<string>("apiKey")?.trim();
    const workspaceId = cfg.get<string>("workspaceId")?.trim();
    const modelName = cfg.get<string>("model")?.trim();
    return setLLMConfig({
      apiKey: apiKey ? apiKey : undefined,
      workspaceId: workspaceId ? workspaceId : undefined,
      modelName: modelName ? modelName : undefined,
    });
  }

  /** 显式重新加载 LLM 配置（命令触发），并提示当前生效值。 */
  private reloadLLMConfig(): void {
    const before = getLLMConfig();
    const after = this.applyConfigFromVSCode();
    const changed =
      before.apiKey !== after.apiKey ||
      before.workspaceId !== after.workspaceId ||
      before.modelName !== after.modelName ||
      before.baseUrl !== after.baseUrl;
    vscode.window.showInformationMessage(
      `Flagent LLM 配置${changed ? "已刷新" : "未变化"}：` +
        `workspaceId=${after.workspaceId}, model=${after.modelName}, key=${after.apiKey ? "✓已设置" : "✗未设置"}`
    );
    this.outputChannel.appendLine(
      `[config] ${changed ? "changed" : "unchanged"}  ws=${after.workspaceId} model=${after.modelName} keyLen=${after.apiKey.length}`
    );
  }

  /** 发起 LLM 调用前的 apiKey 校验：未配置时给用户跳转设置的入口。 */
  private async ensureApiKey(): Promise<boolean> {
    if (getLLMConfig().apiKey) return true;
    const choice = await vscode.window.showWarningMessage(
      "尚未配置 Flagent 的 DashScope API Key，LLM 调用会失败。是否前往设置？",
      "打开设置",
      "忽略本次"
    );
    if (choice === "打开设置") {
      await vscode.commands.executeCommand(
        "workbench.action.openSettings",
        "flagent.apiKey"
      );
    }
    // 用户选忽略也放行，让后续调用自然返回 401 以便排查
    return true;
  }

  private getWebviewContent(): string {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Flagent 多智能体对话</title>
<style>
  body { font-family: var(--vscode-editor-font-family, monospace); padding: 12px; color: var(--vscode-editor-foreground); background: var(--vscode-editor-background); margin: 0; }
  .chat-container { display: flex; flex-direction: column; height: calc(100vh - 96px); }
  .header { font-size: 0.85em; color: var(--vscode-descriptionForeground); padding: 4px 6px 8px; border-bottom: 1px solid var(--vscode-editorWidget-border); margin-bottom: 8px; }
  .messages { flex: 1; overflow-y: auto; padding: 4px; }
  .message { margin-bottom: 10px; padding: 9px 11px; border-radius: 6px; max-width: 88%; word-wrap: break-word; white-space: pre-wrap; line-height: 1.45; }
  .message.user { background: var(--vscode-textBlockQuote-background); margin-left: auto; }
  .message.assistant { background: var(--vscode-editor-inactiveSelectionBackground); }
  .message.system { background: var(--vscode-editorWidget-background); font-size: 0.9em; color: var(--vscode-descriptionForeground); }
  .input-area { display: flex; gap: 8px; padding: 8px 0 0; }
  textarea { flex: 1; min-height: 56px; padding: 8px; border-radius: 6px; border: 1px solid var(--vscode-editorWidget-border); background: var(--vscode-editorWidget-background); color: var(--vscode-editor-foreground); font-family: inherit; font-size: inherit; resize: vertical; }
  button { padding: 8px 16px; border-radius: 6px; border: none; background: var(--vscode-button-background); color: var(--vscode-button-foreground); cursor: pointer; }
  button:disabled { opacity: 0.5; cursor: default; }
  button:hover:not(:disabled) { background: var(--vscode-button-hoverBackground); }
  .stats { font-size: 0.8em; color: var(--vscode-descriptionForeground); margin: 4px 0 10px; padding-top: 6px; border-top: 1px dashed var(--vscode-editorWidget-border); }
  .loading { display: inline-block; animation: pulse 1.5s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
</style>
</head>
<body>
<div class="chat-container">
  <div class="header" id="header">Flagent 多智能体系统</div>
  <div class="messages" id="messages"></div>
  <div class="input-area">
    <textarea id="input" placeholder="输入你的问题... (Enter 发送, Shift+Enter 换行)"></textarea>
    <button id="sendBtn">发送</button>
  </div>
</div>
<script>
  const messagesDiv = document.getElementById('messages');
  const input = document.getElementById('input');
  const sendBtn = document.getElementById('sendBtn');
  const header = document.getElementById('header');
  let thinkingEl = null;

  function addMessage(text, type) {
    const div = document.createElement('div');
    div.className = 'message ' + type;
    div.textContent = text;
    messagesDiv.appendChild(div);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
    return div;
  }
  function clearThinking() { if (thinkingEl) { thinkingEl.remove(); thinkingEl = null; } }
  function showThinking(text) {
    clearThinking();
    thinkingEl = addMessage(text + ' \\u27f3', 'system');
    thinkingEl.innerHTML = text + ' <span class="loading">\\u27f3</span>';
  }
  function renderHistory(messages, title) {
    messagesDiv.innerHTML = '';
    thinkingEl = null;
    header.textContent = title ? ('会话：' + title) : 'Flagent 多智能体系统';
    if (!messages || messages.length === 0) {
      addMessage('Flagent 多智能体系统已就绪。输入问题开始对话，或在侧边栏切换/新建会话。', 'system');
      return;
    }
    for (const m of messages) {
      const type = m.role === 'user' ? 'user' : (m.role === 'assistant' ? 'assistant' : 'system');
      addMessage(m.content, type);
    }
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
  }
  function sendQuery() {
    const text = input.value.trim();
    if (!text) return;
    addMessage(text, 'user');
    input.value = '';
    showThinking('正在思考...');
    sendBtn.disabled = true;
    vscode.postMessage({ type: 'query', content: text });
  }
  sendBtn.addEventListener('click', sendQuery);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendQuery(); }
  });
  window.addEventListener('message', (event) => {
    const message = event.data;
    if (message.type === 'history') {
      renderHistory(message.messages, message.title);
    } else if (message.type === 'status') {
      showThinking(message.content);
    } else if (message.type === 'response') {
      clearThinking();
      sendBtn.disabled = false;
      addMessage(message.content, 'assistant');
      if (message.stats) {
        const s = document.createElement('div');
        s.className = 'stats';
        s.textContent = '步骤: ' + message.stats.steps + ' | Tokens: ' + message.stats.tokens + ' | 耗时: ' + (message.stats.duration/1000).toFixed(1) + 's | ' + (message.stats.success ? '✓ 成功' : '✗ 未完成');
        messagesDiv.appendChild(s);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
      }
    } else if (message.type === 'error') {
      clearThinking();
      sendBtn.disabled = false;
      addMessage('错误: ' + message.content, 'system');
    }
  });
  renderHistory([], '');
</script>
</body>
</html>`;
  }

  dispose(): void {
    for (const d of this.disposables) d.dispose();
    this.disposables = [];
  }
}

let extensionInstance: FlagentExtension | undefined;

export function activate(context: vscode.ExtensionContext): void {
  extensionInstance = new FlagentExtension(context);
}

export function deactivate(): void {
  if (extensionInstance) {
    extensionInstance.dispose();
    extensionInstance = undefined;
  }
}
