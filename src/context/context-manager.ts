import { generateText } from "ai";
import { model } from "../llm/client";

export interface Message {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  timestamp: number;
  tokenCount: number;
}

export interface ContextConfig {
  maxContextTokens: number;
  summaryThresholdTokens: number;
  windowMessages: number;
  summarySystemPrompt: string;
}

const DEFAULT_CONFIG: ContextConfig = {
  maxContextTokens: 8000,
  summaryThresholdTokens: 4000,
  windowMessages: 10,
  summarySystemPrompt:
    "你是一个专业的对话摘要助手。请将以下对话历史压缩为简洁的摘要，保留关键信息、决策和事实。用第三人称叙述，不超过300字。",
};

export class ContextManager {
  private messages: Message[] = [];
  private config: ContextConfig;
  private summary: string = "";
  private writeLock: Promise<void> = Promise.resolve();

  constructor(config: Partial<ContextConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  async addMessage(message: Omit<Message, "timestamp" | "tokenCount">): Promise<void> {
    return this.runLocked(async () => {
      this.messages.push({
        ...message,
        timestamp: Date.now(),
        tokenCount: this.estimateTokens(message.content),
      });
      await this.checkAndSummarize();
    });
  }

  async addMessagesBatch(messages: Array<Omit<Message, "timestamp" | "tokenCount">>): Promise<void> {
    return this.runLocked(async () => {
      for (const m of messages) {
        this.messages.push({
          ...m,
          timestamp: Date.now(),
          tokenCount: this.estimateTokens(m.content),
        });
      }
      await this.checkAndSummarize();
    });
  }

  getMessages(): Message[] {
    return [...this.messages];
  }

  getSummary(): string {
    return this.summary;
  }

  getActiveMessages(): Message[] {
    if (this.messages.length <= this.config.windowMessages) {
      return [...this.messages];
    }
    return this.messages.slice(-this.config.windowMessages);
  }

  getTotalTokens(): number {
    return this.messages.reduce((sum, m) => sum + m.tokenCount, 0);
  }

  clear(): void {
    this.messages = [];
    this.summary = "";
  }

  /**
   * 批量恢复消息与摘要（会话重载时用）。同步、不走 writeLock、不触发 checkAndSummarize。
   * 调用时机：会话加载阶段，早于任何并发 addMessage。tokenCount 用 estimateTokens 重算；
   * timestamp 不保留（跨重启无意义），设为 Date.now()。
   */
  restoreMessages(
    messages: Array<{ role: Message["role"]; content: string }>,
    summary?: string
  ): void {
    this.messages = messages.map((m) => ({
      role: m.role,
      content: m.content,
      timestamp: Date.now(),
      tokenCount: this.estimateTokens(m.content),
    }));
    this.summary = summary ?? "";
  }

  /**
   * 手动触发摘要（/summarize 命令）：将窗口外的消息摘要后截断，返回当前摘要。
   * 全部消息都在窗口内时无需摘要，返回已有摘要（可能为空）。
   * 与自动 checkAndSummarize 共用 summarizeMessages，串行化于 writeLock。
   */
  async summarizeNow(): Promise<string> {
    return this.runLocked(async () => {
      if (this.messages.length > this.config.windowMessages) {
        const nonWindow = this.messages.slice(
          0,
          this.messages.length - this.config.windowMessages
        );
        await this.summarizeMessages(nonWindow);
        this.messages = this.messages.slice(-this.config.windowMessages);
      }
      return this.summary;
    });
  }

  private runLocked<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.writeLock.then(fn, fn);
    this.writeLock = next.then(() => undefined, () => undefined);
    return next;
  }

  private estimateTokens(text: string): number {
    return Math.ceil(text.length / 4);
  }

  private async checkAndSummarize(): Promise<void> {
    const totalTokens = this.getTotalTokens();
    if (totalTokens > this.config.summaryThresholdTokens) {
      const nonWindowMessages = this.messages.slice(
        0,
        this.messages.length - this.config.windowMessages
      );
      if (nonWindowMessages.length > 0) {
        await this.summarizeMessages(nonWindowMessages);
        this.messages = this.messages.slice(-this.config.windowMessages);
      }
    }
  }

  private async summarizeMessages(messages: Message[]): Promise<void> {
    const conversationText = messages
      .map((m) => {
        const roleMap: Record<string, string> = {
          system: "系统",
          user: "用户",
          assistant: "助手",
          tool: "工具",
        };
        return `${roleMap[m.role] || m.role}: ${m.content}`;
      })
      .join("\n");

    const prompt = `${this.config.summarySystemPrompt}\n\n对话历史：\n${conversationText}\n\n已有摘要：\n${this.summary || "（无）"}\n\n请生成新的合并摘要：`;

    try {
      const { text } = await generateText({
        model,
        prompt,
      });
      this.summary = this.summary
        ? `${this.summary}\n---\n${text}`
        : text;
    } catch (error) {
      console.error("[ContextManager] 摘要生成失败:", error);
    }
  }
}