import { ContextManager } from "../context/context-manager";
import { ToolRegistry } from "../tools/registry";
import { ToolExecutor } from "./tool-executor";
import { parseReactResponse, parseToolCallLine } from "./react-parser";
import { generateText } from "ai";
import { model } from "../llm/client";

export interface SubAgentConfig {
  id: string;
  name: string;
  role: string;
  systemPrompt: string;
  toolNames: string[];
  contextManager: ContextManager;
  toolExecutor?: ToolExecutor;
  maxSteps?: number;
}

export class SubAgent {
  public id: string;
  public name: string;
  public role: string;
  public systemPrompt: string;
  public toolNames: string[];
  private contextManager: ContextManager;
  private toolRegistry: ToolRegistry;
  private toolExecutor?: ToolExecutor;
  private maxSteps: number;

  constructor(config: SubAgentConfig, toolRegistry: ToolRegistry) {
    this.id = config.id;
    this.name = config.name;
    this.role = config.role;
    this.systemPrompt = config.systemPrompt;
    this.toolNames = config.toolNames;
    this.contextManager = config.contextManager;
    this.toolRegistry = toolRegistry;
    this.toolExecutor = config.toolExecutor;
    this.maxSteps = config.maxSteps ?? 8;
  }

  /**
   * 真实 ReAct 循环：思考→行动→观察，直至 FINAL_ANSWER 或达到 maxSteps。
   * 子 agent 仅支持单工具 ACTION（并发采集交给 MainAgent 统一调度）。
   * 使用自身独立 context，无共享竞态。
   */
  async run(task: string): Promise<string> {
    await this.contextManager.addMessage({ role: "user", content: task });

    let lastObservation = "";

    for (let step = 1; step <= this.maxSteps; step++) {
      const prompt = this.buildPrompt(task, step);
      const { text } = await generateText({ model, prompt });
      const { thought, action, finalAnswer } = parseReactResponse(text);

      if (finalAnswer) {
        await this.contextManager.addMessage({
          role: "assistant",
          content: finalAnswer,
        });
        return finalAnswer;
      }

      if (action) {
        const { toolName, toolArgs } = parseToolCallLine(action);
        if (toolName) {
          const obs = await this.executeScoped(toolName, toolArgs);
          lastObservation = obs;
          await this.contextManager.addMessage({
            role: "tool",
            content: `[${toolName}] ${JSON.stringify(toolArgs)} → ${obs}`,
          });
          continue;
        }
      }

      // NO_ACTION：记录思考继续下一步
      lastObservation = thought || "(无有效输出)";
      await this.contextManager.addMessage({
        role: "assistant",
        content: thought || "(无有效输出)",
      });
    }

    // 超步：返回最后观察
    return lastObservation || "子智能体达到最大步数，未能给出最终答案。";
  }

  /** 仅允许调用本专家工具集内的工具（工具越权直接拒绝，不执行） */
  private async executeScoped(
    toolName: string,
    toolArgs: Record<string, any>
  ): Promise<string> {
    if (!this.toolNames.includes(toolName)) {
      return `[工具越权] ${toolName} 不在本专家工具集内，可用: ${this.toolNames.join(", ")}`;
    }
    if (this.toolExecutor) {
      const [r] = await this.toolExecutor.executeBatch([{ toolName, toolArgs }]);
      return r.result;
    }
    try {
      return await this.toolRegistry.execute(toolName, toolArgs);
    } catch (err: any) {
      return `工具执行失败: ${err.message}`;
    }
  }

  private buildPrompt(task: string, step: number): string {
    const tools = this.toolNames
      .map((n) => this.toolRegistry.get(n))
      .filter(Boolean);
    const toolsDescription = tools
      .map((t) => `- ${t!.name}: ${t!.description}`)
      .join("\n");
    const messages = this.contextManager.getActiveMessages();
    const historyText = messages
      .map((m) => `${m.role}: ${m.content}`)
      .join("\n");
    const summary = this.contextManager.getSummary();
    const summaryText = summary ? `\n\n历史摘要：\n${summary}` : "";

    return `${this.systemPrompt}

你是一个${this.role}。请按照 ReAct（思考-行动-观察）模式工作，每一步只调用一个工具。

步骤 ${step}/${this.maxSteps}

当前任务：${task}

可用工具：
${toolsDescription}

对话历史：
${historyText}
${summaryText}

请严格按照以下格式输出（只输出一段）：
THOUGHT: [分析当前进展，决定下一步]
ACTION: <工具名>({...参数JSON...})
  或
FINAL_ANSWER: [任务完成或无需工具时的最终结论]

注意：
- ACTION 行格式必须为 工具名(JSON参数)，例如 http_request({"url":"http://example.com"})
- 仅使用上方列出的工具
- 参数 JSON 必须合法`;
  }

  getContext(): ContextManager {
    return this.contextManager;
  }
}
