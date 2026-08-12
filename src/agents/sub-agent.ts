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
  /** 允许灵活调用的跨类工具白名单：不参与 prompt 中工具主清单的重点推荐，
   *  但实际执行时放行；用于常见联动（如 web→数据库、pwn→linux 提权）。
   */
  crossCategoryToolNames?: string[];
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
  public crossCategoryToolNames: string[];
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
    this.crossCategoryToolNames = config.crossCategoryToolNames ?? [];
    this.contextManager = config.contextManager;
    this.toolRegistry = toolRegistry;
    this.toolExecutor = config.toolExecutor;
    this.maxSteps = config.maxSteps ?? 8;
  }

  /** 本 agent 实际允许调用的工具全集（主工具 + 跨类白名单并集） */
  getAllowedToolNames(): string[] {
    const set = new Set([...this.toolNames, ...this.crossCategoryToolNames]);
    return Array.from(set);
  }

  /** 某工具是否属于跨类白名单（仅白名单且不在主工具内） */
  private isCrossCategory(name: string): boolean {
    return !this.toolNames.includes(name) && this.crossCategoryToolNames.includes(name);
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

  /** 仅允许调用本专家工具集内的工具（主清单 + 跨类白名单）；越权拒绝并给出委派建议 */
  private async executeScoped(
    toolName: string,
    toolArgs: Record<string, any>
  ): Promise<string> {
    const allowed = this.getAllowedToolNames();
    if (!allowed.includes(toolName)) {
      return [
        `[工具越权] ${toolName} 不在本专家工具集内。`,
        `主工具可用: ${this.toolNames.join(", ")}`,
        this.crossCategoryToolNames.length ? `跨类放行（请优先选择合适的 peer agent）：${this.crossCategoryToolNames.join(", ")}` : ``,
        `提示：如该问题明显属于另一类题型，请通过 MainAgent DELEGATE 委派给更合适的 peer agent（web/pwn/reverse/crypto/misc/forensics/mobile/blockchain/osint/cloud/iot/aiml/linux?database）。`,
      ].filter(Boolean).join("\n");
    }
    const crossHint = this.isCrossCategory(toolName)
      ? ` [⚠️ 跨类工具调用：${this.name} 为 ${this.role}，若非核心任务请下次委派更合适的 peer agent]`
      : "";
    if (this.toolExecutor) {
      const [r] = await this.toolExecutor.executeBatch([{ toolName, toolArgs }]);
      return crossHint + r.result;
    }
    try {
      return crossHint + (await this.toolRegistry.execute(toolName, toolArgs));
    } catch (err: any) {
      return crossHint + `工具执行失败: ${err.message}`;
    }
  }

  private buildPrompt(task: string, step: number): string {
    const tools = this.toolNames
      .map((n) => this.toolRegistry.get(n))
      .filter(Boolean);
    const toolsDescription = tools
      .map((t) => `- ${t!.name}: ${t!.description}`)
      .join("\n");
    const crossDesc = this.crossCategoryToolNames
      .map((n) => this.toolRegistry.get(n))
      .filter(Boolean)
      .map(
        (t) =>
          `  ⚠️ [跨类] ${t!.name}: ${t!.description}（非必要不调用，请优先委派对应的 peer agent）`
      )
      .join("\n");
    const messages = this.contextManager.getActiveMessages();
    const historyText = messages
      .map((m) => `${m.role}: ${m.content}`)
      .join("\n");
    const summary = this.contextManager.getSummary();
    const summaryText = summary ? `\n\n历史摘要：\n${summary}` : "";
    const crossBlock = crossDesc
      ? `\n跨类可选工具（灵活调用但请优先委派 peer agent，避免任务跑偏）：\n${crossDesc}\n`
      : "";

    return `${this.systemPrompt}

你是一个${this.role}。请按照 ReAct（思考-行动-观察）模式工作，每一步只调用一个工具。

步骤 ${step}/${this.maxSteps}

当前任务：${task}

可用工具：
${toolsDescription}
${crossBlock}
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
- 优先使用上方 "可用工具"（本专家专属）；只有当跨类工具与任务强相关时才调用
- 如果题目主要属于另一 CTF 题型，返回 FINAL_ANSWER 并在结论中明确建议 MainAgent 委派给合适的 peer agent
- 参数 JSON 必须合法`;
  }

  getContext(): ContextManager {
    return this.contextManager;
  }
}
