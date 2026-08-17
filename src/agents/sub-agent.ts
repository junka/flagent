import { ContextManager } from "../context/context-manager";
import { ToolRegistry } from "../tools/registry";
import { ToolExecutor } from "./tool-executor";
import { generateText, hasToolCall, isStepCount, type ModelMessage, tool } from "ai";
import { z } from "zod";
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

  /**
   * tool_use 循环：generateText + tools + stopWhen。SDK 自动驱动
   * 思考→工具调用→观察→再思考，直到 final_answer 或达到 maxSteps。
   * 子 agent 用自身独立 context，无共享竞态。
   */
  async run(task: string): Promise<string> {
    await this.contextManager.addMessage({ role: "user", content: task });

    // 组装 system prompt（工具由 SDK 发 schema，不再拼工具描述）
    const crossDesc = this.crossCategoryToolNames.length
      ? `\n跨类可选工具（灵活调用但请优先委派 peer agent，避免任务跑偏）：${this.crossCategoryToolNames.join(", ")}\n`
      : "";
    const system = `${this.systemPrompt}

你是一个${this.role}。按 ReAct（思考-行动-观察）模式工作，调用工具获取信息后继续推理，直到任务完成调用 final_answer 交卷。
${crossDesc}
注意：
- 优先使用本专家专属工具；只有当跨类工具与任务强相关时才调用
- 如果题目主要属于另一 CTF 题型，调用 final_answer 并在结论中明确建议 MainAgent 委派给合适的 peer agent`;

    // 组装 messages
    const history = this.contextManager.getActiveMessages();
    const summary = this.contextManager.getSummary();
    const messages: ModelMessage[] = [];
    if (summary) messages.push({ role: "system", content: `历史摘要：\n${summary}` });
    for (const m of history) {
      if (m.role === "system") messages.push({ role: "system", content: m.content });
      else if (m.role === "user") messages.push({ role: "user", content: m.content });
      else if (m.role === "assistant") messages.push({ role: "assistant", content: m.content });
    }

    // 组装 tools：本专家工具集（含越权隔离）
    const allowed = this.getAllowedToolNames();
    const toolExecutor = this.toolExecutor;
    const execFn = async (action: {
      toolName: string;
      toolArgs: Record<string, any>;
    }): Promise<string> => {
      if (!allowed.includes(action.toolName)) {
        return [
          `[工具越权] ${action.toolName} 不在本专家工具集内。`,
          `主工具可用: ${this.toolNames.join(", ")}`,
          this.crossCategoryToolNames.length
            ? `跨类放行：${this.crossCategoryToolNames.join(", ")}`
            : ``,
          `提示：如该问题明显属于另一类题型，请通过 final_answer 返回结论并建议 MainAgent 委派给更合适的 peer agent。`,
        ].filter(Boolean).join("\n");
      }
      const crossHint = this.isCrossCategory(action.toolName)
        ? ` [⚠️ 跨类工具调用：${this.name} 为 ${this.role}，若非核心任务请下次委派更合适的 peer agent]`
        : "";
      if (toolExecutor) {
        const r = await toolExecutor.executeOne(action);
        return crossHint + r.result;
      }
      try {
        return crossHint + (await this.toolRegistry.execute(action.toolName, action.toolArgs));
      } catch (err: any) {
        return crossHint + `工具执行失败: ${err.message}`;
      }
    };
    const registryTools = this.toolRegistry.toAISDKTools(execFn, allowed);

    // 子 agent 专用 final_answer（无 CTF 校验，直接结束）
    let subFinalAnswer = "";
    const finalAnswerDef: any = {
      description: "提交子任务的最终结论并结束。若题目属于另一题型，在结论中说明并建议委派 peer agent。",
      parameters: z.object({
        answer: z.string().describe("子任务最终结论"),
      }),
      execute: async (args: { answer: string }) => {
        subFinalAnswer = args.answer;
        return `[子任务完成] ${args.answer}`;
      },
    };
    const allTools = { ...registryTools, final_answer: tool(finalAnswerDef) };

    try {
      const result = await generateText({
        model,
        system,
        messages,
        tools: allTools,
        stopWhen: [hasToolCall("final_answer"), isStepCount(this.maxSteps)],
      });

      // 优先从 final_answer toolCall 取（AI SDK v7 用 input，非 args）
      const finalCall = result.toolCalls.find(
        (tc: any) => tc.toolName === "final_answer",
      );
      const answer =
        (finalCall && (finalCall as any).input?.answer) ||
        subFinalAnswer ||
        result.text ||
        "子智能体达到最大步数，未能给出最终答案。";

      await this.contextManager.addMessage({ role: "assistant", content: answer });
      return answer;
    } catch (err: any) {
      const msg = `子智能体执行失败: ${err.message}`;
      await this.contextManager.addMessage({ role: "assistant", content: msg });
      return msg;
    }
  }

  /** 某工具是否属于跨类白名单（仅白名单且不在主工具内） */
  private isCrossCategory(name: string): boolean {
    return !this.toolNames.includes(name) && this.crossCategoryToolNames.includes(name);
  }

  getContext(): ContextManager {
    return this.contextManager;
  }
}
