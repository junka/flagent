import { SubAgent } from "./sub-agent";
import { ToolRegistry } from "../tools/registry";
import { ToolExecutor } from "./tool-executor";
import { ContextManager } from "../context/context-manager";
import { generateText, tool } from "ai";
import { z } from "zod";
import { model } from "../llm/client";

export interface SchedulerDecision {
  agentId: string;
  task: string;
  reason: string;
}

export interface DispatchRequest {
  agentId: string;
  task: string;
}

export interface DispatchResult {
  agentId: string;
  task: string;
  result: string;
  success: boolean;
}

/**
 * 动态 SubAgent 注册配置（决策四：给"不落进 5 类预设的新题"留口子）。
 * MainAgent 基于自身分类结论，按需 spawn 一个通用深挖 agent。
 * toolNames 会过滤到注册表内已有工具；空集则拒绝注册。
 */
export interface DynamicAgentConfig {
  id: string;
  name: string;
  role: string;
  systemPrompt: string;
  toolNames: string[];
  maxSteps?: number;
}

export class Scheduler {
  private agents: Map<string, SubAgent> = new Map();
  private toolRegistry: ToolRegistry;
  private toolExecutor?: ToolExecutor;
  private dynamicConfigs: Map<string, DynamicAgentConfig> = new Map();
  private routingHistory: Array<{
    task: string;
    agentId: string;
    decision: string;
    timestamp: number;
  }> = [];

  constructor(toolRegistry: ToolRegistry, toolExecutor?: ToolExecutor) {
    this.toolRegistry = toolRegistry;
    this.toolExecutor = toolExecutor;
  }

  registerAgent(agent: SubAgent): void {
    this.agents.set(agent.id, agent);
  }

  unregisterAgent(id: string): void {
    this.agents.delete(id);
  }

  getAgent(id: string): SubAgent | undefined {
    return this.agents.get(id);
  }

  getAllAgents(): SubAgent[] {
    return Array.from(this.agents.values());
  }

  /** 工具注册表（阶段7 registerDynamicAgent 构造动态 SubAgent 时使用） */
  getToolRegistry(): ToolRegistry {
    return this.toolRegistry;
  }

  /**
   * 动态注册一个 generic SubAgent（决策四）。
   * - id 唯一性校验（冲突抛错）
   * - toolNames 过滤到注册表内已有工具；全部未知则拒绝（避免空壳 agent）
   * - 独立 ContextManager（context 隔离），共享 toolExecutor（统一权限/并发策略）
   * 注册后即可纳入 dispatchConcurrent / DELEGATE。返回 agentId。
   */
  registerDynamicAgent(config: DynamicAgentConfig): string {
    if (this.agents.has(config.id)) {
      throw new Error(`动态注册失败：agentId "${config.id}" 已存在`);
    }
    if (!Array.isArray(config.toolNames) || config.toolNames.length === 0) {
      throw new Error(
        `动态注册失败：agentId "${config.id}" 未指定 toolNames`
      );
    }
    const known = new Set(this.toolRegistry.getNames());
    const validTools = config.toolNames.filter((n) => known.has(n));
    if (validTools.length === 0) {
      throw new Error(
        `动态注册失败：agentId "${config.id}" 的 toolNames 均不在注册表中: ${config.toolNames.join(", ")}`
      );
    }

    // 归一化 config：既用于构造 SubAgent，又存入侧表供会话序列化
    const normalized: DynamicAgentConfig = {
      id: config.id,
      name: config.name || config.id,
      role: config.role || config.name || config.id,
      systemPrompt: config.systemPrompt || "",
      toolNames: validTools,
      maxSteps: config.maxSteps ?? 8,
    };

    const agent = new SubAgent(
      {
        id: normalized.id,
        name: normalized.name,
        role: normalized.role,
        systemPrompt: normalized.systemPrompt,
        toolNames: normalized.toolNames,
        // 动态 agent 独立 context，避免污染主上下文；与预设 agent 一致
        contextManager: new ContextManager(),
        // 共享 toolExecutor：统一权限确认与并发限流
        toolExecutor: this.toolExecutor,
        maxSteps: normalized.maxSteps,
      },
      this.toolRegistry
    );
    this.agents.set(agent.id, agent);
    this.dynamicConfigs.set(agent.id, normalized);
    return agent.id;
  }

  /** 注销动态 agent（任务完成后清理，避免 agent map 膨胀）。预设 agent 也可注销。 */
  unregisterDynamicAgent(id: string): boolean {
    this.dynamicConfigs.delete(id);
    return this.agents.delete(id);
  }

  /** 当前已注册的动态 agent 配置（用于会话序列化；预设 agent 不在列表）。 */
  getDynamicAgentConfigs(): DynamicAgentConfig[] {
    return Array.from(this.dynamicConfigs.values());
  }

  async route(task: string): Promise<{ agent: SubAgent; decision: SchedulerDecision }> {
    const agents = this.getAllAgents();
    if (agents.length === 0) {
      throw new Error("No sub-agents registered");
    }

    if (agents.length === 1) {
      return {
        agent: agents[0],
        decision: {
          agentId: agents[0].id,
          task,
          reason: "单智能体模式，直接路由",
        },
      };
    }

    const agentList = agents
      .map(
        (a) =>
          `- ${a.id} (${a.name}): 角色=${a.role}, 可用工具=${a.toolNames.join(", ")}, 提示词=${a.systemPrompt.slice(0, 100)}...`
      )
      .join("\n");

    const routingHistoryText = this.routingHistory
      .slice(-5)
      .map((h) => `- 任务"${h.task.slice(0, 50)}..." → ${h.agentId} (原因: ${h.decision})`)
      .join("\n");

    // 用 tool_use 取代文本协议的 AGENT_ID/REASON 解析
    let decision: SchedulerDecision;
    try {
      const selectDef: any = {
        description: "选择一个子智能体执行任务",
        parameters: z.object({
          agentId: z.string().describe("选择的子智能体 id"),
          reason: z.string().describe("选择原因"),
        }),
        execute: async (args: { agentId: string; reason: string }) => {
          return `已选择 ${args.agentId}: ${args.reason}`;
        },
      };
      const result = await generateText({
        model,
        system: `你是一个智能体调度器。根据任务描述，调用 select_agent 工具选择最合适的子智能体来执行。\n\n可用子智能体列表：\n${agentList}\n\n调度历史（最近5条）：\n${routingHistoryText || "（无）"}\n\n当前任务：${task}`,
        messages: [{ role: "user", content: task }],
        tools: { select_agent: tool(selectDef) },
        toolChoice: "required",
      });
      const call = (result.toolCalls[0] as any) || undefined;
      const args: any = call?.args || {};
      decision = {
        agentId: args.agentId || agents[0].id,
        task,
        reason: args.reason || "无说明",
      };
    } catch {
      decision = {
        agentId: agents[0].id,
        task,
        reason: "调度失败，回退到默认智能体",
      };
    }

    this.routingHistory.push({
      task,
      agentId: decision.agentId,
      decision: decision.reason,
      timestamp: Date.now(),
    });

    const agent = this.agents.get(decision.agentId);
    if (!agent) {
      return {
        agent: agents[0],
        decision: {
          agentId: agents[0].id,
          task,
          reason: `调度失败，回退到默认智能体: ${decision.reason}`,
        },
      };
    }

    return { agent, decision };
  }

  async dispatch(task: string): Promise<{ agentId: string; result: string; decision: string }> {
    const { agent, decision } = await this.route(task);
    const result = await agent.run(task);
    return {
      agentId: agent.id,
      result,
      decision: decision.reason,
    };
  }

  /**
   * 并发委派多个子智能体：MainAgent 一次 DELEGATE 多个 agent 时使用。
   * 各 agent 各自独立 context，互不干扰；未找到的 agent 标记失败，不影响其他。
   * 注意：此处并发度等于请求数，LLM 限流/429 退避重试属阶段7待加项。
   */
  async dispatchConcurrent(
    requests: DispatchRequest[]
  ): Promise<DispatchResult[]> {
    return Promise.all(
      requests.map(async (req) => {
        const agent = this.agents.get(req.agentId);
        if (!agent) {
          return {
            agentId: req.agentId,
            task: req.task,
            result: `[子智能体未找到] ${req.agentId}`,
            success: false,
          };
        }
        try {
          const result = await agent.run(req.task);
          return { agentId: req.agentId, task: req.task, result, success: true };
        } catch (err: any) {
          return {
            agentId: req.agentId,
            task: req.task,
            result: `[子智能体执行失败] ${err.message}`,
            success: false,
          };
        }
      })
    );
  }
}