// 内置控制工具：用原生 tool_use 协议取代文本协议的 FINAL_ANSWER/DELEGATE/SPAWN_AGENT 标记。
// 模型通过结构化 tool_call 调用这些工具，而非输出文本标记由 react-parser 解析。
//
// - final_answer(answer): 提交最终答案，经 CTF flag 校验门控；通过则结束循环（stopWhen）
// - delegate(agentId, task): 委派任务给指定子智能体
// - spawn_agent(id, role, toolNames): 动态注册通用深挖子智能体

import { z } from "zod";
import { tool, type ToolSet } from "ai";
import type { Scheduler } from "./scheduler";
import type { ToolExecutor } from "./tool-executor";

/** CTF flag 校验器签名（由 MainAgent 注入，复用 validateCTFFinalAnswer）。 */
export type FinalAnswerValidator = (answer: string) => {
  ok: boolean;
  reason: string;
  hint: string;
};

export interface BuiltinToolDeps {
  scheduler: Scheduler;
  toolExecutor: ToolExecutor;
  /** 委派时是否需要用户确认（多步骤 Plan 门控复用）。返回 false 则不执行委派。 */
  confirmDelegate?: (agentId: string, task: string) => Promise<boolean>;
}

/**
 * 构造内置控制工具集。final_answer 的"完成"信号通过返回值约定：
 * execute 返回字符串供模型继续推理；真正的"结束"由 MainAgent 在
 * stopWhen=hasToolCall("final_answer") + 校验通过后判定。
 *
 * @param deps        依赖（scheduler/toolExecutor/confirmDelegate）
 * @param validator   final_answer 的 CTF 校验器（由 MainAgent 注入）
 * @param emit        事件发射回调（delegateStart/End, spawnAgent, finalAnswer）
 */
export function createBuiltinTools(
  deps: BuiltinToolDeps,
  validator: FinalAnswerValidator,
  emit: (event: import("./agent-events").AgentEvent) => void,
  step: number,
): ToolSet {
  const { scheduler, toolExecutor, confirmDelegate } = deps;

  const finalAnswerDef: any = {
    description:
      "提交最终答案并结束任务。CTF 类任务必须包含可验证的 flag{xxx} 或 平台名{xxx} 格式，" +
      "并附逐步 Writeup（每步写清操作/观察/推理）。简单问答可直接回答。调用此工具即视为交卷。",
    parameters: z.object({
      answer: z.string().describe("最终答案全文（含 flag 与 writeup）"),
    }),
    execute: async (args: { answer: string }) => {
      const answer = args.answer;
      const guard = validator(answer);
      emit({ type: "finalAnswer", step, answer });
      if (!guard.ok) {
        // 校验未通过：返回拦截原因 + 调试建议，让模型继续推理（不结束循环）
        return (
          `[系统校验：不通过] ${guard.reason}\n` +
          `请按以下调试建议继续迭代（不要再次调用 final_answer 直到拿到真实 flag）：\n${guard.hint}`
        );
      }
      // 校验通过：返回确认串；MainAgent 的 stopWhen 会因 hasToolCall("final_answer") 结束循环
      return `[系统校验：通过] ${guard.reason}`;
    },
  };
  const finalAnswerTool = tool(finalAnswerDef);

  const delegateDef: any = {
    description:
      "委派子任务给指定子智能体深挖。仅当子任务需独立多步深挖或输出较大时使用。" +
      "可用子智能体见系统提示中的 agents 清单。可并发调用多个 delegate。",
    parameters: z.object({
      agentId: z.string().describe("目标子智能体 id（如 web/pwn/reverse/crypto/misc）"),
      task: z.string().describe("委派给子智能体的子任务描述"),
    }),
    execute: async (args: { agentId: string; task: string }) => {
      const { agentId, task } = args;
      // Plan 门控：若配置了 confirmDelegate，先询问
      if (confirmDelegate) {
        const ok = await confirmDelegate(agentId, task);
        if (!ok) {
          return `[委派已取消] 用户未授权委派给 ${agentId}。`;
        }
      }
      emit({ type: "delegateStart", step, agents: [agentId] });
      try {
        const results = await scheduler.dispatchConcurrent([
          { agentId, task },
        ]);
        const r = results[0];
        emit({ type: "delegateEnd", step, results: r ? [r] : [] });
        return `[委派 ${agentId}] ${r?.result ?? "[无结果]"}`;
      } catch (err: any) {
        const result = {
          agentId,
          task,
          result: `[委派失败] ${err.message}`,
          success: false,
        };
        emit({ type: "delegateEnd", step, results: [result] });
        return result.result;
      }
    },
  };
  const delegateTool = tool(delegateDef);

  const spawnDef: any = {
    description:
      "动态注册一个自定义通用深挖子智能体（当任务不落进任一预设类别时）。" +
      "注册后需用 delegate 工具委派任务给它。id 须唯一，toolNames 必须来自可用工具清单。",
    parameters: z.object({
      id: z.string().describe("新子智能体唯一 id"),
      role: z.string().describe("角色描述（如 'blockchain-exploit'）"),
      toolNames: z
        .array(z.string())
        .describe("该子智能体可用的工具名清单（须来自可用工具）"),
      systemPrompt: z
        .string()
        .optional()
        .describe("可选的自定义系统提示"),
    }),
    execute: async (args: {
      id: string;
      role: string;
      toolNames: string[];
      systemPrompt?: string;
    }) => {
      const { id, role, toolNames, systemPrompt } = args;
      const name = id;
      try {
        scheduler.registerDynamicAgent({
          id,
          name,
          role,
          systemPrompt:
            systemPrompt ||
            `你是专注于 ${role} 的专家子智能体，按 ReAct 方法论独立深挖分配给你的子任务。`,
          toolNames,
        });
        const config = scheduler
          .getDynamicAgentConfigs()
          .find((c) => c.id === id);
        emit({
          type: "spawnAgent",
          step,
          config: config || {
            id,
            name,
            role,
            toolNames,
            systemPrompt: systemPrompt || "",
          },
          success: true,
        });
        return `[SPAWN 成功] ${id}（role=${role}, tools=${toolNames.join(", ")}）。请用 delegate 工具委派任务给它。`;
      } catch (err: any) {
        emit({
          type: "spawnAgent",
          step,
          config: {
            id,
            name,
            role,
            toolNames,
            systemPrompt: systemPrompt || "",
          },
          success: false,
          message: err.message,
        });
        return `[SPAWN 失败] ${id}: ${err.message}`;
      }
    },
  };
  const spawnAgentTool = tool(spawnDef);

  return {
    final_answer: finalAnswerTool,
    delegate: delegateTool,
    spawn_agent: spawnAgentTool,
  };
}
