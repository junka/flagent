// 统一事件类型：MainAgent / ToolExecutor 通过 EventEmitter 的 "event" 通道发射，
// Session.run 桥接到调用方（CLI/VSCode）的 onEvent 回调，实现流式输出与 Plan 门控。

import type { PlannedAction, ActionResult } from "./tool-executor";
import type { DispatchResult } from "./scheduler";

export {
  type PlannedAction,
  type ActionResult,
};
export { type DispatchResult };

/** spawn_agent 动态注册子智能体的事件载荷类型。 */
export interface SpawnAgentRequest {
  id: string;
  name: string;
  role: string;
  systemPrompt: string;
  toolNames: string[];
  maxSteps?: number;
}

export type AgentEvent =
  | { type: "stepStart"; step: number; maxSteps: number }
  | { type: "thinking"; step: number; delta: string }
  | { type: "thought"; step: number; thought: string }
  | { type: "plan"; step: number; plan: string; isMultiStep: boolean }
  | { type: "planConfirmed"; step: number; confirmed: boolean }
  | { type: "actionStart"; step: number; actions: PlannedAction[] }
  | { type: "toolStart"; action: PlannedAction } // 细粒度：单个工具开始（ToolExecutor 发）
  | { type: "toolEnd"; result: ActionResult } // 细粒度：单个工具完成
  | { type: "actionEnd"; step: number; results: ActionResult[] }
  | { type: "delegateStart"; step: number; agents: string[] }
  | { type: "delegateEnd"; step: number; results: DispatchResult[] }
  | {
      type: "spawnAgent";
      step: number;
      config: SpawnAgentRequest;
      success: boolean;
      message?: string;
    }
  | { type: "finalAnswer"; step: number; answer: string }
  | { type: "stepEnd"; step: number }
  | {
      type: "complete";
      success: boolean;
      finalAnswer: string;
      duration: number;
      totalTokens: number;
    };

/** Plan 确认回调类型：返回 true 继续，false 取消当前计划。 */
export type ConfirmPlanFn = (plan: string, step: number) => Promise<boolean>;

/** 事件监听器类型。 */
export type AgentEventListener = (event: AgentEvent) => void;
