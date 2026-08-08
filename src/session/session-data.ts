// 会话序列化数据结构。省略 timestamp/tokenCount（重载时重算），只保留语义字段。
import type { AgentStep } from "../agents/main-agent";
import type { DynamicAgentConfig } from "../agents/scheduler";

export type MessageRole = "system" | "user" | "assistant" | "tool";

export interface SerializableMessage {
  role: MessageRole;
  content: string;
}

export interface SessionMeta {
  sessionId: string;
  title: string;
  updatedAt: number;
}

export interface SessionData {
  sessionId: string;
  title: string;
  createdAt: number;
  updatedAt: number;
  messages: SerializableMessage[];
  summary: string;
  steps: AgentStep[];
  approvedTools: string[];
  dynamicAgents: DynamicAgentConfig[];
}
