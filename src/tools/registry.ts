import { z } from "zod";
import { tool, type ToolSet } from "ai";

export interface ToolDefinition {
  name: string;
  description: string;
  parameters: z.ZodTypeAny;
  execute: (args: any) => Promise<string>;
  category?: string;
  concurrent?: boolean;        // true=只读采集，可安全并发执行（默认 false 保守）
  requirePermission?: boolean; // true=有副作用，需逐次权限确认（默认 false）
}

export class ToolRegistry {
  private tools: Map<string, ToolDefinition> = new Map();

  register(tool: ToolDefinition): void {
    if (this.tools.has(tool.name)) {
      throw new Error(`Tool "${tool.name}" already registered`);
    }
    this.tools.set(tool.name, tool);
  }

  unregister(name: string): void {
    this.tools.delete(name);
  }

  get(name: string): ToolDefinition | undefined {
    return this.tools.get(name);
  }

  getAll(): ToolDefinition[] {
    return Array.from(this.tools.values());
  }

  getByCategory(category: string): ToolDefinition[] {
    return this.getAll().filter((t) => t.category === category);
  }

  isConcurrent(name: string): boolean {
    const tool = this.tools.get(name);
    return tool?.concurrent === true;
  }

  requiresPermission(name: string): boolean {
    const tool = this.tools.get(name);
    return tool?.requirePermission === true;
  }

  getNames(): string[] {
    return Array.from(this.tools.keys());
  }

  async execute(name: string, args: any): Promise<string> {
    const tool = this.tools.get(name);
    if (!tool) {
      throw new Error(`Tool "${name}" not found`);
    }
    const parsed = tool.parameters.safeParse(args);
    if (!parsed.success) {
      throw new Error(`Invalid arguments for "${name}": ${parsed.error.message}`);
    }
    return tool.execute(parsed.data);
  }

  getToolDescriptions(): Array<{
    name: string;
    description: string;
    parameters: any;
  }> {
    return this.getAll().map((t) => ({
      name: t.name,
      description: t.description,
      parameters: this.zodToJsonSchema(t.parameters),
    }));
  }

  /**
   * 转换为 AI SDK 原生 ToolSet，供 streamText/generateText 的 tools 参数使用。
   * 这是迁移到 tool_use 协议的核心：把工具的 Zod schema 真正发给模型，
   * 模型用结构化 tool_call 调用，而非文本标记解析。
   *
   * @param exec 单工具执行回调（由 ToolExecutor.executeOne 提供，含权限/超时/事件）
   * @param allowedTools 白名单；未传则全部工具可用
   */
  toAISDKTools(
    exec: (action: { toolName: string; toolArgs: Record<string, any> }) => Promise<string>,
    allowedTools?: string[],
  ): ToolSet {
    const tools: ToolSet = {};
    for (const t of this.getAll()) {
      if (allowedTools && !allowedTools.includes(t.name)) continue;
      // 跳过空描述（模型无法理解）
      const desc = t.description || `工具 ${t.name}`;
      // 用 as any 绕过 tool() 对 ZodTypeAny 的泛型推断（INPUT 无法从 ZodTypeAny 精确推断）
      const def: any = {
        description: desc,
        parameters: t.parameters,
        execute: async (args: Record<string, any>) => {
          // execute 回调内调 exec → ToolExecutor.executeOne（权限/超时/事件 emit）
          return exec({ toolName: t.name, toolArgs: args ?? {} });
        },
      };
      tools[t.name] = tool(def);
    }
    return tools;
  }

  /**
   * zod schema → JSON schema 推断。
   * 用 instanceof 判定类型（zod v4 的 _def.typeName 已不可靠，instanceof 跨版本稳健）。
   * 支持 string/number/boolean/array/object 及 optional/nullable 解包。
   */
  private zodToJsonSchema(schema: z.ZodTypeAny): any {
    try {
      if (schema instanceof z.ZodString) return { type: "string" };
      if (schema instanceof z.ZodNumber) return { type: "number" };
      if (schema instanceof z.ZodBoolean) return { type: "boolean" };
      if (schema instanceof z.ZodArray) {
        return { type: "array", items: this.zodToJsonSchema(schema.element as z.ZodTypeAny) };
      }
      if (schema instanceof z.ZodOptional || schema instanceof z.ZodNullable) {
        return this.zodToJsonSchema(schema.unwrap() as z.ZodTypeAny);
      }
      if (schema instanceof z.ZodObject) {
        const properties: Record<string, any> = {};
        const shape = (schema as any).shape;
        for (const [key, value] of Object.entries(shape)) {
          properties[key] = this.zodToJsonSchema(value as z.ZodTypeAny);
        }
        return { type: "object", properties };
      }
      return { type: "object", properties: {} };
    } catch {
      return { type: "object", properties: {} };
    }
  }
}