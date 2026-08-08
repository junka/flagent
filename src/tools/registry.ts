import { z } from "zod";

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