import { z } from "zod";
import { ToolRegistry } from "./registry";

export function createDefaultTools(): ToolRegistry {
  const registry = new ToolRegistry();

  registry.register({
    name: "web_search",
    description: "搜索互联网获取最新信息",
    parameters: z.object({
      query: z.string().describe("搜索关键词"),
    }),
    category: "information",
    execute: async (args: any) => {
      const { query } = args;
      return `[模拟搜索结果] 关于"${query}"的搜索结果：\n1. 结果一：这是关于${query}的详细信息...\n2. 结果二：更多相关内容...\n3. 结果三：补充信息...`;
    },
  });

  registry.register({
    name: "code_search",
    description: "在代码库中搜索相关代码",
    parameters: z.object({
      query: z.string().describe("代码搜索关键词"),
      language: z.string().optional().describe("编程语言"),
    }),
    category: "development",
    execute: async (args: any) => {
      const { query, language } = args;
      return `[代码搜索结果] 在${language || "所有语言"}中搜索"${query}"：\n找到了3处匹配：\n- src/utils/helper.ts:12 - function ${query.replace(/\s+/g, "")}()\n- src/services/api.ts:45 - // ${query}\n- src/components/App.tsx:89 - useSearch("${query}")`;
    },
  });

  registry.register({
    name: "file_read",
    description: "读取文件内容",
    parameters: z.object({
      path: z.string().describe("文件路径"),
    }),
    category: "file",
    execute: async (args: any) => {
      const { path } = args;
      return `[文件读取] 路径: ${path}\n内容: 这是一个示例文件内容...`;
    },
  });

  registry.register({
    name: "file_write",
    description: "写入文件",
    parameters: z.object({
      path: z.string().describe("文件路径"),
      content: z.string().describe("文件内容"),
    }),
    category: "file",
    execute: async (args: any) => {
      const { path, content } = args;
      return `[文件写入成功] 路径: ${path}\n写入内容长度: ${content.length} 字符`;
    },
  });

  registry.register({
    name: "task_decompose",
    description: "将复杂任务分解为子任务",
    parameters: z.object({
      task: z.string().describe("要分解的任务描述"),
    }),
    category: "planning",
    execute: async (args: any) => {
      const { task } = args;
      return `[任务分解] 将任务"${task}"分解为以下子任务：\n1. 分析需求和现有代码\n2. 设计数据结构\n3. 实现核心功能\n4. 编写测试用例\n5. 进行代码审查`;
    },
  });

  registry.register({
    name: "code_review",
    description: "审查代码质量并提供建议",
    parameters: z.object({
      code: z.string().describe("要审查的代码"),
    }),
    category: "development",
    execute: async (args: any) => {
      const { code } = args;
      return `[代码审查] 审查意见：\n✅ 代码结构清晰\n⚠️ 建议：添加错误处理\n💡 建议：增加类型注解\n📝 建议：添加单元测试`;
    },
  });

  return registry;
}