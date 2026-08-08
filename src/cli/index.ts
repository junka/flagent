#!/usr/bin/env node

import readline from "readline";
import { API_KEY, MODEL_NAME, WORKSPACE_ID } from "../llm/client";
import { createAgentSystem, type AgentSystem } from "../agents/factory";
import { createToolRegistry } from "../tools/factory";
import { SessionManager } from "../session/session-manager";
import type { AgentEvent } from "../agents/agent-events";

// 兼容旧 import 路径（tests 仍从 dist/cli/index 取 createAgentSystem / createToolRegistry）
export { createAgentSystem, createToolRegistry, type AgentSystem };

const BANNER = `
╔══════════════════════════════════════════════════════════════╗
║                    Flagent Multi-Agent System                ║
║                    多智能体协作系统                          ║
╠══════════════════════════════════════════════════════════════╣
║  Model: ${MODEL_NAME.padEnd(56)}  ║
║  Workspace: ${WORKSPACE_ID.padEnd(50)}  ║
║  API Key: ${API_KEY ? "✓ 已配置".padEnd(52) : "✗ 未配置".padEnd(52)}  ║
╚══════════════════════════════════════════════════════════════╝
`;

const HELP_TEXT = `
会话管理（每会话独立上下文/权限/动态 agent，可同时分析多题）:
  /new [标题]        新建会话并切为活动（标题可选）
  /sessions          列出所有会话（标记当前活动会话）
  /switch <id>       切换到指定会话（不在内存则从磁盘恢复）
  /delete <id>       删除指定会话（内存 + 磁盘）
  /title [标题]      查看或设置当前会话标题

会话内命令:
  /help              显示帮助信息
  /verbose           切换思考过程显示（默认精简，切换后显示完整思考与工具结果）
  /agents            显示所有子智能体
  /tools             显示所有可用工具
  /context           显示当前上下文状态
  /clear             清除当前会话的对话历史与权限记忆
  /permissions       显示当前会话已批准的工具
  /summarize         生成当前会话对话摘要
  /exit              退出系统

提示:
  - 直接输入问题即可与多智能体系统对话
  - 无活动会话时首次提问会自动新建会话
  - 会话自动持久化到 .flagent/sessions/，重启后可 /switch 恢复
  - 思考过程实时流式输出；多步骤 Plan 会暂停等待确认，单步骤直接执行
`;

function fmtTime(ts: number): string {
  const d = new Date(ts);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** 标题截短显示。 */
function shortTitle(t: string): string {
  return t ? (t.length > 24 ? t.slice(0, 24) + "…" : t) : "(未命名)";
}

/** 文本按指定前缀缩进每一行。 */
function indent(text: string, prefix: string): string {
  return text
    .split("\n")
    .map((l) => prefix + l)
    .join("\n");
}

/** 截断长文本为单行预览。 */
function preview(text: string, max = 100): string {
  const oneLine = text.replace(/\n/g, " ").trim();
  return oneLine.length > max ? oneLine.slice(0, max) + "…" : oneLine;
}

export async function startCLI(): Promise<void> {
  console.log(BANNER);

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: "👤 ",
  });

  // 权限确认：副作用工具（command_exec 等）逐次询问，本会话记忆
  const confirmFn = async (
    toolName: string,
    args: Record<string, any>
  ): Promise<boolean> => {
    const argStr = JSON.stringify(args).slice(0, 200);
    return new Promise((resolve) => {
      rl.question(
        `\n⚠️  权限请求: 工具 "${toolName}" 参数 ${argStr}\n    允许执行? (y/n) [本会话记忆] `,
        (answer) => {
          resolve(answer.trim().toLowerCase().startsWith("y"));
        }
      );
    });
  };

  const toolRegistry = createToolRegistry();
  const sessionManager = new SessionManager({ toolRegistry, confirmFn });
  let mainAgentRunning = false; // run 期间拦截新输入（权限确认的 y/n 由 rl.question 处理）
  let verbose = false; // /verbose 切换：默认精简，开启后显示完整思考与工具结果

  /** 更新提示符，含当前会话标题。 */
  const refreshPrompt = (): void => {
    const s = sessionManager.current();
    rl.setPrompt(s ? `👤[${shortTitle(s.title)}] ` : "👤 ");
  };

  // 启动时自动恢复最近会话（若有）；否则等待首次提问自动新建
  try {
    const list = await sessionManager.list();
    if (list.length > 0) {
      const recent = list[0];
      await sessionManager.resume(recent.sessionId);
      console.log(
        `📂 已恢复最近会话: ${recent.sessionId.slice(0, 8)} (${recent.title})`
      );
    } else {
      console.log("📂 暂无历史会话，输入问题即可开始（将自动新建会话）。");
    }
  } catch (e: any) {
    console.warn(`⚠️  恢复会话失败: ${e.message}`);
  }

  console.log("系统已启动！输入 /help 查看帮助，直接输入问题开始对话。\n");
  refreshPrompt();
  rl.prompt();

  rl.on("line", async (line: string) => {
    const input = line.trim();

    // run 期间忽略新输入（权限确认的 y/n 由 rl.question 回调消费）
    if (mainAgentRunning) {
      return;
    }

    if (!input) {
      rl.prompt();
      return;
    }

    if (input === "/exit" || input === "/quit") {
      console.log("\n👋 再见！");
      rl.close();
      return;
    }

    if (input === "/help") {
      console.log(HELP_TEXT);
      rl.prompt();
      return;
    }

    if (input === "/verbose") {
      verbose = !verbose;
      console.log(
        `\n🔊 思考过程显示已${verbose ? "开启" : "关闭"}（${verbose ? "完整思考与工具结果" : "精简摘要"}）。\n`
      );
      rl.prompt();
      return;
    }

    // /new [标题]
    if (input === "/new" || input.startsWith("/new ")) {
      const title = input.slice(4).trim() || undefined;
      const session = await sessionManager.create(title);
      console.log(
        `\n📄 新建会话: ${session.id.slice(0, 8)} (${session.title || "未命名"})`
      );
      refreshPrompt();
      rl.prompt();
      return;
    }

    // /sessions
    if (input === "/sessions") {
      const list = await sessionManager.list();
      if (list.length === 0) {
        console.log("\n📭 暂无会话。用 /new [标题] 创建一个吧。");
      } else {
        console.log("\n📋 会话列表（按最近更新排序）：");
        for (const m of list) {
          const mark = m.active ? " ← 当前" : "";
          console.log(
            `  • ${m.sessionId.slice(0, 8)}  ${shortTitle(m.title).padEnd(26)} ${fmtTime(m.updatedAt)}${mark}`
          );
        }
      }
      rl.prompt();
      return;
    }

    // /switch <id>
    if (input.startsWith("/switch ")) {
      const id = input.split(/\s+/)[1]?.trim();
      if (!id) {
        console.log("\n⚠️  用法: /switch <id>（id 可用 /sessions 查看的短前缀）");
      } else {
        try {
          // 支持短前缀匹配
          const list = await sessionManager.list();
          const match = list.find((m) => m.sessionId.startsWith(id));
          if (!match) {
            console.log(`\n⚠️  未找到会话: ${id}`);
          } else {
            const session = await sessionManager.switch(match.sessionId);
            console.log(
              `\n🔄 已切换到会话: ${session.id.slice(0, 8)} (${session.title || "未命名"})`
            );
            refreshPrompt();
          }
        } catch (e: any) {
          console.error(`\n❌ 切换失败: ${e.message}`);
        }
      }
      rl.prompt();
      return;
    }

    // /delete <id>
    if (input.startsWith("/delete ")) {
      const id = input.split(/\s+/)[1]?.trim();
      if (!id) {
        console.log("\n⚠️  用法: /delete <id>");
      } else {
        try {
          const list = await sessionManager.list();
          const match = list.find((m) => m.sessionId.startsWith(id));
          if (!match) {
            console.log(`\n⚠️  未找到会话: ${id}`);
          } else {
            const wasActive = sessionManager.getActiveId() === match.sessionId;
            const ok = await sessionManager.delete(match.sessionId);
            console.log(
              ok
                ? `\n🗑️  已删除会话: ${match.sessionId.slice(0, 8)}`
                : `\n⚠️  会话不存在: ${match.sessionId.slice(0, 8)}`
            );
            if (wasActive) refreshPrompt();
          }
        } catch (e: any) {
          console.error(`\n❌ 删除失败: ${e.message}`);
        }
      }
      rl.prompt();
      return;
    }

    // /title [标题]
    if (input === "/title" || input.startsWith("/title ")) {
      const session = sessionManager.current();
      if (!session) {
        console.log("\n⚠️  无活动会话，用 /new 创建或直接输入问题。");
      } else if (input === "/title") {
        console.log(`\n🏷️  当前标题: ${session.title || "(未命名)"}`);
      } else {
        const title = input.slice(6).trim();
        session.setTitle(title);
        await sessionManager.persistActive();
        console.log(`\n🏷️  标题已更新: ${title}`);
        refreshPrompt();
      }
      rl.prompt();
      return;
    }

    // 以下命令需要活动会话
    const session = sessionManager.current();

    if (input === "/agents") {
      if (!session) {
        console.log("\n⚠️  无活动会话，用 /new 创建或直接输入问题。");
        rl.prompt();
        return;
      }
      const agents = session.getScheduler().getAllAgents();
      console.log("\n📋 子智能体列表：");
      for (const agent of agents) {
        console.log(`  • ${agent.id} (${agent.name}) - ${agent.role}`);
        console.log(`    工具: ${agent.toolNames.join(", ")}`);
      }
      rl.prompt();
      return;
    }

    if (input === "/tools") {
      const tools = toolRegistry.getAll();
      console.log("\n🔧 可用工具列表：");
      for (const tool of tools) {
        const flags = [
          tool.concurrent ? "并发" : null,
          tool.requirePermission ? "需权限" : null,
        ]
          .filter(Boolean)
          .join("/");
        console.log(`  • ${tool.name}${flags ? ` [${flags}]` : ""}: ${tool.description}`);
      }
      rl.prompt();
      return;
    }

    if (input === "/permissions") {
      if (!session) {
        console.log("\n⚠️  无活动会话，用 /new 创建或直接输入问题。");
        rl.prompt();
        return;
      }
      const approved = session.getPermissionManager().getApproved();
      console.log("\n🔐 本会话已批准的工具：");
      console.log(
        approved.length ? approved.map((t) => `  • ${t}`).join("\n") : "  (无)"
      );
      rl.prompt();
      return;
    }

    if (input === "/context") {
      if (!session) {
        console.log("\n⚠️  无活动会话，用 /new 创建或直接输入问题。");
        rl.prompt();
        return;
      }
      const cm = session.getContextManager();
      const messages = cm.getMessages();
      const summary = cm.getSummary();
      console.log(`\n📊 上下文状态：`);
      console.log(`  会话: ${session.id.slice(0, 8)} (${session.title || "未命名"})`);
      console.log(`  消息数: ${messages.length}`);
      console.log(`  总 Token 数: ${cm.getTotalTokens()}`);
      console.log(`  摘要: ${summary ? summary.slice(0, 200) + "..." : "(无)"}`);
      rl.prompt();
      return;
    }

    if (input === "/summarize") {
      if (!session) {
        console.log("\n⚠️  无活动会话，用 /new 创建或直接输入问题。");
        rl.prompt();
        return;
      }
      const cm = session.getContextManager();
      console.log("\n📝 正在生成对话摘要...");
      mainAgentRunning = true;
      try {
        const summary = await cm.summarizeNow();
        console.log(
          summary
            ? `  ${summary.slice(0, 500)}${summary.length > 500 ? "..." : ""}`
            : "  (当前对话较短，无需摘要)"
        );
        await sessionManager.persistActive();
      } catch (err: any) {
        console.error(`\n❌ 摘要失败: ${err.message}`);
      } finally {
        mainAgentRunning = false;
      }
      rl.prompt();
      return;
    }

    if (input === "/clear") {
      if (!session) {
        console.log("\n⚠️  无活动会话，用 /new 创建或直接输入问题。");
        rl.prompt();
        return;
      }
      session.clearRuntime();
      await sessionManager.persistActive();
      console.log("\n🧹 当前会话的对话历史与权限记忆已清除。\n");
      rl.prompt();
      return;
    }

    // 普通任务：经 SessionManager 执行（无活动会话则自动新建）
    // 通过 onEvent 流式输出思考/工具执行过程；多步骤 Plan 经 confirmPlan 门控
    console.log("\n🤖 正在思考...");
    mainAgentRunning = true;

    /** 流式事件渲染：verbose 控制思考/结果详细程度，工具执行实时打印 */
    const onEvent = (event: AgentEvent): void => {
      switch (event.type) {
        case "stepStart":
          if (verbose)
            console.log(`\n━━━ Step ${event.step}/${event.maxSteps} ━━━`);
          break;

        case "thought": {
          if (verbose) {
            console.log(`\n  💭 思考:`);
            console.log(indent(event.thought, "     "));
          } else {
            const head = event.thought.split("\n")[0];
            console.log(`\n  💭 ${preview(head, 80)}`);
          }
          break;
        }

        case "plan": {
          const tag = event.isMultiStep ? "（多步骤·待确认）" : "（单步骤·直接执行）";
          console.log(`\n  📋 Plan${tag}:`);
          console.log(indent(event.plan, "     "));
          break;
        }

        case "planConfirmed":
          console.log(
            event.confirmed
              ? `  ▶️  已确认，开始执行`
              : `  ⏹️  已取消该计划`
          );
          break;

        case "actionStart":
          console.log(
            `  🔧 执行工具: ${event.actions
              .map((a) => a.toolName)
              .join(", ")}`
          );
          break;

        case "toolStart":
          if (verbose)
            console.log(
              `     → 开始 ${event.action.toolName}(${JSON.stringify(
                event.action.toolArgs
              )})`
            );
          break;

        case "toolEnd": {
          const r = event.result;
          const mark = r.success ? "✓" : "✗";
          const skipped = r.skipped ? "（跳过）" : "";
          console.log(`     ${mark} ${r.toolName}${skipped}: ${preview(r.result, 100)}`);
          if (verbose && r.result.length > 100)
            console.log(indent(r.result, "        "));
          break;
        }

        case "actionEnd":
          // 精简模式下 toolEnd 已实时打印每个工具；verbose 在 toolEnd 已展开结果，此处不重复
          break;

        case "delegateStart":
          console.log(`  🤝 委派子智能体: ${event.agents.join(", ")}`);
          break;

        case "delegateEnd":
          for (const d of event.results) {
            const mark = d.success ? "✓" : "✗";
            console.log(`     ${mark} ${d.agentId}: ${preview(d.result, 100)}`);
            if (verbose && d.result.length > 100)
              console.log(indent(d.result, "        "));
          }
          break;

        case "spawnAgent": {
          const mark = event.success ? "✓" : "✗";
          const detail = event.success
            ? `role=${event.config.role}, tools=${event.config.toolNames.join(", ")}`
            : event.message || "注册失败";
          console.log(`     ${mark} SPAWN ${event.config.id}: ${detail}`);
          break;
        }

        case "finalAnswer":
          console.log(`\n✅ 最终回答：`);
          console.log(indent(event.answer, "   "));
          break;

        case "stepEnd":
          break;

        case "complete": {
          console.log(`\n📈 执行统计：`);
          console.log(`   耗时: ${(event.duration / 1000).toFixed(1)}s`);
          console.log(`   Token 数: ${event.totalTokens}`);
          console.log(
            `   状态: ${event.success ? "✓ 成功" : "✗ 未完成"}\n`
          );
          break;
        }
      }
    };

    /** 多步骤 Plan 门控：rl.question 询问 y/n（mainAgentRunning 期间不会被 line 事件拦截） */
    const confirmPlan = (_plan: string): Promise<boolean> => {
      return new Promise((resolve) => {
        rl.question(`\n  ⏸️  上述 Plan 为多步骤，是否执行? (y/n) `, (answer) => {
          resolve(answer.trim().toLowerCase().startsWith("y"));
        });
      });
    };

    try {
      await sessionManager.run(input, { onEvent, confirmPlan });
    } catch (error: any) {
      console.error(`\n❌ 执行出错: ${error.message}\n`);
    } finally {
      mainAgentRunning = false;
    }

    refreshPrompt();
    rl.prompt();
  });

  rl.on("close", () => {
    console.log("\n👋 再见！");
    process.exit(0);
  });
}

// 入口点：直接运行时启动 CLI
if (require.main === module) {
  startCLI().catch((err) => {
    console.error("❌ 启动失败:", err.message);
    process.exit(1);
  });
}
