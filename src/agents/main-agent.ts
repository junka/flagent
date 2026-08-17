import { EventEmitter } from "events";
import { ContextManager, type Message } from "../context/context-manager";
import { ToolRegistry } from "../tools/registry";
import { Scheduler, type DispatchResult } from "./scheduler";
import {
  ToolExecutor,
  type ActionResult,
  type PlannedAction,
} from "./tool-executor";
import type { AgentEvent, ConfirmPlanFn } from "./agent-events";
import { streamText, hasToolCall, isStepCount, type ModelMessage } from "ai";
import { model } from "../llm/client";
import { createBuiltinTools } from "./builtin-tools";

export interface AgentStep {
  step: number;
  action: string;
  thought: string;
  observation: string;
  agentId?: string;
  plan?: string; // 阶段8：PLAN 步骤记录的总体方案
}

export interface AgentResult {
  success: boolean;
  finalAnswer: string;
  steps: AgentStep[];
  totalTokens: number;
  duration: number;
}

export class MainAgent extends EventEmitter {
  private contextManager: ContextManager;
  private toolRegistry: ToolRegistry;
  private scheduler: Scheduler;
  private toolExecutor?: ToolExecutor;
  private maxSteps: number;
  private steps: AgentStep[] = [];
  private confirmPlanFn?: ConfirmPlanFn;

  constructor(
    contextManager: ContextManager,
    toolRegistry: ToolRegistry,
    scheduler: Scheduler,
    toolExecutor?: ToolExecutor,
    maxSteps: number = 20
  ) {
    super();
    this.contextManager = contextManager;
    this.toolRegistry = toolRegistry;
    this.scheduler = scheduler;
    this.toolExecutor = toolExecutor;
    this.maxSteps = maxSteps;
  }

  private heartbeatCallback?: () => void;

  /** 统一事件发射 helper。 */
  private emitEvent(event: AgentEvent): void {
    try { this.heartbeatCallback?.(); } catch {}
    this.emit("event", event);
  }

  /** 设置后台任务心跳回调（background 运行时由 Session 注入）。传 undefined 清除。 */
  setHeartbeatCallback(fn?: () => void): void {
    this.heartbeatCallback = fn;
  }

  /** 设置 Plan 确认回调（多步骤 Plan 执行前询问用户）。传 undefined 清除。 */
  setConfirmPlanFn(fn?: ConfirmPlanFn): void {
    this.confirmPlanFn = fn;
  }

  // 公共访问器：消除 CLI 里 (mainAgent as any) 的 hack
  getScheduler(): Scheduler {
    return this.scheduler;
  }
  getToolRegistry(): ToolRegistry {
    return this.toolRegistry;
  }
  getContextManager(): ContextManager {
    return this.contextManager;
  }
  getToolExecutor(): ToolExecutor | undefined {
    return this.toolExecutor;
  }

  /** 恢复历史 steps（会话重载，仅用于显示；下一次 run() 会重置）。 */
  setSteps(steps: AgentStep[]): void {
    this.steps = [...steps];
  }

  /** 运行选项：后台执行时注入的取消信号与工具级超时。 */
  async run(
    userTask: string,
    options?: { signal?: AbortSignal; toolTimeoutMs?: number }
  ): Promise<AgentResult> {
    const startTime = Date.now();
    const signal = options?.signal;
    const toolTimeoutMs = options?.toolTimeoutMs;
    this.steps = [];
    let currentStep = 0;
    let finalAnswer = "";

    const throwIfAborted = (): void => {
      if (signal?.aborted) {
        throw signal.reason instanceof Error
          ? signal.reason
          : new Error("Task aborted");
      }
    };

    await this.contextManager.addMessage({
      role: "user",
      content: userTask,
    });

    // ── 组装 system prompt：角色 + 工作方法 + 规则 + agents 清单（工具由 SDK 发 schema） ──
    const agentsDescription = this.scheduler
      .getAllAgents()
      .map(
        (a) =>
          `- ${a.id} (${a.name}): 角色=${a.role}, 工具=${a.toolNames.join(", ")}`
      )
      .join("\n");

    const system = `你是一个多智能体系统的主控制器，拥有全部工具并可直接调用，也可通过 delegate 工具委派子智能体做独立深挖。按 ReAct 模式工作，尽量并发采集信息后统一思考。

工作方法（侦察 → 分类 → 深挖，非强制状态机，按任务复杂度自主决定）：
1. 侦察：复杂任务第一步优先并发调用多个只读采集工具（concurrent 工具可同时调用），先获取事实再判断。不要在未侦察前就凭题目字面猜类别并硬路由到某个 agent。
2. 分类：基于侦察观察自主归类（落进 web/pwn/reverse/crypto/misc 之一，或判断为新题）。
3. 深挖：继续用合适工具深入，或并发调用 delegate 委派给专家 agent；不落进预设类别的新题可先 spawn_agent 自定义通用 agent 再 delegate。
简单任务（如算术、常识问答）可直接调用 final_answer 交卷。

可用子智能体（适合需独立多步深挖、或输出较大的子任务；通过 delegate 工具委派）：
${agentsDescription}

规则：
- 优先并发只读采集（同时调用多个只读工具），再统一思考
- 未侦察前不要凭题目字面猜类别并硬路由到某个 agent；先侦察再分类
- 仅当子任务需独立多步深挖或输出较大时才 delegate 给已有 agent
- 仅当任务不落进任一预设 agent 类别、且需要独立深挖时，才 spawn_agent 自定义通用 agent（id 须唯一、toolNames 必须来自可用工具），随后 delegate 给它
- 解题/分析类任务的 final_answer 必须含 Flag + 可手动复现的逐步 Writeup（每步写清：操作、观察、推理）；简单问答可直接回答
- 拿到真实结果后再调用 final_answer 交卷，不要在未拿到 flag 时就用 "Flag: 无" 交卷`;

    // ── 组装 messages：ContextManager 历史 → SDK CoreMessage ──
    const history = this.contextManager.getActiveMessages();
    const summary = this.contextManager.getSummary();
    const messages: ModelMessage[] = [];
    if (summary) {
      messages.push({ role: "system", content: `历史摘要：\n${summary}` });
    }
    for (const m of history) {
      if (m.role === "system") {
        messages.push({ role: "system", content: m.content });
      } else if (m.role === "user") {
        messages.push({ role: "user", content: m.content });
      } else if (m.role === "assistant") {
        messages.push({ role: "assistant", content: m.content });
      }
      // role === "tool" 的历史消息跳过：tool_use 协议下 tool_result 由 SDK 自动管理
    }

    // ── 组装 tools：注册表工具 + 内置控制工具 ──
    const toolExecutor = this.toolExecutor;
    if (!toolExecutor) {
      throw new Error("MainAgent 缺少 ToolExecutor，无法运行 tool_use 循环");
    }
    const execFn = async (action: {
      toolName: string;
      toolArgs: Record<string, any>;
    }): Promise<string> => {
      const r = await toolExecutor.executeOne(action, { signal, toolTimeoutMs });
      return r.result;
    };
    const registryTools = this.toolRegistry.toAISDKTools(execFn);

    // CTF 校验器（闭包捕获 userTask/history/summary）
    const validator = (answer: string) =>
      validateCTFFinalAnswer(answer, userTask, history.map((m) => `${m.role}: ${m.content}`).join("\n"), summary);

    const builtinTools = createBuiltinTools(
      {
        scheduler: this.scheduler,
        toolExecutor,
        confirmDelegate: this.confirmPlanFn
          ? async (_agentId: string, _task: string) =>
              this.confirmPlanFn ? this.confirmPlanFn(_task, currentStep) : true
          : undefined,
      },
      validator,
      (ev) => this.emitEvent(ev),
      currentStep,
    );

    const allTools = { ...registryTools, ...builtinTools };

    // ── step 计数（onStepEnd 递增，供事件与 validator 引用） ──
    const maxStepCount = this.maxSteps;

    this.emitEvent({ type: "stepStart", step: 1, maxSteps: maxStepCount });

    try {
      const streamResult = streamText({
        model,
        system,
        messages,
        tools: allTools,
        stopWhen: [hasToolCall("final_answer"), isStepCount(maxStepCount)],
        ...(signal ? { abortSignal: signal } : {}),
        onStepEnd: () => {
          currentStep += 1;
          this.emitEvent({ type: "stepEnd", step: currentStep });
          if (currentStep < maxStepCount) {
            this.emitEvent({ type: "stepStart", step: currentStep + 1, maxSteps: maxStepCount });
          }
        },
      });

      // 流式思考文本：逐 delta emit（CLI/VSCode 渲染层零改动）
      for await (const delta of streamResult.textStream) {
        throwIfAborted();
        this.emitEvent({ type: "thinking", step: currentStep + 1, delta });
      }

      throwIfAborted();

      // 等待流结束（确保所有 toolCall 执行完毕）
      await streamResult;

      // 取最终答案：优先从 final_answer toolCall 的 input.answer 取
      // AI SDK v7 的 toolCall 用 input（已解析对象），非 args
      const toolCalls = (await streamResult.toolCalls) || [];
      const finalCall = toolCalls.find((tc: any) => tc.toolName === "final_answer");
      if (finalCall && (finalCall as any).input?.answer) {
        finalAnswer = (finalCall as any).input.answer;
      } else {
        // 兜底：用模型文本输出
        finalAnswer = (await streamResult.text) || "";
      }

      await this.contextManager.addMessage({
        role: "assistant",
        content: finalAnswer,
      });

      const totalTokens = this.contextManager.getTotalTokens();
      const result: AgentResult = {
        success: Boolean(finalCall),
        finalAnswer,
        steps: this.steps,
        totalTokens,
        duration: Date.now() - startTime,
      };
      this.emitEvent({
        type: "complete",
        success: result.success,
        finalAnswer,
        duration: result.duration,
        totalTokens,
      });
      return result;
    } catch (err: any) {
      // 取消/中断：返回部分结果
      const isAbort =
        err?.name === "AbortError" || /\b(abort|中断)\b/i.test(err?.message || "");
      const totalTokens = this.contextManager.getTotalTokens();
      const result: AgentResult = {
        success: false,
        finalAnswer: finalAnswer || (isAbort ? "任务已中断。" : `执行出错: ${err?.message || err}`),
        steps: this.steps,
        totalTokens,
        duration: Date.now() - startTime,
      };
      this.emitEvent({
        type: "complete",
        success: false,
        finalAnswer: result.finalAnswer,
        duration: result.duration,
        totalTokens,
      });
      if (isAbort) return result;
      throw err;
    }
  }
}

/**
 * CTF 类任务 Final Answer 校验器：防止 Agent "Flag: 无" 就交卷。
 * 校验逻辑：
 *   1) 先判断是否为 CTF 类任务（用户任务/历史/摘要含关键词）
 *      关键词 flag/ctf/pwn/reverse/附件/题目/靶机/靶场/crypto/web…
 *   2) 非 CTF 类：一律放行（纯聊天、CRUD、部署等不卡）
 *   3) 是 CTF 类但 finalAnswer 含 "Flag: 无" / "未获取" 等无 flag 措辞 → 拦截
 *   4) 是 CTF 类且 finalAnswer 中确实含 1+ 条可验证 flag 格式（<平台>{...}，≥ 6 字符） → 通过
 *   5) 未命中 → 拦截，并给出具体 debug 建议
 */
function validateCTFFinalAnswer(
  finalAnswer: string,
  userTask: string,
  historyText: string,
  summary: string
): { ok: boolean; reason: string; hint: string } {
  const combinedContext = `${userTask}\n${historyText}\n${summary}`.toLowerCase();
  const ctfKeywords = [
    "flag", "ctf", "pwn", "reverse", "crypto",
    "附件", "题目", "靶机", "靶场", "challenge",
    "ctfhub", "ctftime", "ctfshow",
    "antiy", "buu", "攻防世界", "hgame", "xctf",
  ];
  const isCTFTask = ctfKeywords.some((k) => combinedContext.includes(k));
  if (!isCTFTask) {
    return { ok: true, reason: "非 CTF 类任务，跳过 Flag 校验。", hint: "" };
  }

  const faLower = finalAnswer.toLowerCase();
  const hasExplicitNo =
    /flag\s*[:：]\s*无/.test(finalAnswer) ||
    /flag\s*[:：]\s*未/.test(finalAnswer) ||
    /未从远程获取/.test(finalAnswer) ||
    /需实际执行获取/.test(finalAnswer) ||
    /flag.{0,20}(未|无|没)/.test(faLower);

  const flagPatterns = [
    /flag\{[^}\n\r]{1,128}\}/i,
    /CTF\{[^}\n\r]{1,128}\}/,
    /ctfhub\{[^}\n\r]{1,128}\}/,
    /picoCTF\{[^}\n\r]{1,128}\}/,
    /FLAG\{[^}\n\r]{1,128}\}/,
    /HITS\{[^}\n\r]{1,128}\}/,
    /DASCTF\{[^}\n\r]{1,128}\}/,
    // 兜底：任意 <平台>{<内容≥3 字符>}
    /[A-Za-z0-9_]{1,32}\{[^}\n\r]{3,128}\}/,
  ];
  const matched = flagPatterns
    .map((re) => finalAnswer.match(re))
    .filter((m): m is RegExpMatchArray => !!m)
    .map((m) => m[0])
    .filter((c) => c.length >= 6);

  // 去重
  const unique = Array.from(new Set(matched));
  if (unique.length > 0) {
    return {
      ok: true,
      reason: `检测到 ${unique.length} 条 flag 匹配：${unique.join(", ")}`,
      hint: "",
    };
  }

  if (hasExplicitNo) {
    return {
      ok: false,
      reason: "Final Answer 中声明 'Flag: 无/未获取/需实际执行'，但这是一道 CTF 类任务 → 必须继续 debug 到拿到真实 flag 再交卷。",
      hint:
        "调试 checklist：\n" +
        "  (a) 回顾最后 2~3 条工具结果末尾：有没有 [NO FLAG FOUND] / [FLAG FOUND] 标记？\n" +
        "      有 [NO FLAG FOUND] → 按它下面的 5 条建议改 exploit\n" +
        "  (b) pwn 类：用 pwn_run_exploit（不要 file_write_real + python3 -c），脚本结尾一定要\n" +
        "      发多条命令：cat flag\\ncat /flag\\nls -la /\\nfind / -name 'flag*' 2>/dev/null\\n，\n" +
        "      且最后一个 send 后 sleep(1~2s) + while recv，避免 shell 输出被截断\n" +
        "  (c) web：重新检查 HTTP 200 页面中有没有注释/源码里的 flag，flag 不在 body 里也可能在响应头\n" +
        "  (d) crypto：检查 decode 输出的字节，不要只看 repr\n" +
        "  (e) 题目有明确平台前缀的：调用工具时传 flagRegex='ctfhub\\\\{[^}]+\\\\}'（或对应平台名）精确扫",
    };
  }

  // 既没匹配 flag，又没写 "Flag: 无" → 可能漏扫或平台名特殊
  return {
    ok: false,
    reason: "这是 CTF 类任务，但 Final Answer 里未出现可验证的 flag{xxx}/ctfhub{xxx}/平台名{xxx} 格式匹配。\n" +
      "请确认 flag 是否真的拿到，或改用工具自动扫描（pwn_run_exploit / nc_remote_client 已内置扫描）。",
    hint:
      "处理建议：\n" +
      "  1) 重新看工具输出的最后一段 bytes 尾部/hex 尾部：flag 可能在乱码之后\n" +
      "  2) 未执行 exploit → 先写 exploit 跑一次再交卷\n" +
      "  3) 平台前缀未知：用 flagRegex='[A-Za-z0-9_]+\\\\{[^}]+\\\\}' 兜底再扫\n" +
      "  4) 真的确认无 flag 且题目是分析类 → 写完整推导并在 Writeup 里说明 '题目预期输出分析结论而非 flag'，但这是极少数情况",
  };
}