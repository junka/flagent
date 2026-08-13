import { EventEmitter } from "events";
import { ContextManager, type Message } from "../context/context-manager";
import { ToolRegistry } from "../tools/registry";
import { Scheduler, type DispatchResult } from "./scheduler";
import {
  ToolExecutor,
  type ActionResult,
  type PlannedAction,
} from "./tool-executor";
import { parseMainReactResponse } from "./react-parser";
import type { AgentEvent, ConfirmPlanFn } from "./agent-events";
import { streamText } from "ai";
import { model } from "../llm/client";

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

    for (let step = 1; step <= this.maxSteps; step++) {
      throwIfAborted();
      this.emitEvent({ type: "stepStart", step, maxSteps: this.maxSteps });
      const stepResult = await this.reactStep(step, userTask, { signal, toolTimeoutMs });
      this.emitEvent({ type: "stepEnd", step });

      if (stepResult.isComplete) {
        await this.contextManager.addMessage({
          role: "assistant",
          content: stepResult.answer,
        });

        const isCancelled = stepResult.cancelled === true;
        const result: AgentResult = {
          success: !isCancelled,
          finalAnswer: stepResult.answer,
          steps: this.steps,
          totalTokens: this.contextManager.getTotalTokens(),
          duration: Date.now() - startTime,
        };
        this.emitEvent({
          type: "complete",
          success: result.success,
          finalAnswer: stepResult.answer,
          duration: result.duration,
          totalTokens: result.totalTokens,
        });
        return result;
      }

      if (stepResult.needsMoreInfo) {
        const result: AgentResult = {
          success: false,
          finalAnswer: stepResult.answer,
          steps: this.steps,
          totalTokens: this.contextManager.getTotalTokens(),
          duration: Date.now() - startTime,
        };
        this.emitEvent({
          type: "complete",
          success: false,
          finalAnswer: stepResult.answer,
          duration: result.duration,
          totalTokens: result.totalTokens,
        });
        return result;
      }
    }

    const result: AgentResult = {
      success: false,
      finalAnswer: "已达到最大步数限制，任务未能完成。",
      steps: this.steps,
      totalTokens: this.contextManager.getTotalTokens(),
      duration: Date.now() - startTime,
    };
    this.emitEvent({
      type: "complete",
      success: false,
      finalAnswer: result.finalAnswer,
      duration: result.duration,
      totalTokens: result.totalTokens,
    });
    return result;
  }

  /**
   * 判断是否为多步骤 Plan（两者结合）：
   * ① PLAN 文本含 ≥2 个编号步骤（1. / 1) / 1、 等格式，按行匹配）
   * ② 当前 step 并发动作数（actions + delegates）≥2
   * 满足任一即视为多步骤，需用户确认。
   */
  private isMultiStepPlan(
    plan: string,
    actionCount: number,
    delegateCount: number
  ): boolean {
    const numberedStepLines = plan
      .split("\n")
      .filter((l) => /^\s*\d+[.\)、]/.test(l)).length;
    return numberedStepLines >= 2 || actionCount + delegateCount >= 2;
  }

  private async reactStep(
    step: number,
    userTask: string,
    opts?: { signal?: AbortSignal; toolTimeoutMs?: number }
  ): Promise<{
    isComplete: boolean;
    needsMoreInfo: boolean;
    answer: string;
    cancelled?: boolean;
  }> {
    const signal = opts?.signal;
    const toolTimeoutMs = opts?.toolTimeoutMs;
    const throwIfAborted = (): void => {
      if (signal?.aborted) {
        throw signal.reason instanceof Error
          ? signal.reason
          : new Error("Task aborted");
      }
    };
    throwIfAborted();
    const messages = this.contextManager.getActiveMessages();
    const historyText = messages
      .map((m) => `${m.role}: ${m.content}`)
      .join("\n");

    const summary = this.contextManager.getSummary();
    const summaryText = summary ? `\n\n历史摘要：\n${summary}` : "";

    const toolsDescription = this.toolRegistry
      .getAll()
      .map((t) => `- ${t.name}: ${t.description}`)
      .join("\n");

    const agentsDescription = this.scheduler
      .getAllAgents()
      .map(
        (a) =>
          `- ${a.id} (${a.name}): 角色=${a.role}, 工具=${a.toolNames.join(", ")}`
      )
      .join("\n");

    const prompt = `你是一个多智能体系统的主控制器，拥有全部工具并可直接执行，也可委派子智能体做独立深挖。按 ReAct 模式工作，尽量并发采集信息后统一思考。

工作方法（侦察 → 分类 → 深挖，非强制状态机，按任务复杂度自主决定）：
1. 侦察：复杂任务第一步优先并发只读采集（多个 concurrent 工具同时跑），先获取事实再判断。不要在未侦察前就凭题目字面猜类别并硬路由到某个 agent。
2. 分类：基于侦察观察自主归类（落进 web/pwn/reverse/crypto/misc 之一，或判断为新题）。
3. 深挖：MainAgent 继续用合适工具深入，或并发 DELEGATE 给专家 agent；不落进预设类别的新题可 SPAWN_AGENT 自定义通用 agent 再 DELEGATE。
简单任务（如算术、常识问答）可跳过 PLAN/ACTIONS 直接 FINAL_ANSWER。

步骤 ${step}/${this.maxSteps}

用户任务：${userTask}

可用工具（可直接调用，鼓励并发只读采集）：
${toolsDescription}

可用子智能体（适合需独立多步深挖、或输出较大的子任务）：
${agentsDescription}

对话历史：
${historyText}
${summaryText}

输出格式（PLAN 通常仅第一步输出；ACTIONS / SPAWN_AGENT / DELEGATE 可同时出现以并发推进）：
PLAN: [可选：侦察目标 + 总体方案。简单任务可省略]
THOUGHT: [思考：分析进展、决定下一步。若 DELEGATE 多个 agent，在此说明每个 agent 的子任务]
ACTIONS:
  - <工具名>({...参数JSON...})
  - <工具名>({...参数JSON...})
SPAWN_AGENT: {"id":"gen-xxx","name":"...","role":"...","systemPrompt":"...","toolNames":["t1","t2"]}
DELEGATE: <agentId1>, <agentId2>
FINAL_ANSWER: [任务完成时的最终答案。解题/渗透/逆向/分析类任务必须按以下结构输出，让读者能手动逐步复现：
  Flag: <flag 值；若无写"无">
  Writeup:
  1. <步骤：具体操作（命令/URL/动作）+ 关键观察 + 推理依据>
  2. <步骤...>
  ...（覆盖从入手到拿到 flag 的完整链路，命令需可复制执行）]

规则：
- 优先并发只读采集（ACTIONS 多个只读工具同时跑），再统一思考
- 未侦察前不要凭题目字面猜类别并硬路由到某个 agent；先侦察再分类
- 仅当子任务需独立多步深挖或输出较大时才 DELEGATE 给已有 agent
- 仅当任务不落进任一预设 agent 类别、且需要独立深挖时，才 SPAWN_AGENT 自定义通用 agent（id 须唯一、toolNames 必须来自上方可用工具），随后 DELEGATE 给它
- 工具调用格式必须为 工具名(JSON参数)
- 解题/分析类任务的 FINAL_ANSWER 必须含 Flag + 可手动复现的逐步 Writeup（每步写清：操作、观察、推理）；简单问答可直接回答`;

    // ── 流式输出：逐 token emit thinking delta，完成后解析完整文本 ──
    const streamResult = streamText({
      model,
      prompt,
      ...(signal ? { abortSignal: signal } : {}),
    });

    let text = "";
    for await (const delta of streamResult.textStream) {
      text += delta;
      // 逐段 emit，CLI 端实时打印
      this.emitEvent({ type: "thinking", step, delta });
    }
    throwIfAborted();

    const { thought, plan, actions, delegates, spawnAgents, finalAnswer } =
      parseMainReactResponse(text);

    if (thought) this.emitEvent({ type: "thought", step, thought });

    if (finalAnswer) {
      // ============================================================
      // CTF 任务 final answer 前置检查：
      //   若 finalAnswer 写了 "Flag: 无" 或没有出现可验证的 flag 格式，
      //   且用户任务/历史中出现过 CTF 相关关键词（flag/ctf/pwn/附件/题目 等），
      //   则不提交 final，改为把 self-reflection 观察写入上下文，
      //   让 LLM 下一轮继续 debug 迭代（直到工具 [FLAG FOUND] 被检测到）。
      // ============================================================
      const guard = validateCTFFinalAnswer(finalAnswer, userTask, historyText, summary || "");
      if (!guard.ok) {
        // 把校验失败 + 具体的 debug 建议写进上下文，相当于强制一轮 self-reflection
        this.steps.push({
          step,
          action: "FINAL_ANSWER_GUARD",
          thought,
          observation: guard.reason + "\n" + guard.hint,
        });
        await this.contextManager.addMessagesBatch([
          { role: "assistant", content: `[计划]\n${plan || ""}\n\n[思考]\n${thought || ""}\n\n[尝试的 FINAL_ANSWER]\n${finalAnswer}\n\n[系统校验：不通过]\n${guard.reason}\n\n[请按以下调试建议继续迭代（不要 FINAL_ANSWER 交卷）]\n${guard.hint}` },
          { role: "user", content:
`收到。请不要直接 FINAL_ANSWER，而是基于上一轮的执行结果做下一轮迭代调试：
1. 重新精读最近 2~3 条工具结果的末尾（特别是 bytes 尾部、[NO FLAG FOUND]、[FLAG FOUND] 行），判断上一轮 exploit 为什么没触发 win
2. 用 pwn_run_exploit 调试：调整偏移、写入字节数、cat flag 命令、sleep 时间
3. 有条件本地调试的，先本地确认 payload 正确性再打远程
4. 只有当工具输出里出现明确的 [FLAG FOUND] 或 flag{xxx}/ctfhub{xxx} 完整匹配时才能 FINAL_ANSWER 交卷` },
        ]);
        this.emitEvent({ type: "thought", step, thought: "⚠️  Flag 校验未通过：" + guard.reason + " 继续下一轮 debug。" });
        return { isComplete: false, needsMoreInfo: false, answer: "" };
      }

      this.emitEvent({ type: "finalAnswer", step, answer: finalAnswer });
      this.steps.push({
        step,
        action: "FINAL_ANSWER",
        thought,
        observation: finalAnswer,
      });
      return { isComplete: true, needsMoreInfo: false, answer: finalAnswer };
    }

    const hasActions = actions.length > 0;
    const hasDelegates = delegates.length > 0;
    const hasSpawn = spawnAgents.length > 0;
    const hasPlan = !!plan;

    // 无任何可推进内容 → NO_ACTION
    if (!hasPlan && !hasActions && !hasDelegates && !hasSpawn) {
      this.steps.push({
        step,
        action: "NO_ACTION",
        thought,
        observation: "无法解析的响应，继续下一步",
      });
      await this.contextManager.addMessagesBatch([
        { role: "assistant", content: thought || "(无有效输出)" },
      ]);
      return { isComplete: false, needsMoreInfo: false, answer: "" };
    }

    // PLAN / 工具采集 / 子智能体委派可同时推进，结果统一落库供下一步思考
    const observations: Array<Omit<Message, "timestamp" | "tokenCount">> = [];

    // 记录 PLAN（若有），写入上下文供后续步骤参考策略
    if (hasPlan) {
      const isMultiStep = this.isMultiStepPlan(
        plan,
        actions.length,
        delegates.length
      );
      this.emitEvent({ type: "plan", step, plan, isMultiStep });

      // 多步骤 Plan 门控：等待用户确认后再执行
      if (isMultiStep && this.confirmPlanFn) {
        const confirmed = await this.confirmPlanFn(plan, step);
        this.emitEvent({ type: "planConfirmed", step, confirmed });
        if (!confirmed) {
          this.steps.push({
            step,
            action: "PLAN_CANCELLED",
            thought,
            observation: "用户取消执行计划",
            plan,
          });
          await this.contextManager.addMessagesBatch([
            { role: "assistant", content: `[PLAN 取消] ${plan}` },
          ]);
          return {
            isComplete: true,
            needsMoreInfo: false,
            answer: "用户已取消该计划。",
            cancelled: true,
          };
        }
      }

      this.steps.push({
        step,
        action: "PLAN",
        thought,
        observation: plan,
        plan,
      });
      observations.push({ role: "assistant", content: `[PLAN] ${plan}` });
    }

    // 先注册动态 agent（若有），使其本轮即可被 DELEGATE
    // 注册失败记为观察，不阻断其余 actions/delegates
    if (hasSpawn) {
      for (const sp of spawnAgents) {
        try {
          this.scheduler.registerDynamicAgent(sp);
          this.emitEvent({
            type: "spawnAgent",
            step,
            config: sp,
            success: true,
          });
          this.steps.push({
            step,
            action: `SPAWN_AGENT → ${sp.id}`,
            thought,
            observation: `role=${sp.role}, tools=${sp.toolNames.join(", ")}`,
          });
        } catch (err: any) {
          this.emitEvent({
            type: "spawnAgent",
            step,
            config: sp,
            success: false,
            message: err.message,
          });
          this.steps.push({
            step,
            action: `SPAWN_AGENT → ${sp.id}`,
            thought,
            observation: `[注册失败] ${err.message}`,
          });
          observations.push({
            role: "assistant",
            content: `[动态注册失败] ${sp.id}: ${err.message}`,
          });
        }
      }
    }

    if (hasActions) this.emitEvent({ type: "actionStart", step, actions });
    if (hasDelegates)
      this.emitEvent({ type: "delegateStart", step, agents: delegates });

    const actionTask: Promise<ActionResult[]> = hasActions
      ? this.toolExecutor
        ? this.toolExecutor.executeBatch(actions, { signal, toolTimeoutMs })
        : this.fallbackExecuteBatch(actions, { signal })
      : Promise.resolve<ActionResult[]>([]);
    const delegateTask: Promise<DispatchResult[]> = hasDelegates
      ? this.scheduler.dispatchConcurrent(
          delegates.map((agentId) => ({
            agentId,
            task: this.buildDelegateTask(thought, userTask),
          }))
        )
      : Promise.resolve<DispatchResult[]>([]);

    // 包装取消：signal 触发时立即 reject，避免 Promise.all 永久挂住
    const withCancel = async <T>(p: Promise<T>): Promise<T> => {
      if (!signal) return p;
      if (signal.aborted) {
        throw signal.reason instanceof Error ? signal.reason : new Error("Task aborted");
      }
      let rejectOnAbort: (e: Error) => void = () => {};
      const abortP = new Promise<never>((_, rej) => {
        rejectOnAbort = (e) => rej(e);
      });
      const onAbort = () => {
        rejectOnAbort(
          signal!.reason instanceof Error
            ? (signal!.reason as Error)
            : new Error("Task aborted")
        );
      };
      signal.addEventListener("abort", onAbort, { once: true });
      try {
        return await Promise.race([p, abortP]);
      } finally {
        signal.removeEventListener("abort", onAbort);
      }
    };

    const [actionResults, delegateResults] = await Promise.all([
      withCancel(actionTask),
      withCancel(delegateTask),
    ]);
    throwIfAborted();

    if (hasActions)
      this.emitEvent({ type: "actionEnd", step, results: actionResults });
    if (hasDelegates)
      this.emitEvent({
        type: "delegateEnd",
        step,
        results: delegateResults,
      });

    for (const r of actionResults) {
      this.steps.push({
        step,
        action: `TOOL: ${r.toolName}(${JSON.stringify(r.toolArgs)})`,
        thought,
        observation: r.result,
      });
      observations.push({
        role: "tool",
        content: `[${r.toolName}] ${JSON.stringify(r.toolArgs)} → ${r.result}`,
      });
    }
    for (const d of delegateResults) {
      this.steps.push({
        step,
        action: `DELEGATE → ${d.agentId}`,
        thought,
        observation: d.result,
        agentId: d.agentId,
      });
      observations.push({
        role: "assistant",
        content: `[调度给 ${d.agentId}] ${thought} → ${d.result}`,
      });
    }

    await this.contextManager.addMessagesBatch(observations);
    return { isComplete: false, needsMoreInfo: false, answer: "" };
  }

  /** toolExecutor 缺失时的回退执行（串行） */
  private async fallbackExecuteBatch(
    actions: PlannedAction[],
    opts?: { signal?: AbortSignal }
  ): Promise<ActionResult[]> {
    const signal = opts?.signal;
    const results: ActionResult[] = [];
    for (const a of actions) {
      if (signal?.aborted) {
        throw signal.reason instanceof Error ? signal.reason : new Error("Task aborted");
      }
      try {
        const result = await this.toolRegistry.execute(a.toolName, a.toolArgs);
        results.push({
          toolName: a.toolName,
          toolArgs: a.toolArgs,
          success: true,
          result,
        });
      } catch (err: any) {
        results.push({
          toolName: a.toolName,
          toolArgs: a.toolArgs,
          success: false,
          result: `工具执行失败: ${err.message}`,
        });
      }
    }
    return results;
  }

  /** 构造给子智能体的任务（含主控思考与原始任务上下文） */
  private buildDelegateTask(thought: string, userTask: string): string {
    return `${thought}\n\n[原始任务上下文] ${userTask}`;
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