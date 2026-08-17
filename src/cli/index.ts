#!/usr/bin/env node

import readline from "readline";
import { getLLMConfig, setLLMConfig, listAvailableModels } from "../llm/client";
import { writeGlobalConfig, type Platform } from "../config/global-config";
import { createAgentSystem, type AgentSystem } from "../agents/factory";
import { createToolRegistry } from "../tools/factory";
import { SessionManager } from "../session/session-manager";
import type { AgentEvent } from "../agents/agent-events";
import {
  getBackgroundManager,
  type BackgroundTaskSnapshot,
  type BackgroundManager,
} from "../agents/background-manager";

// 兼容旧 import 路径（tests 仍从 dist/cli/index 取 createAgentSystem / createToolRegistry）
export { createAgentSystem, createToolRegistry, type AgentSystem };

/**
 * LLM API 错误分类结果。纯函数，无运行时依赖，便于单测。
 * tips 中的 {model} / {baseUrl} 占位符由调用方（CLI）用 getLLMConfig() 替换。
 */
export interface LLMErrorDiagnosis {
  kind: "arrearage" | "quota" | "auth" | "model" | "network" | "unknown";
  tag: string;
  detail: string;
  tips: string[];
}

/**
 * 识别 LLM API 级错误（欠费/额度/鉴权/模型不支持/网络），返回可操作诊断。
 * ai-sdk 的 APICallError: message 仅是 HTTP 描述(如"Bad Request")，真实业务信息在 responseBody。
 */
export function classifyLLMError(error: any): LLMErrorDiagnosis {
  const httpMsg = String(error && error.message ? error.message : error);
  const statusCode = Number(error && error.statusCode) || 0;
  let bodyCode = "";
  let bodyMsg = "";
  const rawBody = error && error.responseBody ? String(error.responseBody) : "";
  if (rawBody) {
    try {
      const parsed = JSON.parse(rawBody);
      bodyCode = parsed && parsed.code ? String(parsed.code) : "";
      bodyMsg = parsed && parsed.message ? String(parsed.message) : "";
    } catch {
      bodyMsg = rawBody.slice(0, 300);
    }
  }
  const fullText = (httpMsg + " " + bodyCode + " " + bodyMsg + " " + (error && error.data ? String(error.data) : "")).toLowerCase();
  const detail = bodyMsg ? (bodyCode ? "[" + bodyCode + "] " + bodyMsg : bodyMsg) : httpMsg;

  const isArrearage =
    bodyCode.toLowerCase().includes("arrearage") ||
    fullText.includes("arrearage") ||
    fullText.includes("in good standing") ||
    fullText.includes("overdue") ||
    fullText.includes("欠费") ||
    fullText.includes("结清");
  if (isArrearage) {
    return {
      kind: "arrearage",
      tag: "💳 LLM 账户欠费（Arrearage）",
      detail,
      tips: [
        "1) 阿里云费用账单结清欠费（欠费会导致所有模型 400 拦截）",
        "2) 错误说明与充值指引: https://help.aliyun.com/zh/model-studio/error-code#overdue-payment",
        "3) 结清后稍等几分钟生效，再重试；或 /model 切换到免费额度内的模型",
        "4) /platform qianwen|bailian 切换端点（两个平台计费独立，可能其一未欠费）",
      ],
    };
  }
  const isQuota =
    fullText.includes("forbidden") ||
    fullText.includes("quota") ||
    fullText.includes("permission_denied") ||
    fullText.includes("free quota exhausted") ||
    statusCode === 403 ||
    statusCode === 429;
  if (isQuota) {
    return {
      kind: "quota",
      tag: "🔒 LLM 访问受限（额度/权限/频率）",
      detail,
      tips: [
        '1) 阿里云控制台 / 百炼工作台：充值或关闭"仅使用免费额度"',
        "2) /model 列出可用模型，切到其他已开通 PTU/按量的模型",
        "3) /platform qianwen (或 /platform bailian) 切换端点，可能可用额度不同",
        "4) 检查 key 是否归属正确阿里云账号下的工作空间",
      ],
    };
  }
  const isAuth =
    fullText.includes("authentication") ||
    fullText.includes("invalid api") ||
    fullText.includes("unauthorized") ||
    statusCode === 401;
  if (isAuth) {
    return {
      kind: "auth",
      tag: "🔐 LLM 鉴权失败（API Key）",
      detail,
      tips: [
        "1) 环境变量 DASHSCOPE_API_KEY 是否设置（CLI 全局安装需手动 export）",
        "2) Key 是否启用、未吊销、非空字符串",
        "3) VSCode: 设置 flagent.apiKey 并重载（命令 > Flagent: Reload LLM Config）",
      ],
    };
  }
  const isModelUnsupported =
    (statusCode === 400 || statusCode === 404) &&
    (fullText.includes("model") || fullText.includes("not found") || fullText.includes("does not exist") || fullText.includes("unsupported"));
  if (isModelUnsupported) {
    return {
      kind: "model",
      tag: "🤖 LLM 模型不可用",
      detail,
      tips: [
        "1) /model 查看可用模型列表，当前 {model} 可能在该平台未开通/已下线",
        "2) /platform 切换平台后重试（千问与百炼支持的模型集合不同）",
        "3) 阿里云控制台确认该模型已申请开通/开通按量付费",
      ],
    };
  }
  const isNetwork =
    fullText.includes("network") ||
    fullText.includes("econn") ||
    fullText.includes("fetch failed") ||
    fullText.includes("timeout") ||
    fullText.includes("etimedout");
  if (isNetwork) {
    return {
      kind: "network",
      tag: "🌐 LLM 调用网络问题",
      detail,
      tips: [
        "1) 本机是否能联网: curl -I {baseUrl}",
        "2) 是否走代理；必要时 HTTPS_PROXY=http://proxy:port 开启",
        "3) 百炼平台 workspaceId 是否正确且该工作空间已开通网络出网",
      ],
    };
  }
  return { kind: "unknown", tag: "", detail, tips: [] };
}

/** 启动 BANNER：动态读 getLLMConfig()，反映 platform/model/workspace/key 当前态。 */
function renderBanner(): string {
  const cfg = getLLMConfig();
  let platformLabel: string = cfg.platform;
  switch (cfg.platform) {
    case "qianwen": platformLabel = "千问平台 (DashScope)"; break;
    case "bailian": platformLabel = "百炼平台 (Bailian Workspace)"; break;
    case "anthropic": platformLabel = "Anthropic API"; break;
  }
  const ws =
    cfg.platform === "bailian" && cfg.workspaceId ? cfg.workspaceId :
    cfg.platform === "anthropic" ? "(不适用)" : "(无)";
  return `
╔══════════════════════════════════════════════════════════════╗
║                    Flagent Multi-Agent System                ║
║                    多智能体CTF协作系统                       ║
╠══════════════════════════════════════════════════════════════╣
║  Platform: ${platformLabel.padEnd(51)}  ║
║  Model:    ${cfg.modelName.padEnd(51)}  ║
║  Workspace:${ws.padEnd(51)}  ║
║  API Key:  ${(cfg.apiKey ? "✓ 已配置" : "✗ 未配置").padEnd(51)}  ║
╚══════════════════════════════════════════════════════════════╝`;
}

const HELP_TEXT = `
会话管理（每会话独立上下文/权限/动态 agent，可同时分析多题）:
  /new [标题]        新建会话并切为活动（标题可选）
  /sessions          列出所有会话（标记当前活动会话）
  /switch <id>       切换到指定会话（不在内存则从磁盘恢复）
  /delete <id>       删除指定会话（内存 + 磁盘）
  /title [标题]      查看或设置当前会话标题

后台任务（长时间分析在后台跑，前台可继续工作/定时轮询）:
  /bgstart <任务>    后台启动任务（立即返回 taskId，不阻塞前台），事件仍实时打印
  /bg                列出所有后台任务及其状态（PENDING/RUNNING/STUCK/...）
  /status [id]       查看单个任务详细健康状态（步数/最近活动/空闲时长）
  /kill <id>         取消指定后台任务（AbortSignal 下发到 LLM + 工具）

LLM 配置（全局，写入 ~/.flagent/config.json，重启后生效）:
  /platform [平台]   切换平台（qianwen 千问 / bailian 百炼 / anthropic）；无参显示当前
  /model [名称]      列出可用模型或切换模型（/model <name>）；切换写回全局配置

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
  - 后台任务每 30s 自动打印健康摘要；长时间无活动会被标记 WARNING 或 STUCK，可 /kill 取消
  - Ctrl+C：中断当前思考/工具执行；快速双击 Ctrl+C 退出 CLI
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

/**
 * 思考流节流缓冲：累积 thinking delta，按固定间隔批量 flush，避免逐 token
 * 直接写 stdout 造成的卡顿感。首块立即 flush（让用户尽快看到开始思考），
 * 之后每 flushIntervalMs 毫秒 flush 一次；调用 flushNow() 在流结束/切换阶段
 * 时强制清空残余。
 */
class ThinkingBuffer {
  private buf = "";
  private timer: NodeJS.Timeout | null = null;
  private started = false;
  constructor(
    private readonly writer: (text: string) => void,
    private readonly flushIntervalMs = 1000,
  ) {}

  /** 写入一个 delta 片段。首块立即 flush，之后启动定时器。 */
  push(delta: string): void {
    if (!delta) return;
    this.buf += delta;
    if (!this.started) {
      this.started = true;
      this.flushNow();
      this.timer = setInterval(() => this.flushNow(), this.flushIntervalMs);
    }
  }

  /** 强制清空缓冲并停止定时器（流结束 / 阶段切换时调用）。 */
  flushNow(): void {
    if (this.buf) {
      this.writer(this.buf);
      this.buf = "";
    }
  }

  /** 彻底停止：flush 残余 + 清定时器，回到未启动状态，可复用。 */
  reset(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.flushNow();
    this.started = false;
  }
}

/**
 * 终端旋转 spinner（Braille 帧），无第三方依赖。在思考/工具执行等阶段
 * 显示动态指示，替代静态文字。与思考流输出互斥：流式 delta 开始后应 stop()。
 */
class Spinner {
  private static readonly FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
  private timer: NodeJS.Timeout | null = null;
  private frameIdx = 0;
  private prefix = "";
  private active = false;

  /** 启动 spinner，prefix 为前缀文案（如 "思考中" / "执行 http_request"）。 */
  start(prefix: string): void {
    if (this.active) {
      // 已在转：仅更新文案
      this.prefix = prefix;
      return;
    }
    this.active = true;
    this.prefix = prefix;
    this.frameIdx = 0;
    this.render();
    this.timer = setInterval(() => {
      this.frameIdx = (this.frameIdx + 1) % Spinner.FRAMES.length;
      this.render();
    }, 120);
  }

  /** 更新文案但不重启。 */
  update(prefix: string): void {
    if (this.active) this.prefix = prefix;
  }

  private render(): void {
    const frame = Spinner.FRAMES[this.frameIdx];
    process.stdout.write(`\r${frame} ${this.prefix}`);
  }

  /** 停止并清除当前行。 */
  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    if (this.active) {
      process.stdout.write("\r\x1b[K"); // 回到行首并清行
    }
    this.active = false;
  }
}

/**
 * 通用上下键选择器：暂停 readline 行模式，切 stdin 到 raw 模式捕获方向键，
 * 渲染可滚动菜单，Enter 确认 / Ctrl+C 取消。支持任意数量选项，每项可带描述。
 *
 * 后续 Plan 门控、权限确认、多分支问题都可复用，避免逐字输入 y/n。
 *
 * @param title   菜单标题（单行，必填）
 * @param options 选项数组：label 为正文，desc 为可选灰色说明
 * @param opts    initialIdx 初始高亮项；cancelIdx 取消时返回该项索引（默认 0）
 * @returns       选中项索引；Ctrl+C / Esc 返回 cancelIdx
 */
async function selectPrompt(
  title: string,
  options: { label: string; desc?: string }[],
  rl: readline.Interface,
  opts: { initialIdx?: number; cancelIdx?: number } = {},
): Promise<number> {
  const initialIdx = opts.initialIdx ?? 0;
  const cancelIdx = opts.cancelIdx ?? 0;
  if (options.length === 0) return 0;

  // 非 TTY（管道/重定向）无法捕获方向键 → 退化为打印首项并返回
  if (!process.stdin.isTTY) {
    console.log(`\n${title}`);
    console.log(`  (非交互环境，默认选择: ${options[initialIdx].label})`);
    return initialIdx;
  }

  return new Promise<number>((resolve) => {
    let idx = Math.max(0, Math.min(initialIdx, options.length - 1));
    let settled = false;
    let wasRaw = false;
    // 本菜单已渲染的行数（标题+空行+各选项）。重绘时按此上移，保证回到首行。
    let renderedLines = 0;

    const finish = (val: number): void => {
      if (settled) return;
      settled = true;
      process.stdin.removeListener("data", onData);
      process.stdin.removeListener("end", onEnd);
      // 恢复 raw 模式：仅当进入前不是 raw 时才关回行模式
      if (!wasRaw && process.stdin.setRawMode) process.stdin.setRawMode(false);
      process.stdin.resume();
      // 让 readline 重新接管行模式输入
      rl.resume();
      // 清掉整块菜单渲染（标题+空行+选项），回到菜单首行
      if (renderedLines > 0) {
        process.stdout.write(`\x1b[${renderedLines}A`);
        for (let i = 0; i < renderedLines; i++) {
          process.stdout.write("\r\x1b[K\n");
        }
        // 上移回去，让光标停在菜单块首行（供调用方覆盖输出结果）
        process.stdout.write(`\x1b[${renderedLines}A`);
      }
      resolve(val);
    };

    const render = (): void => {
      // 若已渲染过，先把光标移回首行再逐行重绘（每行 \r\x1b[K 清整行，杜绝残留）
      if (renderedLines > 0) {
        process.stdout.write(`\x1b[${renderedLines}A`);
      }
      const out: string[] = [];
      out.push(""); // 标题上方空行（与下方 label 对齐美观）
      // title 可能含 \n（如权限确认的多行标题），按实际行数展开
      for (const tLine of title.split("\n")) out.push(tLine);
      options.forEach((o, i) => {
        const arrow = i === idx ? "❯" : " ";
        const label = i === idx ? `\x1b[36m${o.label}\x1b[0m` : o.label;
        const desc = o.desc ? `  \x1b[2m${o.desc}\x1b[0m` : "";
        out.push(`  ${arrow} ${label}${desc}`);
      });
      renderedLines = out.length;
      for (const line of out) {
        process.stdout.write(`\r\x1b[K${line}\n`);
      }
    };

    const onData = (buf: Buffer): void => {
      const s = buf.toString();
      // 方向键以 ESC(0x1b) 起头的三字节序列
      if (s === "\x1b[A" || s === "k") {
        // 上
        idx = (idx - 1 + options.length) % options.length;
        render();
      } else if (s === "\x1b[B" || s === "j") {
        // 下
        idx = (idx + 1) % options.length;
        render();
      } else if (s === "\r" || s === "\n") {
        // Enter 确认
        finish(idx);
      } else if (s === "\x03") {
        // Ctrl+C 取消
        finish(cancelIdx);
      } else if (s === "\x1b") {
        // 单独 Esc 取消
        finish(cancelIdx);
      } else if (s === "y" || s === "Y") {
        // y/n 快捷：首个 label 含"是/允许/确认"视为 yes
        const yesIdx = options.findIndex((o) => /是|允许|确认|执行|继续/.test(o.label));
        finish(yesIdx >= 0 ? yesIdx : 0);
      } else if (s === "n" || s === "N") {
        const noIdx = options.findIndex((o) => /否|拒绝|取消|停止|放弃/.test(o.label));
        finish(noIdx >= 0 ? noIdx : options.length - 1);
      }
    };

    const onEnd = (): void => finish(cancelIdx);

    // 暂停 readline 行模式，接管 stdin
    rl.pause();
    // 先记录进入前的 raw 状态，再开启 raw（顺序不能反）
    wasRaw = Boolean(process.stdin.isRaw);
    if (process.stdin.setRawMode) process.stdin.setRawMode(true);
    process.stdin.resume();

    // 首次渲染：renderedLines=0 不上移，直接画出标题+菜单
    render();

    process.stdin.on("data", onData);
    process.stdin.on("end", onEnd);
  });
}

/** y/n 二选一封装：返回 true=是，false=否。Ctrl+C 视为否。 */
async function confirmYesNo(
  title: string,
  rl: readline.Interface,
  yesLabel = "是，允许",
  noLabel = "否，取消",
  opts: { defaultYes?: boolean } = {},
): Promise<boolean> {
  const initialIdx = opts.defaultYes ? 0 : 1;
  const picked = await selectPrompt(title, [
    { label: yesLabel, desc: "Enter 确认" },
    { label: noLabel, desc: "或 Ctrl+C" },
  ], rl, { initialIdx, cancelIdx: 1 });
  return picked === 0;
}

/** 把毫秒转成人读的时长。 */
function fmtDuration(ms: number | null): string {
  if (ms == null || !isFinite(ms) || ms < 0) return "-";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rs = s % 60;
  if (m < 60) return `${m}m${rs}s`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return `${h}h${rm}m`;
}

/** 后台任务单行摘要（供 /bg 与 30s 健康摘要复用）。 */
function formatTaskSummary(
  t: BackgroundTaskSnapshot & { health?: "HEALTHY" | "WARNING" | "STUCK" | "IDLE" }
): string {
  const stepStr =
    t.currentStep != null
      ? `Step ${t.currentStep}${t.maxSteps ? `/${t.maxSteps}` : ""}`
      : "未启动";
  const healthBadge =
    t.health === "STUCK" ? " 🔴STUCK" :
    t.health === "WARNING" ? " 🟡WARNING" :
    t.health === "HEALTHY" ? " 🟢" :
    "";
  const statusBadge =
    t.status === "RUNNING" ? "🏃RUNNING" :
    t.status === "COMPLETED" ? "✅COMPLETED" :
    t.status === "CRASHED" ? "💥CRASHED" :
    t.status === "CANCELLED" ? "🛑CANCELLED" :
    t.status === "STUCK" ? "🔴STUCK" :
    t.status === "PENDING" ? "⏳PENDING" :
    t.status;
  const tail =
    t.status === "COMPLETED"
      ? ` | 结果: ${t.result?.success ? "成功" : "未完成"}`
      : t.status === "CRASHED" && t.error
      ? ` | 错误: ${t.error.slice(0, 60)}`
      : t.idleMs != null
      ? ` | 空闲: ${fmtDuration(t.idleMs)}`
      : "";
  return (
    `  • ${t.taskId.slice(0, 10).padEnd(12)} ${statusBadge.padEnd(13)}` +
    ` ${stepStr.padEnd(12)}` +
    `${healthBadge}  ${shortTitle(t.title).padEnd(28)}` +
    tail
  );
}

/** 单个任务的详细健康信息打印。 */
function printTaskDetail(
  t: BackgroundTaskSnapshot & { health?: "HEALTHY" | "WARNING" | "STUCK" | "IDLE" }
): void {
  console.log(`\n  任务 ${t.taskId}`);
  console.log(`    会话:       ${t.sessionId.slice(0, 12)}`);
  console.log(`    标题:       ${t.title || "(未命名)"}`);
  console.log(`    状态:       ${t.status}` +
    (t.health ? ` (健康=${t.health})` : ""));
  console.log(`    创建时间:   ${fmtTime(t.createdAt)}`);
  console.log(`    启动时间:   ${t.startedAt ? fmtTime(t.startedAt) : "(未启动)"}`);
  console.log(`    结束时间:   ${t.endedAt ? fmtTime(t.endedAt) : "-"}`);
  console.log(`    最近活动:   ${t.lastActivityAt ? fmtTime(t.lastActivityAt) + " (" + fmtDuration(t.idleMs) + "前)" : "-"}`);
  console.log(`    当前步数:   ${t.currentStep != null ? t.currentStep + (t.maxSteps ? ` / ${t.maxSteps}` : "") : "(未启动)"}`);
  console.log(`    任务预览:   ${t.taskPreview}`);
  if (t.status === "COMPLETED") {
    console.log(`    完成: success=${t.result?.success}, tokens=${t.result?.totalTokens ?? "-"}`);
    if (t.result?.finalAnswer) {
      console.log(`    FinalAnswer 首行: ${t.result.finalAnswer.split("\n")[0].slice(0, 160)}`);
    }
  }
  if (t.status === "CRASHED") {
    console.log(`    崩溃错误: ${t.error}`);
  }
}

export async function startCLI(): Promise<void> {
  console.log(renderBanner());

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
    const title = `⚠️  权限请求: 工具 "${toolName}" 参数 ${argStr}\n    允许执行? [本会话记忆]`;
    return confirmYesNo(title, rl, "是，允许执行", "否，拒绝", { defaultYes: false });
  };

  const toolRegistry = createToolRegistry();
  const sessionManager = new SessionManager({ toolRegistry, confirmFn });
  let mainAgentRunning = false; // run 期间：新输入被提示等待（前台优先，不自动挤转后台）
  let verbose = false; // /verbose 切换：默认精简，开启后显示完整思考与工具结果

  // --- Ctrl+C 交互：单次中断当前运行，快速双击退出 ---
  let currentAbortController: AbortController | null = null;
  let lastSigintTime = 0;
  const SIGINT_DOUBLE_THRESHOLD = 500; // ms：500ms 内两次 Ctrl+C 视为退出

  rl.on("SIGINT", () => {
    const now = Date.now();

    // 正在运行 → 中断当前任务
    if (mainAgentRunning && currentAbortController) {
      currentAbortController.abort(new Error("用户中断 (Ctrl+C)"));
      console.log("\n\n⚡ 已中断当前任务（再按 Ctrl+C 退出 CLI）。\n");
      lastSigintTime = now;
      return;
    }

    // 非运行态 / 已中断后快速双击 → 退出（只调 rl.close()，告别由 close 事件统一打印，避免重复）
    if (now - lastSigintTime < SIGINT_DOUBLE_THRESHOLD) {
      rl.close();
      return;
    }

    // 非运行态首次 → 提示再按一次退出
    lastSigintTime = now;
    console.log("\n  (再按 Ctrl+C 退出 CLI，或输入问题继续对话)");
    rl.prompt();
  });

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

  // --- 30 秒一次后台任务健康自动轮询 ---
  // 仅在有 RUNNING / STUCK / WARNING 的任务时才打印，避免刷屏。
  const HEALTH_INTERVAL_MS = 30 * 1000;
  let lastSeenFinalStates = new Set<string>(); // 已经通知过的 COMPLETED/CRASHED/CANCELLED 任务（避免反复刷）
  const healthTimer = setInterval(() => {
    try {
      const reports = getBackgroundManager().healthCheck();
      const active = reports.filter(
        (t) => t.status === "RUNNING" || t.status === "STUCK"
      );
      const newlyFinal = reports.filter(
        (t) =>
          (t.status === "COMPLETED" || t.status === "CRASHED" || t.status === "CANCELLED") &&
          !lastSeenFinalStates.has(t.taskId)
      );
      for (const t of newlyFinal) lastSeenFinalStates.add(t.taskId);
      if (active.length === 0 && newlyFinal.length === 0) return;

      const lines: string[] = [];
      lines.push("\n" + "─".repeat(60));
      lines.push(`⏰ 后台健康摘要 (${new Date().toLocaleTimeString()})`);
      if (active.length > 0) {
        lines.push("  活跃任务:");
        for (const t of active) lines.push(formatTaskSummary(t));
      }
      if (newlyFinal.length > 0) {
        lines.push("  刚刚结束的任务:");
        for (const t of newlyFinal) lines.push(formatTaskSummary(t));
      }
      lines.push("─".repeat(60));
      console.log(lines.join("\n"));
      // 重新显示提示行（prompt 已被打断）
      try { rl.prompt(); } catch {}
    } catch (e: any) {
      // 健康检查自身异常不能把 CLI 崩了
      try { console.warn("[健康检查异常]", e && e.message ? e.message : e); } catch {}
    }
  }, HEALTH_INTERVAL_MS);
  healthTimer.unref(); // 不阻塞进程退出

  // 结束时清理已结束 >1h 的任务（不阻塞启动）
  try { getBackgroundManager().cleanup(60 * 60 * 1000); } catch {}

  refreshPrompt();
  rl.prompt();

  rl.on("line", async (line: string) => {
    const input = line.trim();

    // 前台任务运行中：不挤转后台，提示用户等待或用 /bgstart 起独立后台任务。
    // 理由：自动挤转会让正在思考的任务过早进后台、用户失去观察；
    //       前台优先 + 主动 /bgstart 是更简单清晰的模型。
    if (mainAgentRunning) {
      console.log(
        "\n⏳ 当前任务正在前台运行中。等待完成即可继续；" +
        "若需并行，用 /bgstart <任务> 起独立后台任务，用 /status 查看进度。\n"
      );
      rl.prompt();
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

    // /platform [qianwen|bailian|anthropic] —— 切换平台，写回全局配置
    if (input === "/platform" || input.startsWith("/platform ")) {
      const arg = input.slice(9).trim().toLowerCase();
      if (!arg) {
        const cfg = getLLMConfig();
        let label: string = cfg.platform;
        switch (cfg.platform) {
          case "qianwen": label = "千问 (DashScope)"; break;
          case "bailian": label = "百炼 (Workspace)"; break;
          case "anthropic": label = "Anthropic (OpenAI 兼容)"; break;
        }
        console.log(`\n🖥️  当前平台: ${label}`);
        console.log(`  baseUrl: ${cfg.baseUrl}`);
        console.log(`  切换: /platform qianwen  或  /platform bailian  或  /platform anthropic`);
        console.log(
          `  - 千问: https://dashscope.aliyuncs.com/compatible-mode/v1（无需 workspaceId）`
        );
        console.log(
          `  - 百炼: https://{workspaceId}.cn-beijing.maas.aliyuncs.com/...（需 workspaceId）`
        );
        console.log(
          `  - Anthropic: https://api.anthropic.com/v1（支持 claude-* 系列，ANTHROPIC_API_KEY 优先识别）`
        );
      } else if (arg === "qianwen" || arg === "bailian" || arg === "anthropic") {
        setLLMConfig({ platform: arg as Platform });
        writeGlobalConfig({ platform: arg as Platform });
        const cfg = getLLMConfig();
        let label = arg;
        switch (arg) {
          case "qianwen": label = "千问"; break;
          case "bailian": label = "百炼"; break;
          case "anthropic": label = "Anthropic"; break;
        }
        console.log(`\n🖥️  平台已切换: ${label}  →  默认模型: ${cfg.modelName}`);
        console.log(`  baseUrl: ${cfg.baseUrl}`);
        console.log(`  已写入全局配置 (~/.flagent/config.json)，重启后生效`);
      } else {
        console.log(`\n⚠️  用法: /platform [qianwen|bailian|anthropic]`);
      }
      rl.prompt();
      return;
    }

    // /model [名称] —— 列出可用模型或切换模型，写回全局配置
    if (input === "/model" || input.startsWith("/model ")) {
      const arg = input.slice(6).trim();
      if (!arg) {
        console.log("\n📋 正在拉取可用模型列表...");
        try {
          const models = await listAvailableModels();
          const cfg = getLLMConfig();
          // 按类别分组展示
          const byCategory = new Map<string, typeof models>();
          for (const m of models) {
            if (!byCategory.has(m.category)) byCategory.set(m.category, []);
            byCategory.get(m.category)!.push(m);
          }
          const order = ["对话", "视觉语言", "嵌入", "重排", "图像", "情感", "动作"];
          for (const cat of order) {
            const list = byCategory.get(cat);
            if (!list || list.length === 0) continue;
            console.log(`\n  【${cat}】`);
            for (const m of list) {
              const mark = m.name === cfg.modelName ? "*" : " ";
              console.log(`  ${mark} ${m.name}  [plans: ${m.plans.join("/")}]`);
            }
          }
          console.log(`\n  * = 当前模型 (${cfg.modelName})`);
          console.log(`  切换: /model <名称>（如 /model qwen-plus）`);
        } catch (err: any) {
          console.log(`\n❌ 拉取模型列表失败: ${err.message}`);
          console.log(`  可直接用 /model <名称> 切换（需已知模型名）`);
        }
      } else {
        setLLMConfig({ modelName: arg });
        writeGlobalConfig({ modelName: arg });
        const cfg = getLLMConfig();
        console.log(`\n🤖 模型已切换: ${arg}`);
        console.log(`  当前平台: ${cfg.platform}, baseUrl: ${cfg.baseUrl}`);
        console.log(`  已写入全局配置 (~/.flagent/config.json)，重启后生效`);
      }
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

    // /bgstart <任务> —— 后台启动，立即返回 taskId（不阻塞前台）
    if (input.startsWith("/bgstart ")) {
      const task = input.slice(8).trim();
      if (!task) {
        console.log("\n⚠️  用法: /bgstart <任务描述>");
        rl.prompt();
        return;
      }
      // 后台任务期间仍拦截前台 run 触发，但允许继续输入命令（mainAgentRunning 只卡普通任务）
      if (!sessionManager.current()) await sessionManager.create();
      const session = sessionManager.current()!;
      const taskBadge = " [BG]";

      /** 后台事件打印：复用 verbose 策略（与前台相同的视觉）。 */
      let bgStreamingThinking = false;
      const bgThinkingBuf = new ThinkingBuffer((text) => {
        process.stdout.write(text);
      });
      const endBgThinking = (): void => {
        bgThinkingBuf.reset();
        if (bgStreamingThinking) {
          process.stdout.write("\n");
          bgStreamingThinking = false;
        }
      };
      const onEvent = (event: AgentEvent): void => {
        switch (event.type) {
          case "stepStart":
            endBgThinking();
            if (verbose)
              console.log(`\n${taskBadge} ━━━ Step ${event.step}/${event.maxSteps} ━━━`);
            break;
          case "thinking": {
            if (!bgStreamingThinking) {
              bgStreamingThinking = true;
              process.stdout.write(`\n${taskBadge} 💭 `);
            }
            bgThinkingBuf.push(event.delta);
            break;
          }
          case "thought": {
            if (bgStreamingThinking) {
              bgThinkingBuf.flushNow();
              process.stdout.write("\n");
              bgStreamingThinking = false;
            } else if (verbose) {
              console.log(`\n${taskBadge} 💭 思考:`);
              console.log(indent(event.thought, "        "));
            } else {
              const head = event.thought.split("\n")[0];
              console.log(`\n${taskBadge} 💭 ${preview(head, 80)}`);
            }
            break;
          }
          case "plan": {
            endBgThinking();
            const tag = event.isMultiStep ? "（多步骤·待确认）" : "（单步骤·直接执行）";
            console.log(`\n${taskBadge} 📋 Plan${tag}:`);
            console.log(indent(event.plan, "       "));
            break;
          }
          case "planConfirmed":
            console.log(
              taskBadge + (event.confirmed ? " ▶️  已确认，开始执行" : " ⏹️  已取消该计划")
            );
            break;
          case "actionStart":
            endBgThinking();
            console.log(
              `${taskBadge} 🔧 执行工具: ${event.actions
                .map((a) => a.toolName).join(", ")}`
            );
            break;
          case "toolStart":
            if (verbose)
              console.log(
                `${taskBadge}    → 开始 ${event.action.toolName}(${JSON.stringify(
                  event.action.toolArgs
                )})`
              );
            break;
          case "toolEnd": {
            const r = event.result;
            const mark = r.success ? "✓" : "✗";
            const skipped = r.skipped ? "（跳过）" : "";
            console.log(`${taskBadge}    ${mark} ${r.toolName}${skipped}:`);
            console.log(indent(r.result, "           "));
            break;
          }
          case "delegateStart":
            console.log(`${taskBadge} 🤝 委派子智能体: ${event.agents.join(", ")}`);
            break;
          case "delegateEnd":
            for (const d of event.results) {
              const mark = d.success ? "✓" : "✗";
              console.log(`${taskBadge}    ${mark} ${d.agentId}:`);
              console.log(indent(d.result, "           "));
            }
            break;
          case "spawnAgent": {
            const mark = event.success ? "✓" : "✗";
            const detail = event.success
              ? `role=${event.config.role}, tools=${event.config.toolNames.join(", ")}`
              : event.message || "注册失败";
            console.log(`${taskBadge}    ${mark} SPAWN ${event.config.id}: ${detail}`);
            break;
          }
          case "finalAnswer":
            endBgThinking();
            console.log(`\n${taskBadge} ${"─".repeat(52)}`);
            console.log(`${taskBadge} ✅ 最终回答：`);
            console.log(taskBadge + " " + "─".repeat(52));
            console.log(indent(event.answer, taskBadge + "    "));
            console.log(taskBadge + " " + "─".repeat(52));
            break;
          case "complete": {
            endBgThinking();
            console.log(`\n${taskBadge} 📈 执行统计：`);
            console.log(`${taskBadge}    耗时: ${(event.duration / 1000).toFixed(1)}s`);
            console.log(`${taskBadge}    Token 数: ${event.totalTokens}`);
            console.log(
              `${taskBadge}    状态: ${event.success ? "✓ 成功" : "✗ 未完成"}\n`
            );
            break;
          }
        }
      };
      const confirmPlan = async (plan: string): Promise<boolean> => {
        if (plan && plan.trim()) {
          console.log(`\n${taskBadge} 📋 待确认的委派/计划：`);
          console.log(indent(plan, taskBadge + "      "));
        }
        const picked = await selectPrompt(
          `${taskBadge} ⏸️  是否执行?`,
          [
            { label: "执行", desc: "Enter" },
            { label: "取消", desc: "Ctrl+C" },
          ],
          rl,
          { initialIdx: 0, cancelIdx: 1 },
        );
        if (picked === 1) console.log(`${taskBadge} ⏹️  已取消该计划`);
        return picked === 0;
      };

      try {
        const taskId = session.runBackground(task, { onEvent, confirmPlan });
        console.log(`\n🚀 任务已后台启动: ${taskId}（用 /bg 查看列表，/kill ${taskId.slice(0,8)} 取消）`);
        refreshPrompt();
      } catch (err: any) {
        console.error(`\n❌ 启动后台任务失败: ${err.message}`);
      }
      rl.prompt();
      return;
    }

    // /bg —— 列出后台任务（全会话全局），附带健康检查
    if (input === "/bg") {
      const reports = getBackgroundManager().healthCheck();
      if (reports.length === 0) {
        console.log("\n📭 暂无后台任务。用 /bgstart <任务> 启动一个。");
      } else {
        console.log("\n📋 后台任务列表（附健康诊断）：");
        for (const r of reports) console.log(formatTaskSummary(r));
        console.log(`\n  详细信息: /status <taskId>；取消: /kill <taskId>`);
      }
      rl.prompt();
      return;
    }

    // /status [id] —— 查看任务详细健康信息
    if (input === "/status" || input.startsWith("/status ")) {
      const arg = input.slice(7).trim();
      const mgr = getBackgroundManager();
      const all = mgr.list();
      const pick = (id: string) =>
        all.find((t) => t.taskId === id || t.taskId.startsWith(id));
      if (!arg) {
        // 无参：打印最近 RUNNING / STUCK 的第一个详细信息；若没有就同 /bg
        const active = mgr.healthCheck().filter(
          (t) => t.status === "RUNNING" || t.status === "STUCK"
        );
        if (active.length === 0) {
          console.log("\n(无活动后台任务，列表概览:)");
          if (all.length === 0) {
            console.log("  (空)");
          } else {
            for (const r of mgr.healthCheck()) console.log(formatTaskSummary(r));
          }
        } else {
          console.log("\n📊 当前最活跃的后台任务：");
          for (const t of active.slice(0, 3)) {
            printTaskDetail(t);
          }
        }
      } else {
        const found = pick(arg);
        if (!found) {
          console.log(`\n⚠️  未找到任务: ${arg}`);
        } else {
          const health = mgr.healthCheck().find((t) => t.taskId === found.taskId);
          printTaskDetail(health ?? found);
        }
      }
      rl.prompt();
      return;
    }

    // /kill <id> —— 取消任务
    if (input.startsWith("/kill ")) {
      const arg = input.slice(5).trim();
      if (!arg) {
        console.log("\n⚠️  用法: /kill <taskId>");
      } else {
        const all = getBackgroundManager().list();
        const found = all.find(
          (t) => t.taskId === arg || t.taskId.startsWith(arg)
        );
        if (!found) {
          console.log(`\n⚠️  未找到任务: ${arg}`);
        } else {
          const ok = getBackgroundManager().cancel(found.taskId);
          console.log(
            ok
              ? `\n🛑 已取消任务: ${found.taskId.slice(0, 10)} (${shortTitle(found.title)})`
              : `\n⚠️  任务已结束，无法取消: ${found.status}`
          );
        }
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

    // ── 拦截未识别的斜杠命令：不进 LLM，直接提示 ──
    if (input.startsWith("/")) {
      const cmd = input.split(/\s+/)[0];
      // 命令用法表（cmd → 用法说明）
      const CMD_USAGE: Record<string, string> = {
        "/help": "/help",
        "/exit": "/exit",
        "/quit": "/quit",
        "/verbose": "/verbose",
        "/sessions": "/sessions",
        "/bg": "/bg",
        "/clear": "/clear",
        "/compact": "/compact",
        "/new": "/new [标题]",
        "/title": "/title [新标题]",
        "/platform": "/platform [qianwen|bailian|anthropic]",
        "/model": "/model [模型名]",
        "/switch": "/switch <id>",
        "/delete": "/delete <id>",
        "/bgstart": "/bgstart <任务描述>",
        "/status": "/status [taskId]",
        "/kill": "/kill <taskId>",
      };
      if (!(cmd in CMD_USAGE)) {
        console.log(
          `\n⚠️  未知命令: ${cmd}\n` +
          `  可用命令: ${Object.keys(CMD_USAGE).join(" ")}\n`
        );
        rl.prompt();
        return;
      }
      const extra = input.slice(cmd.length).trim();
      const usage = CMD_USAGE[cmd];
      if (extra) {
        console.log(
          `\n⚠️  命令 "${cmd}" 不接受额外参数 "${extra}"。\n` +
          `  用法: ${usage}\n`
        );
      } else {
        console.log(
          `\n⚠️  命令 "${cmd}" 用法不正确。\n` +
          `  用法: ${usage}\n`
        );
      }
      rl.prompt();
      return;
    }

    // 普通任务：经 SessionManager 执行（无活动会话则自动新建）
    // 通过 onEvent 流式输出思考/工具执行过程；多步骤 Plan 经 confirmPlan 门控
    mainAgentRunning = true;

    // ── 流式渲染辅助：spinner 动画 + 思考流 1s 节流缓冲 ──
    const spinner = new Spinner();
    /** 转后台后为 true，此后所有输出加 [BG] 前缀，复用后台任务视觉。 */
    let taskWentBackground = false;
    /**
     * 转后台后，前台 run 在 BackgroundManager 注册的"影子任务"句柄。
     * 用 holder 对象包一层，避免 TS 把 let 变量在闭包赋值后收窄成 null。
     * /status 可见、/kill 可取消（联动前台 AbortController），
     * run 结束时由下方 try/catch 标记 COMPLETED/CRASHED。
     */
    const bgHandlesRef: { current: ReturnType<BackgroundManager["createTask"]> | null } = { current: null };
    const bgBadge = () => (taskWentBackground ? " [BG]" : "");
    /** 思考缓冲：按 ~1s 批量 flush thinking delta，避免逐 token 卡顿。 */
    const thinkingBuf = new ThinkingBuffer((text) => {
      // 写入前确保 spinner 已停（thinking 流与 spinner 互斥）
      spinner.stop();
      process.stdout.write(text);
    });
    /** 当前是否在流式输出思考（控制 thought 事件是否仅关闭行）。 */
    let streamingThinking = false;
    /** 切换阶段时强制 flush 思考缓冲并关闭思考行。 */
    const endThinkingStream = (): void => {
      thinkingBuf.reset();
      if (streamingThinking) {
        process.stdout.write("\n");
        streamingThinking = false;
      }
      spinner.stop();
    };

    const onEvent = (event: AgentEvent): void => {
      // 转后台后：同步刷新影子任务心跳与 step（供 /status 显示进度）
      if (bgHandlesRef.current) {
        try { bgHandlesRef.current.onEvent(event); } catch {}
      }
      const badge = bgBadge();
      switch (event.type) {
        case "stepStart":
          endThinkingStream();
          if (verbose)
            console.log(`\n${badge} ━━━ Step ${event.step}/${event.maxSteps} ━━━`);
          spinner.start("思考中");
          break;

        case "thinking": {
          // 首个 delta → 打印行头并停止 spinner，之后通过缓冲按 1s flush
          if (!streamingThinking) {
            spinner.stop();
            streamingThinking = true;
            process.stdout.write(`\n${badge}  💭 `);
            // 首块立即 flush（ThinkingBuffer 首块即时机制）
          }
          thinkingBuf.push(event.delta);
          break;
        }

        case "thought": {
          // 流式已输出完整思考，只需 flush 残余 + 关闭行；非流式 fallback 正常打印
          if (streamingThinking) {
            thinkingBuf.flushNow();
            process.stdout.write("\n");
            streamingThinking = false;
          } else if (verbose) {
            console.log(`\n${badge}  💭 思考:`);
            console.log(indent(event.thought, badge + "      "));
          } else {
            const head = event.thought.split("\n")[0];
            console.log(`\n${badge}  💭 ${preview(head, 80)}`);
          }
          break;
        }

        case "plan": {
          endThinkingStream();
          const tag = event.isMultiStep ? "（多步骤·待确认）" : "（单步骤·直接执行）";
          console.log(`\n${badge}  📋 Plan${tag}:`);
          console.log(indent(event.plan, badge + "      "));
          break;
        }

        case "planConfirmed":
          console.log(
            badge + (event.confirmed ? "  ▶️  已确认，开始执行" : "  ⏹️  已取消该计划")
          );
          break;

        case "actionStart":
          endThinkingStream();
          console.log(
            `${badge}  🔧 执行工具: ${event.actions
              .map((a) => a.toolName)
              .join(", ")}`
          );
          break;

        case "toolStart":
          if (verbose)
            console.log(
              `${badge}      → 开始 ${event.action.toolName}(${JSON.stringify(
                event.action.toolArgs
              )})`
            );
          else
            spinner.start("执行 " + event.action.toolName);
          break;

        case "toolEnd": {
          spinner.stop();
          const r = event.result;
          const mark = r.success ? "✓" : "✗";
          const skipped = r.skipped ? "（跳过）" : "";
          // 工具结果完整打印（不截断），保留原换行 + 缩进，便于人类观察关键线索
          console.log(`${badge}      ${mark} ${r.toolName}${skipped}:`);
          console.log(indent(r.result, badge + "         "));
          break;
        }

        case "actionEnd":
          // toolEnd 已实时完整打印每个工具结果，此处不重复
          break;

        case "delegateStart":
          endThinkingStream();
          console.log(`${badge}  🤝 委派子智能体: ${event.agents.join(", ")}`);
          break;

        case "delegateEnd":
          spinner.stop();
          for (const d of event.results) {
            const mark = d.success ? "✓" : "✗";
            console.log(`${badge}      ${mark} ${d.agentId}:`);
            console.log(indent(d.result, badge + "         "));
          }
          break;

        case "spawnAgent": {
          spinner.stop();
          const mark = event.success ? "✓" : "✗";
          const detail = event.success
            ? `role=${event.config.role}, tools=${event.config.toolNames.join(", ")}`
            : event.message || "注册失败";
          console.log(`${badge}      ${mark} SPAWN ${event.config.id}: ${detail}`);
          break;
        }

        case "finalAnswer":
          endThinkingStream();
          console.log(`\n${badge} ${"─".repeat(56 - badge.length)}`);
          console.log(`${badge} ✅ 最终回答：`);
          console.log(badge + " " + "─".repeat(56 - badge.length));
          // writeup 为多行结构化内容，原样打印保留格式（避免缩进破坏编号/代码块）
          console.log(event.answer);
          console.log(badge + " " + "─".repeat(56 - badge.length));
          break;

        case "stepEnd":
          break;

        case "complete": {
          endThinkingStream();
          console.log(`\n${badge} 📈 执行统计：`);
          console.log(`${badge}    耗时: ${(event.duration / 1000).toFixed(1)}s`);
          console.log(`${badge}    Token 数: ${event.totalTokens}`);
          const statusLabel = event.success ? "✓ 成功" : "✗ 已取消/未完成";
          console.log(`${badge}    状态: ${statusLabel}\n`);
          break;
        }
      }
    };

    /**
     * 超长任务兜底：前台跑超 30min 仍未完成时，注册影子任务转到后台继续，
     * 释放前台输入。仅此一条转后台途径——新输入不再自动挤转（前台优先观察）。
     * 幂等：已转后台则直接返回。
     */
    const bumpToBackground = (reason: string): void => {
      if (taskWentBackground) return;
      taskWentBackground = true;
      // 释放前台输入拦截，让用户可继续输入命令（与 /bgstart 行为一致）
      mainAgentRunning = false;
      // 先抓住前台 AbortController 引用（下方置 null 后仍需用它联动 /kill）
      const frontController = currentAbortController;
      currentAbortController = null; // 释放中断控制权（任务继续，无法再 Ctrl+C 中断）
      endThinkingStream();

      // 在 BackgroundManager 注册"影子任务"：前台 run 仍在 await，
      // 但 /status 可见、/kill 可取消（联动前台 AbortController）。
      // run 结束时由下方 try/catch 标记 COMPLETED/CRASHED。
      try {
        const sess = sessionManager.current();
        const mgr = getBackgroundManager();
        const handles = mgr.createTask({
          sessionId: sess ? sess.id : "前台",
          title: sess && sess.title ? sess.title : input.slice(0, 60),
          task: input,
        });
        // /kill 影子任务会 abort 它自己的 controller；这里把"前台 controller"
        // 与"影子任务"双向联动：前台被中断 → 影子取消；影子被 /kill → 前台中断
        if (frontController) {
          if (frontController.signal.aborted) {
            try { mgr.cancel(handles.taskId); } catch {}
          } else {
            frontController.signal.addEventListener(
              "abort",
              () => { try { mgr.cancel(handles.taskId); } catch {} },
              { once: true }
            );
            handles.signal.addEventListener(
              "abort",
              () => { try { frontController.abort(new Error("Task cancelled by user (/kill)")); } catch {} },
              { once: true }
            );
          }
        }
        bgHandlesRef.current = handles;
        // 立即标记开始（已在跑）
        handles.markStart();
      } catch {
        bgHandlesRef.current = null; // 注册失败不影响伪后台视觉
      }

      const tid = bgHandlesRef.current ? bgHandlesRef.current.taskId.slice(0, 8) : "?";
      console.log(
        `\n${" [BG]"} ⏏️  任务已转入后台（${reason}）继续运行。`
      );
      console.log(
        `${" [BG]"}    任务完成时会自动打印结果。用 /status 查看进度（id: ${tid}），/kill ${tid} 取消。\n`
      );
      refreshPrompt();
      rl.prompt();
    };

    /** 多步骤 Plan 门控：上下键选择执行/取消；Ctrl+C 视为取消 */
    const confirmPlan = async (plan: string): Promise<boolean> => {
      if (plan && plan.trim()) {
        console.log(`\n${bgBadge()} 📋 待确认的委派/计划：`);
        console.log(indent(plan, bgBadge() + "      "));
      }
      const picked = await selectPrompt(
        `${bgBadge()} ⏸️  是否执行?`,
        [
          { label: "执行", desc: "Enter" },
          { label: "取消", desc: "Ctrl+C" },
        ],
        rl,
        { initialIdx: 0, cancelIdx: 1 },
      );
      if (picked === 1) console.log(`${bgBadge()} ⏹️  已取消该计划`);
      return picked === 0;
    };

    let runResult: Awaited<ReturnType<SessionManager["run"]>> | null = null;
    try {
      currentAbortController = new AbortController();
      runResult = await sessionManager.run(input, {
        onEvent,
        confirmPlan,
        signal: currentAbortController.signal,
        // 兜底：单任务跑超 30min 仍自动转后台，避免无限占前台。
        // 正常情况任务在前台跑到完成，用户全程观察；并行需求用 /bgstart。
        longTaskThresholdMs: 30 * 60 * 1000,
        onLongTask: () => bumpToBackground("超时兜底"),
      });
      // 转后台的任务：run 正常完成 → 标记影子任务 COMPLETED
      const bgOk = bgHandlesRef.current;
      if (bgOk) {
        const snap = getBackgroundManager().getStatus(bgOk.taskId);
        // 仅在仍处于运行态时标记完成（已被 /kill 取消则不覆盖）
        if (snap && (snap.status === "RUNNING" || snap.status === "PENDING" || snap.status === "STUCK")) {
          try { bgOk.markComplete(runResult); } catch {}
        }
      }
    } catch (error: any) {
      // 转后台的任务：run 抛错 → 标记影子任务 CRASHED（已被 /kill 取消则不覆盖）
      const bgErr = bgHandlesRef.current;
      if (bgErr) {
        const snap = getBackgroundManager().getStatus(bgErr.taskId);
        if (snap && (snap.status === "RUNNING" || snap.status === "PENDING" || snap.status === "STUCK")) {
          const eObj = error instanceof Error ? error : new Error(String(error));
          try { bgErr.markCrash(eObj); } catch {}
        }
      }
      // 用户 Ctrl+C 中断不算错误，静默处理
      if (error?.name === "AbortError" || /\b(abort|中断|Ctrl\+C)\b/i.test(error?.message || "")) {
        console.log("  ⏹️  任务已中断。");
      } else {
        const d = classifyLLMError(error);
        if (d.kind !== "unknown") {
          const cfg = getLLMConfig();
          console.error("\n❌ " + d.tag + ": " + d.detail + "\n");
          console.error("  当前平台: " + cfg.platform + "  模型: " + cfg.modelName + "  baseUrl: " + cfg.baseUrl);
          console.error("  API Key: " + (cfg.apiKey ? "已设置（长度" + cfg.apiKey.length + "）" : "未设置 ⚠️"));
          console.error("  建议:");
          for (const tip of d.tips) {
            console.error("    " + tip.replace("{model}", cfg.modelName).replace("{baseUrl}", cfg.baseUrl));
          }
          console.error("");
        } else {
          console.error("\n❌ 执行出错: " + d.detail + "\n");
        }
      }
    } finally {
      // 兜底：确保 spinner / 思考缓冲清理（任务转后台后 onEvent 仍会自行管理，此处无害）
      spinner.stop();
      thinkingBuf.reset();
      currentAbortController = null;
      // 已转后台的任务不在此处重置 mainAgentRunning（bumpToBackground 已设为 false）
      if (!taskWentBackground) mainAgentRunning = false;
    }

    refreshPrompt();
    rl.prompt();
  });

  rl.on("close", () => {
    console.log("\n👋 再见！");
    process.exit(0);
  });
}

/** 命令行参数解析结果。 */
interface CliFlags {
  help: boolean;
  version: boolean;
  platform?: string;
  model?: string;
  models: boolean; // --models 列出可用模型后退出
  workspaceId?: string;
  apiKey?: string;
  prompt?: string; // <prompt>：非交互模式下一次性执行任务
  rest: string[];  // 未识别参数（拼进 prompt）
}

function parseCliArgs(argv: string[]): CliFlags {
  const flags: CliFlags = { help: false, version: false, models: false, rest: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const take = () => argv[++i];
    switch (a) {
      case "-h":
      case "--help": flags.help = true; break;
      case "-v":
      case "--version": flags.version = true; break;
      case "--models": flags.models = true; break;
      case "--platform": case "-p": flags.platform = take(); break;
      case "--model": case "-m": flags.model = take(); break;
      case "--workspace": case "-w": flags.workspaceId = take(); break;
      case "--api-key": case "-k": flags.apiKey = take(); break;
      case "--": while (++i < argv.length) flags.rest.push(argv[i]); break;
      default:
        if (a.startsWith("--platform=")) flags.platform = a.slice("--platform=".length);
        else if (a.startsWith("--model=")) flags.model = a.slice("--model=".length);
        else if (a.startsWith("--workspace=")) flags.workspaceId = a.slice("--workspace=".length);
        else if (a.startsWith("--api-key=")) flags.apiKey = a.slice("--api-key=".length);
        else if (!a.startsWith("-")) flags.rest.push(a);
        else {
          console.error(`⚠️  未知选项: ${a}（用 --help 查看用法）`);
        }
    }
  }
  if (flags.rest.length) flags.prompt = flags.rest.join(" ");
  return flags;
}

function printVersion() {
  // 直接从 package.json 读，避免 require 路径在 link/pack 下漂移
  const pkg = require("../../package.json");
  console.log(`flagent ${pkg.version}`);
}

function printHelp() {
  console.log(`用法:
  flagent [选项] [任务提示...]

选项:
  -h, --help              显示本帮助
  -v, --version           显示版本号
  --models                列出当前平台可用模型并退出
  -p, --platform <name>   切换平台: qianwen | bailian | anthropic（写 ~/.flagent/config.json）
  -m, --model <name>      切换对话模型（持久化）
  -w, --workspace <id>    设置百炼 WorkspaceId（bailian 平台需要，持久化）
  -k, --api-key <key>     设置 API Key（持久化，权限 0600）

非交互执行:
  flagent 帮我分析 base64 加密的字符串 'SGFja2VyIQ=='     直接输入任务，执行完退出
  echo '1+1 等于几' | flagent                            从 stdin 读任务（管道模式）

交互模式:
  flagent                                                 进入交互式多智能体控制台

示例:
  flagent -p qianwen                                      切换到千问平台
  flagent -m deepseek-v4-flash-0731                        设置模型
  flagent --models                                        列出平台模型
  flagent 扫描 127.0.0.1 的常用端口并报告结果            一次性执行任务
`);
}

// 入口点：直接运行时启动 CLI
if (require.main === module) {
  (async () => {
    const flags = parseCliArgs(process.argv.slice(2));

    // 1. --help / --version：无需依赖，立即处理
    if (flags.help) { printHelp(); return; }
    if (flags.version) { printVersion(); return; }

    // 2. 命令行传入的持久化配置（--platform / --model / --workspace / --api-key）
    if (flags.platform || flags.model || flags.workspaceId || flags.apiKey) {
      try {
        setLLMConfig({
          ...(flags.platform ? { platform: flags.platform as Platform } : {}),
          ...(flags.model ? { modelName: flags.model } : {}),
          ...(flags.workspaceId ? { workspaceId: flags.workspaceId } : {}),
          ...(flags.apiKey ? { apiKey: flags.apiKey } : {}),
        });
        await writeGlobalConfig({
          platform: getLLMConfig().platform,
          modelName: getLLMConfig().modelName,
          workspaceId: getLLMConfig().workspaceId,
          apiKey: getLLMConfig().apiKey,
        });
        const c = getLLMConfig();
        console.log(`✅ 已保存配置: platform=${c.platform} model=${c.modelName} workspace=${c.workspaceId || "(无)"} key=${c.apiKey ? "已设置" : "未设置"}`);
      } catch (e: any) {
        console.error("❌ 配置写入失败:", e.message);
        process.exit(1);
      }
      if (!flags.models && !flags.prompt) return;
    }

    // 3. --models：列出可用模型
    if (flags.models) {
      try {
        const table = await listAvailableModels();
        console.log(table);
      } catch (e: any) {
        console.error("❌ 列模型失败:", e.message);
        process.exit(1);
      }
      if (!flags.prompt) return;
    }

    // 4. 非交互一次性执行模式（命令行给了 prompt，或从 stdin 管道读入）
    const stdinPrompt = !process.stdin.isTTY ? await new Promise<string>((resolve) => {
      let buf = "";
      process.stdin.on("data", (c) => buf += c);
      process.stdin.on("end", () => resolve(buf.trim()));
      process.stdin.resume();
    }) : "";
    const oneShotPrompt = flags.prompt || stdinPrompt;
    if (oneShotPrompt) {
      await runOneShot(oneShotPrompt);
      return;
    }

    // 5. 交互模式：必须有 TTY
    if (!process.stdin.isTTY) {
      console.error("❌ 非交互环境：请通过 `flagent 任务描述` 或 `cat task.txt | flagent` 执行，或在终端内使用 `flagent` 进入交互。");
      process.exit(2);
    }
    await startCLI();
  })().catch((err) => {
    console.error("❌ 启动失败:", err.message);
    process.exit(1);
  });
}

/** 非交互一次性任务执行：跑一遍 Session 并打印 finalAnswer。 */
async function runOneShot(task: string): Promise<void> {
  const { createToolRegistry } = require("../tools/factory");
  const { SessionManager } = require("../session/session-manager");
  const toolRegistry = createToolRegistry();
  const mgr = new SessionManager({
    toolRegistry,
    confirmFn: async () => true, // 非交互模式下默认允许副作用工具；可加 --dry 开关禁用
  });
  let titlePrinted = false;
  const oneShotBuf = new ThinkingBuffer((t) => process.stdout.write(t));
  const final = await mgr.run(task, {
    onEvent: (ev: AgentEvent) => {
      switch (ev.type) {
        case "thinking": oneShotBuf.push(ev.delta); break;
        case "thought":
          oneShotBuf.flushNow();
          process.stdout.write("\n\n"); break;
        case "toolStart":
          oneShotBuf.flushNow();
          if (!titlePrinted) { process.stdout.write("\n"); titlePrinted = true; }
          process.stdout.write(`🔧 ${ev.action.toolName}... `); break;
        case "toolEnd":
          process.stdout.write(ev.result.success ? "✓\n" : `✗ ${(ev.result as any).error || "failed"}\n`); break;
        case "finalAnswer":
          console.log("\n" + "─".repeat(56));
          console.log(ev.answer);
          console.log("─".repeat(56));
          break;
      }
    },
    confirmPlan: async () => true,
  });
  if (!final) {
    // finalAnswer 没有事件落下来，兜底：从最后一条 assistant 消息里取
    const cur = mgr.current();
    if (cur) {
      const msgs = (cur as any).getContextManager().getActiveMessages();
      for (let i = msgs.length - 1; i >= 0; i--) {
        if (msgs[i].role === "assistant") {
          console.log("\n" + "─".repeat(56));
          console.log(msgs[i].content);
          console.log("─".repeat(56));
          break;
        }
      }
    }
  }
}
