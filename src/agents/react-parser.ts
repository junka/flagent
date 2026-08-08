// 公共 ReAct 输出解析器：供 MainAgent 与 SubAgent 共用，消除重复。
// 支持续行（多行 THOUGHT / 多行 JSON 参数），容错 LLM 输出格式波动。

export interface ParsedReact {
  thought: string;
  action: string; // ACTION: 行内容（单工具调用字符串，如 http_request({...})）
  delegateAgent: string; // DELEGATE: 行内容
  finalAnswer: string; // FINAL_ANSWER: 行内容
}

const KEY_PATTERNS: Array<{ key: keyof ParsedReact; re: RegExp }> = [
  { key: "thought", re: /^\s*THOUGHT\s*[:：]\s*(.*)$/i },
  { key: "action", re: /^\s*ACTION\s*[:：]\s*(.*)$/i },
  { key: "delegateAgent", re: /^\s*DELEGATE\s*[:：]\s*(.*)$/i },
  { key: "finalAnswer", re: /^\s*FINAL_ANSWER\s*[:：]\s*(.*)$/i },
];

/**
 * 解析 ReAct 响应。识别 THOUGHT/ACTION/DELEGATE/FINAL_ANSWER 四类键，
 * 键之间的非键行作为上一键的续行（捕获多段思考与多行 JSON 参数）。
 */
export function parseReactResponse(text: string): ParsedReact {
  const result: ParsedReact = {
    thought: "",
    action: "",
    delegateAgent: "",
    finalAnswer: "",
  };
  let current: keyof ParsedReact | null = null;

  for (const rawLine of text.split("\n")) {
    let matched = false;
    for (const { key, re } of KEY_PATTERNS) {
      const m = rawLine.match(re);
      if (m) {
        const val = m[1].trim();
        result[key] = result[key] ? `${result[key]}\n${val}` : val;
        current = key;
        matched = true;
        break;
      }
    }
    if (!matched && current) {
      const trimmed = rawLine.trim();
      if (trimmed) {
        result[current] = result[current]
          ? `${result[current]}\n${trimmed}`
          : trimmed;
      }
    }
  }

  return result;
}

/**
 * 解析单行工具调用：toolName({...args JSON...})。
 * 支持跨行参数（[\s\S]）。解析失败返回 { toolName: "", toolArgs: {} }。
 */
export function parseToolCallLine(line: string): {
  toolName: string;
  toolArgs: Record<string, any>;
} {
  const match = line.match(/(\w+)\s*\(([\s\S]*)\)/);
  if (!match) {
    return { toolName: "", toolArgs: {} };
  }
  const toolName = match[1];
  const argsStr = match[2].trim();
  if (!argsStr) {
    return { toolName, toolArgs: {} };
  }
  try {
    const parsed = JSON.parse(argsStr);
    return {
      toolName,
      toolArgs:
        parsed && typeof parsed === "object" && !Array.isArray(parsed)
          ? parsed
          : {},
    };
  } catch {
    return { toolName, toolArgs: {} };
  }
}

export interface SpawnAgentRequest {
  id: string;
  name: string;
  role: string;
  systemPrompt: string;
  toolNames: string[];
  maxSteps?: number;
}

export interface ParsedMainReact {
  thought: string;
  plan: string;
  actions: Array<{ toolName: string; toolArgs: Record<string, any> }>;
  delegates: string[];
  spawnAgents: SpawnAgentRequest[];
  finalAnswer: string;
}

/**
 * 解析 MainAgent 的 PLAN / 多 ACTIONS / 多 DELEGATE / SPAWN_AGENT 响应。
 * 格式：
 *   PLAN: [可选，通常仅第一步：侦察目标 + 总体方案]
 *   THOUGHT: ...
 *   ACTIONS:
 *     - toolName({...})
 *     - toolName({...})
 *   SPAWN_AGENT: {"id":"gen-xxx","name":"...","role":"...","systemPrompt":"...","toolNames":["t1","t2"]}
 *   DELEGATE: agentId1, agentId2
 *   FINAL_ANSWER: ...
 *
 * PLAN/THOUGHT/FINAL_ANSWER 支持多行续行；ACTIONS 项以 `- `/`* ` 标记或裸工具调用起头，
 * 跨行 JSON 参数累积；DELEGATE 按逗号分割；SPAWN_AGENT 取整段（inline+body）合并后 JSON.parse，
 * 允许多行 JSON（换行只出现在 token 之间合法）。各段按头部键切分，互不干扰。
 */
export function parseMainReactResponse(text: string): ParsedMainReact {
  const result: ParsedMainReact = {
    thought: "",
    plan: "",
    actions: [],
    delegates: [],
    spawnAgents: [],
    finalAnswer: "",
  };

  const headerRe = /^\s*(PLAN|THOUGHT|ACTIONS|DELEGATE|SPAWN_AGENT|FINAL_ANSWER)\s*[:：]\s*(.*)$/i;
  const lines = text.split("\n");

  // 定位各段头部行
  const headers: Array<{ key: string; inline: string; lineIdx: number }> = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(headerRe);
    if (m) headers.push({ key: m[1].toUpperCase(), inline: m[2], lineIdx: i });
  }

  for (let h = 0; h < headers.length; h++) {
    const start = headers[h].lineIdx + 1;
    const end = h + 1 < headers.length ? headers[h + 1].lineIdx : lines.length;
    const body = lines.slice(start, end);
    const key = headers[h].key;
    const inline = headers[h].inline.trim();

    if (key === "THOUGHT") {
      const parts = [inline, ...body.map((l) => l.trim())].filter(Boolean);
      result.thought = parts.join("\n");
    } else if (key === "PLAN") {
      // PLAN 与 THOUGHT 同：inline + body 续行合并
      const parts = [inline, ...body.map((l) => l.trim())].filter(Boolean);
      result.plan = parts.join("\n");
    } else if (key === "FINAL_ANSWER") {
      const parts = [inline, ...body.map((l) => l.trim())].filter(Boolean);
      result.finalAnswer = parts.join("\n");
    } else if (key === "DELEGATE") {
      const all = [inline, ...body.map((l) => l.trim())]
        .filter(Boolean)
        .join(",");
      result.delegates = all
        ? all.split(/[,，]/).map((s) => s.trim()).filter(Boolean)
        : [];
    } else if (key === "SPAWN_AGENT") {
      // 整段合并为一段 JSON 文本（多行 JSON 换行只出现在 token 间，合法）
      const jsonStr = [inline, ...body.map((l) => l.trim())]
        .filter(Boolean)
        .join(" ");
      if (!jsonStr) continue;
      try {
        const parsed = JSON.parse(jsonStr);
        if (
          parsed &&
          typeof parsed === "object" &&
          !Array.isArray(parsed) &&
          parsed.id &&
          Array.isArray(parsed.toolNames)
        ) {
          result.spawnAgents.push({
            id: String(parsed.id),
            name: String(parsed.name ?? parsed.id),
            role: String(parsed.role ?? parsed.name ?? parsed.id),
            systemPrompt: String(parsed.systemPrompt ?? ""),
            toolNames: parsed.toolNames.map((t: any) => String(t)),
            maxSteps:
              typeof parsed.maxSteps === "number" ? parsed.maxSteps : undefined,
          });
        }
      } catch {
        // JSON 解析失败：忽略该 SPAWN_AGENT（容错，不阻断其余解析）
      }
    } else if (key === "ACTIONS") {
      const items: string[] = [];
      let cur: string[] = inline ? [inline] : [];
      for (const l of body) {
        const t = l.trim();
        if (!t) continue;
        const isMarker = /^[-*]\s+/.test(t);
        const isBareCall = /^\w+\s*\(/.test(t);
        if (isMarker) {
          if (cur.length) items.push(cur.join(" "));
          cur = [t.replace(/^[-*]\s+/, "")];
        } else if (isBareCall && cur.length) {
          items.push(cur.join(" "));
          cur = [t];
        } else {
          cur.push(t);
        }
      }
      if (cur.length) items.push(cur.join(" "));
      for (const item of items) {
        const parsed = parseToolCallLine(item);
        if (parsed.toolName) result.actions.push(parsed);
      }
    }
  }

  return result;
}
