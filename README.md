# Flagent 多智能体并发框架

基于 Vercel AI SDK 的多智能体协作框架，面向 CTF 攻防与安全研究场景。采用 **MainAgent 主控 + 5 类专家 SubAgent** 架构，支持并发 ReAct、动态子智能体注册与权限管控。

## ✨ 特性

- **并发 ReAct 主控**：MainAgent 拥有全部工具并可直接执行，一次输出多个 `ACTIONS`（并发只读采集）与多个 `DELEGATE`（并发委派），统一思考再推进
- **侦察 → 分类 → 深挖**：非强制状态机的 prompt 工程方法论，先并发侦察再分类，避免未侦察就硬路由
- **5 类 CTF 专家子智能体**：`web` / `pwn` / `reverse` / `crypto` / `misc`，各自独立 context 与工具子集
- **动态子智能体**：`registerDynamicAgent` + `SPAWN_AGENT` —— 不落进预设类别的新题可按需 spawn 通用深挖 agent
- **并发安全**：ContextManager Promise 链式锁、ToolExecutor 信号量限流（默认 8）、PermissionManager 双检锁
- **权限管控**：副作用工具（`command_exec` 等）逐次确认，本会话记忆，CLI `/permissions` 查看
- **上下文管理**：滑动窗口 + Token 超阈值自动 LLM 摘要，`/summarize` 手动触发
- **会话管理**：Claude-Code 式多会话，每会话独立上下文/权限/动态 agent，磁盘持久化（`.flagent/sessions/`），CLI `/new` `/sessions` `/switch` `/delete` 切换/恢复，可并行分析多道题
- **类型安全工具系统**：Zod v4 Schema 参数校验，`concurrent` / `requirePermission` 元数据标记
- **双入口**：CLI 终端交互 + VSCode 扩展（Webview 面板 + 命令面板），共用同一套 agent 构造工厂

## 🏗️ 项目结构

```
flagent/
├── src/
│   ├── llm/client.ts                # DashScope（阿里云百炼）LLM 客户端
│   ├── context/
│   │   └── context-manager.ts       # 上下文管理器（并发安全锁 + 滑动窗口 + 自动摘要）
│   ├── permissions/
│   │   └── permission-manager.ts    # 权限管理器（双检锁 + 会话记忆）
│   ├── tools/
│   │   ├── registry.ts              # 工具注册表（Zod 校验 + concurrent/requirePermission 元数据）
│   │   ├── web-tools.ts             # Web 攻防工具（http_request/port_scan/sql_injection_test…）
│   │   ├── pwn-tools.ts             # Pwn 工具（binary_analysis/disassemble/nc_remote_client…）
│   │   ├── reverse-tools.ts         # 逆向工具（packer_detect/pseudocode_gen/js_deobfuscate…）
│   │   ├── crypto-tools.ts          # 密码学工具（rsa_advanced/lll_reduction/mt19937_predict…）
│   │   ├── misc-tools.ts            # 杂项工具（file_type_detect/image_stego_check/traffic_analysis…）
│   │   ├── default-tools.ts         # 默认 mock 工具（web_search/code_search/file_read…）
│   │   ├── factory.ts               # createToolRegistry（5 套工具一次注册，跨会话共享）
│   │   └── index.ts
│   ├── agents/
│   │   ├── main-agent.ts            # 并发 ReAct 主控（多 ACTIONS/DELEGATE/PLAN/SPAWN_AGENT）
│   │   ├── sub-agent.ts             # 子智能体（独立 context + 工具越权隔离）
│   │   ├── scheduler.ts             # 调度器（route + dispatchConcurrent + registerDynamicAgent）
│   │   ├── tool-executor.ts         # 统一工具执行（并发限流 + 权限 + 串行/并发分组）
│   │   ├── react-parser.ts          # ReAct 响应解析器（公共 + MainAgent 多动作解析）
│   │   ├── factory.ts               # createAgentSystem（CLI/VSCode 唯一装配真相源）
│   │   └── index.ts
│   ├── session/
│   │   ├── session-data.ts          # 会话序列化结构（SessionData/SerializableMessage）
│   │   ├── session-store.ts         # 磁盘持久化（.flagent/sessions/<id>.json）
│   │   ├── session.ts               # 单会话封装（agent 图 + 序列化/反序列化）
│   │   ├── session-manager.ts       # 会话集合管理（创建/切换/恢复/删除）
│   │   └── index.ts
│   ├── cli/index.ts                 # CLI 入口（SessionManager + 会话命令 + 交互）
│   ├── vscode/
│   │   ├── extension.ts             # VSCode 扩展入口（SessionManager + 侧边栏会话树 + 会话感知 webview）
│   │   ├── session-tree-provider.ts # 侧边栏会话树数据源（活跃高亮/点击切换）
│   │   ├── media/                   # 活动栏/按钮 SVG 图标
│   │   ├── package.json             # 扩展 manifest（视图/命令/菜单）
│   │   └── tsconfig.json
│   └── index.ts                     # 库导出
├── tests/                           # 测试用例（单元 + e2e）
├── .env.example
├── tsconfig.json
└── package.json
```

## 🚀 快速开始

### 1. 安装依赖

```bash
npm install
```

### 2. 配置环境变量

```bash
cp .env.example .env
# 编辑 .env 填入真实 API Key
```

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `DASHSCOPE_API_KEY` | 阿里云百炼 API Key | - |
| `WORKSPACE_ID` | 百炼 Workspace ID | `llm-v7cepeucys535ynp` |
| `MODEL_NAME` | 模型名称 | `qwen3.8-max` |

### 3. 构建 & 运行 CLI

```bash
npm run build
npm run cli
```

### 4. CLI 交互命令

CLI 启动时自动恢复最近会话（若无历史会话，首次提问自动新建）。会话持久化到 `.flagent/sessions/`，重启后可 `/switch` 恢复（消息/权限/动态 agent/历史 steps 全还原）。

**会话管理**（每会话独立上下文/权限/动态 agent，可并行分析多道题）：

| 命令 | 说明 |
|------|------|
| `/new [标题]` | 新建会话并切为活动 |
| `/sessions` | 列出所有会话（标记当前活动会话） |
| `/switch <id>` | 切换会话（支持 id 短前缀；不在内存则从磁盘恢复） |
| `/delete <id>` | 删除指定会话（内存 + 磁盘） |
| `/title [标题]` | 查看或设置当前会话标题 |

**会话内命令**：

| 命令 | 说明 |
|------|------|
| `/help` | 显示帮助 |
| `/agents` | 查看所有子智能体（含动态注册的） |
| `/tools` | 查看所有可用工具 |
| `/context` | 查看当前会话上下文状态（消息数/Token/摘要） |
| `/summarize` | 手动生成对话摘要（窗口外消息压缩） |
| `/permissions` | 查看本会话已批准的副作用工具 |
| `/clear` | 清除当前会话的对话历史与权限记忆 |
| `/exit` | 退出系统 |

## 🧩 核心架构

### 并发架构总览

```
用户任务
  └─ MainAgent（主控，拥有全部工具）
       ├─ PLAN: 侦察目标 + 总体方案（可选，简单任务可跳过）
       ├─ ACTIONS: 并发只读采集（多个 concurrent 工具同时跑）
       │     └─ ToolExecutor（信号量限流 + 权限确认）
       ├─ SPAWN_AGENT: 按需注册通用深挖 agent（新题）
       └─ DELEGATE: 并发委派多个专家 SubAgent（各自独立 ReAct）
            └─ 统一落库观察 → 下一步统一思考 → FINAL_ANSWER
```

方法论（**侦察 → 分类 → 深挖**，非强制状态机）：
1. **侦察**：复杂任务第一步优先并发只读采集，先获取事实再判断，不在未侦察前凭字面猜类别硬路由
2. **分类**：基于观察自主归类（web/pwn/reverse/crypto/misc，或判断为新题）
3. **深挖**：MainAgent 继续用工具深入，或并发 DELEGATE 给专家；新题可 SPAWN_AGENT 自定义通用 agent

### ContextManager（上下文管理器）

- **并发安全**：`runLocked` Promise 链式锁串行化所有写入，`addMessagesBatch` 批量落库只触发一次锁
- **滑动窗口**：始终保留最近 N 条消息（默认 10 条）
- **自动摘要**：Token 超阈值时自动 LLM 压缩旧消息；`summarizeNow()` 支持手动触发
- **Token 估算**：按 `字符数 / 4` 估算

### ToolRegistry（工具注册表）

基于 Zod v4 Schema 的类型安全工具系统，每个工具带元数据：
- `concurrent: true` — 只读采集工具，可安全并发执行（如 `http_request`）
- `requirePermission: true` — 副作用工具，需逐次权限确认（如 `command_exec`）

`getToolDescriptions()` 将 Zod schema 推断为 JSON schema（用 `instanceof` 判定，跨 zod 版本稳健）。

### ToolExecutor（统一工具执行入口）

MainAgent 与所有 SubAgent 共用，统一权限与并发策略：
1. 串行确认所有 `requirePermission` 工具（PermissionManager 自带锁）
2. 拒绝的标记 `skipped` 不执行
3. `concurrent: true` 的只读工具**并发执行**（信号量限流，默认上限 8）；其余串行（保守避免副作用冲突）
4. 工具执行抛错 / Zod 校验失败均被捕获，返回 `success: false`
5. 保持原顺序返回结果

### PermissionManager（权限管理器）

- **会话记忆**：同一工具在本会话确认一次后不再询问（按工具名记忆）
- **双检锁**：fast-path 无锁读 `approved` → 未命中进锁 → **锁内复检**再询问，确保并发场景同一工具只弹一次窗
- **拒绝不记忆**：被拒的工具下次仍会询问（避免一次拒绝永久封锁）

### SubAgent（子智能体）

5 类 CTF 专家，各自独立 ContextManager（context 隔离）+ 共享 ToolExecutor（统一权限/并发），`maxSteps: 8`：

| 智能体 | 角色 | 工具数 | 代表工具 |
|--------|------|--------|----------|
| `web` | Web 攻防专家 | 14 | `http_request` `port_scan` `dir_bruteforce` `sql_injection_test` `xss_test` `ssti_test` `ssrf_test` `file_upload_test` `header_analysis` |
| `pwn` | 二进制漏洞挖掘与利用专家 | 9 | `binary_analysis` `extract_strings` `vulnerability_scan` `disassemble` `hex_view` `elf_got_plt_analysis` `exploit_template` `nc_remote_client` |
| `reverse` | 逆向工程与代码分析专家 | 11 | `binary_analysis` `disassemble` `packer_detect` `code_deobfuscate` `binary_compare` `apk_analysis` `pseudocode_gen` `js_deobfuscate` `dotnet_decompile` |
| `crypto` | 密码分析与破解专家 | 11 | `encode_decode` `hash_crack` `classical_cipher` `rsa_tool` `rsa_advanced` `aes_encrypt` `des_encrypt` `modular_arithmetic` `lll_reduction` `mt19937_predict` |
| `misc` | 隐写分析与取证专家 | 15 | `file_type_detect` `entropy_analysis` `image_stego_check` `qr_decoder` `archive_crack` `traffic_analysis` `memory_forensics` `file_search_content` `command_exec` |

**工具越权隔离**：SubAgent 仅能调用其 `toolNames` 集合内的工具，越权调用直接返回 `[工具越权]` 拒绝执行。

### Scheduler（调度器）

- `route(task)` — 单智能体直接路由（无 LLM）；多智能体用 LLM 分析任务语义选择最合适执行方
- `dispatchConcurrent(requests)` — **并发委派**多个 SubAgent，`Promise.all` 并发 `run()`，未找到的标记失败不影响其他
- `registerDynamicAgent(config)` / `unregisterDynamicAgent(id)` — 动态注册/注销通用 SubAgent（决策四：给新题留口子），id 唯一校验、toolNames 过滤到注册表

### MainAgent（并发 ReAct 主控）

一次 ReAct 步骤可同时输出：
- `PLAN` — 总体方案（可选，通常仅第一步）
- `ACTIONS` — 多个工具调用，并发执行
- `SPAWN_AGENT` — 动态注册通用 agent
- `DELEGATE` — 多个专家 agent，并发委派
- `FINAL_ANSWER` — 任务完成

工具采集与子智能体委派**同时并发推进**（`Promise.all`），结果统一落库供下一步思考。每步记录 `thought` / `action` / `observation` / `agentId` / `plan`。

## 🗂️ 会话管理（Session）

Claude-Code 式多会话，让 CLI 可在不同 session 分析不同题目，互不干扰。

- **隔离边界**：每会话独立 `ContextManager`（主对话）/ `MainAgent`（steps）/ `PermissionManager`（approved）/ `Scheduler`（预设+动态 agent）；跨会话共享无状态的 `ToolRegistry` 与 LLM client
- **持久化**：`.flagent/sessions/<id>.json`，存主对话（messages+summary）、历史 steps、已批准工具、动态 agent 配置；子 agent context 为瞬时态不持久化
- **恢复**：`Session.fromData` 重建 —— 预置 approved → `createAgentSystem` → `restoreMessages` → 重注册动态 agent → `setSteps`
- **首问自动命名**：`Session.run` 首次以任务前 30 字派生标题

作为库使用时，可直接用 `SessionManager` 驱动多会话：

```typescript
import { SessionManager, createToolRegistry, PermissionManager } from "flagent";

const toolRegistry = createToolRegistry();
const mgr = new SessionManager({
  toolRegistry,
  confirmFn: async () => true, // 自定义副作用工具确认
});

const sessionA = await mgr.create("题一");
await mgr.switch(sessionA.id);
await mgr.run("分析这道 web 题..."); // 在 sessionA 上下文内执行并自动持久化

const sessionB = await mgr.create("题二");
await mgr.run("分析这道 crypto 题..."); // 在 sessionB 上下文内执行，与 A 互不污染

// 重启后从磁盘恢复
const restored = await mgr.resume(sessionA.id);
```

## 🖥️ VSCode 扩展

```bash
cd src/vscode
npm install
npm run compile
```

> 需先在项目根目录 `npm run build` 生成 `dist/`（扩展的运行依赖会随扩展一并编译进 `out/`）。

**LLM 配置**（扩展专属）：通过 VSCode 设置 `flagent.*` 注入，优先级 **>** 项目根 `.env`。

| 设置项 | 默认值 | 说明 |
|--------|--------|------|
| `flagent.apiKey` | _(空)_ | DashScope API Key（**必填**），为空时发起对话会弹窗提示打开设置 |
| `flagent.workspaceId` | `llm-v7cepeucys535ynp` | DashScope workspace ID（会自动重算 `baseUrl`） |
| `flagent.model` | `qwen3.8-max` | 模型名称 |

修改 `settings.json` 后即时生效（无需重启窗口）；另可执行 `Flagent: 重新加载 LLM 配置` 手动刷新。

**侧边栏会话管理**：活动栏新增 **Flagent** 入口，侧边栏「会话」视图列出所有会话（活跃会话以蓝点标记、按更新时间倒序）。

| 操作 | 方式 |
|------|------|
| 新建会话 | 视图标题栏 `+` 按钮 / 命令面板 `Flagent: 新建会话` |
| 切换会话 | 点击会话项 / 命令面板 `Flagent: 切换会话` |
| 重命名 / 删除 | 会话项右键菜单 |
| 刷新列表 | 视图标题栏刷新按钮 |

会话持久化到工作区 `.flagent/sessions/`（与 CLI 共享同一目录），活动会话记忆在 `workspaceState`，重开窗口自动恢复。对话面板绑定当前会话，切换会话即重载该会话的消息历史。`Flagent: 显示状态` 会一并输出当前生效的 LLM 配置。

可用命令：`Flagent: 开始对话` / `Flagent: 打开对话面板` / `Flagent: 分析选中代码` / `Flagent: 清除当前会话上下文` / `Flagent: 显示状态` / `Flagent: 重新加载 LLM 配置` / 会话管理系列命令。

## 📦 作为库使用

```typescript
import {
  ContextManager,
  ToolRegistry,
  MainAgent,
  Scheduler,
  ToolExecutor,
  PermissionManager,
  createWebTools,
  createPwnTools,
  createReverseTools,
  createCryptoTools,
  createMiscTools,
} from "flagent";

async function main() {
  // ① 构建工具注册表（concurrent/requirePermission 元数据）
  const toolRegistry = new ToolRegistry();
  for (const t of createWebTools().getAll()) toolRegistry.register(t);
  for (const t of createPwnTools().getAll()) toolRegistry.register(t);
  // ...其余工具集

  // ② 权限管理器（副作用工具确认）+ 统一工具执行入口（并发限流）
  const permissionManager = new PermissionManager(
    async (toolName, args) => {
      // 自定义确认逻辑，返回 true/false
      return true;
    }
  );
  const toolExecutor = new ToolExecutor(toolRegistry, permissionManager, 8);

  // ③ 调度器（注入 toolExecutor 供动态 agent 使用）
  const scheduler = new Scheduler(toolRegistry, toolExecutor);

  // ④ 动态注册一个通用深挖 agent（决策四）
  scheduler.registerDynamicAgent({
    id: "gen-custom",
    name: "自定义专家",
    role: "通用分析员",
    systemPrompt: "你是通用分析员…",
    toolNames: ["http_request", "file_type_detect"],
    maxSteps: 6,
  });

  // ⑤ MainAgent 主控
  const mainAgent = new MainAgent(
    new ContextManager(),
    toolRegistry,
    scheduler,
    toolExecutor,
    20 // maxSteps
  );

  const result = await mainAgent.run("分析 http://example.com 的安全性");
  console.log(result.finalAnswer);
  console.log(`步数: ${result.steps.length}, 耗时: ${result.duration}ms`);
}
```

## 🧪 测试

先 `npm run build` 生成 dist，再运行测试：

| 命令 | 范围 | 说明 |
|------|------|------|
| `npm test` / `npm run test:unit` | 阶段 0–10 单元 + 边界场景 | 303 项，无需网络/LLM（全 mock） |
| `npm run test:e2e` | 阶段 6/7/8/9/10 e2e | 5 项，真实 LLM + 网络抓取，需 `.env` |

测试覆盖：

- **`tests/stage{0..10}.test.js`** — 各阶段功能单元测试（stage10 覆盖会话序列化往返/磁盘持久化/切换恢复删除/上下文与权限隔离）
- **`tests/edge-cases.test.js`** — 边界场景与错误处理（重复注册/未知工具/参数校验失败/工具抛错/权限拒绝并发/工具越权/解析容错/zod schema 推断等）
- **`tests/e2e-*.test.js`** — 端到端真实 LLM 验证（并发抓取/动态 agent/简单任务跳过工具/编程式构建/双会话隔离 + resume 还原）

## 🛠️ 技术栈

- **Vercel AI SDK v4**（`ai`、`@ai-sdk/openai`）— 接入阿里云百炼 DashScope
- **Zod v4** — 运行时类型校验
- **TypeScript**（strict）— 类型安全
- **Node.js ≥ 18**

## 📝 License

MIT
