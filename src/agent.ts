import { createAgent, summarizationMiddleware, humanInTheLoopMiddleware, type InterruptOnConfig } from "langchain";
import { SqliteSaver } from "@langchain/langgraph-checkpoint-sqlite";
import fs from "node:fs";
import { ChatOpenAI } from "@langchain/openai";
import { ChatAnthropic } from "@langchain/anthropic";
import { ChatDeepSeek } from "@langchain/deepseek";
import { CHECKPOINT_DB, CONFIG_DIR, loadSettings, type AgentConfig, type PermissionLevel, type ProxyConfig, type SearchSettings } from "./config.ts";
import { createTools, needsConfirm, resolveWorkspacePath } from "./tools.ts";
import { startWebUI } from "./web.ts";
import {
  Agent as UndiciAgent,
  ProxyAgent,
  Socks5ProxyAgent,
  setGlobalDispatcher,
} from "undici";

// ---------- SQLite checkpointer：会话状态（含压缩结果）跨重启持久化 ----------
// 模块级单例：网页端改配置重建 agent 时复用同一个数据库连接
// 导出供 web 端读取历史消息与删除会话（deleteThread）
fs.mkdirSync(CONFIG_DIR, { recursive: true });
export const checkpointer = SqliteSaver.fromConnString(CHECKPOINT_DB);

// ---------- 全局代理：影响模型 API 与信息检索工具的 fetch ----------
// proxy 为 null 恢复直连；通过 undici 全局 dispatcher 让 Node 内置 fetch 也走代理
export function applyProxy(proxy: ProxyConfig | null): void {
  if (!proxy) {
    setGlobalDispatcher(new UndiciAgent());
    return;
  }
  if (proxy.protocol === "socks5") {
    setGlobalDispatcher(
      new Socks5ProxyAgent(`socks5://${proxy.host}:${proxy.port}`, {
        username: proxy.username || undefined,
        password: proxy.password || undefined,
      })
    );
    return;
  }
  // HTTP/HTTPS CONNECT 代理：认证内嵌到 URI 的 userinfo，undici 自动生成 Proxy-Authorization
  const auth = proxy.username
    ? `${encodeURIComponent(proxy.username)}:${encodeURIComponent(proxy.password)}@`
    : "";
  setGlobalDispatcher(new ProxyAgent(`http://${auth}${proxy.host}:${proxy.port}`));
}

// ---------- 根据配置构建对应提供商的模型 ----------
// 各 SDK 在 Key 为空时会在构造阶段直接抛错，而本地网关通常不需要 Key；
// 用占位串兜底，真正无效时由服务端返回鉴权错误
export function buildModel(config: AgentConfig) {
  const apiKey = config.apiKey || "not-needed";
  switch (config.provider) {
    case "anthropic":
      return new ChatAnthropic({ model: config.model, apiKey });
    case "deepseek":
      return new ChatDeepSeek({ model: config.model, apiKey });
    case "zhipu":
      // 智谱开放平台的 OpenAI 兼容接口，固定 baseURL，无需用户填写
      return new ChatOpenAI({
        model: config.model,
        apiKey,
        configuration: { baseURL: "https://open.bigmodel.cn/api/paas/v4" },
      });
    case "moonshot":
      // Kimi 的 OpenAI 兼容接口
      return new ChatOpenAI({
        model: config.model,
        apiKey,
        configuration: { baseURL: "https://api.moonshot.cn/v1" },
      });
    case "gemini":
      // Gemini 的 OpenAI 兼容端点，避免额外引入 Google SDK
      return new ChatOpenAI({
        model: config.model,
        apiKey,
        configuration: { baseURL: "https://generativelanguage.googleapis.com/v1beta/openai" },
      });
    case "openai":
      return new ChatOpenAI({ model: config.model, apiKey });
    default:
      // 其他 OpenAI 兼容接口（本地网关等）
      return new ChatOpenAI({
        model: config.model,
        apiKey,
        configuration: { baseURL: config.baseUrl },
      });
  }
}

// ---------- 根据配置构建 Agent（网页端修改配置 / 切换工作区后可重建） ----------
export type KuribohAgent = ReturnType<typeof createKuribohAgent>;

// 各权限级别的系统提示词说明（读取一律免确认；写入按权限管控；命令与进程不做语义
// 分析，写入 containment 完全交给 OS 沙箱按级别硬性保证）
const PERMISSION_PROMPTS: Record<PermissionLevel, string> = {
  readonly:
    "当前文件权限为「仅可查看」：读取任意路径的文件无需确认；所有写入、修改操作都会先请用户确认，被拒绝的操作不会执行。命令与进程（run_command / process_start）在 OS 沙箱内以全盘只读模式免确认执行，任何写入都会被系统直接拒绝；需要写入时请提示用户切换到「工作区内修改」或「完全权限」。",
  workspace:
    "当前文件权限为「工作区内修改」：工作区内文件可自由读写；工作区外的写入会先请用户确认，被拒绝的操作不会执行。命令与进程（run_command / process_start）在 OS 沙箱内免确认执行，写入被沙箱硬性限制在工作区、临时目录与语言缓存目录内，越界写入会直接失败；此时改用 write_file / edit_file 工具（会请用户确认）或提示用户切换到「完全权限」。",
  full: "当前权限为「完全权限」：可以读写计算机上任意路径的文件，命令与进程操作免确认、直接在宿主机执行。",
};

// 受权限管控的文件工具：读取（含工作区外）免确认，仅写入类操作（写入 / 增量修改）需按权限级别拦截
const GATED_FILE_TOOLS: Array<{ name: string; verb: string }> = [
  { name: "write_file", verb: "写入文件" },
  { name: "edit_file", verb: "修改文件" },
];

// 宿主机直执行、无法用沙箱 containment 的系统级工具（GUI 需要显示服务）：完全权限
// 免确认，其余级别逐次确认。run_command / process_start 已由 OS 沙箱按权限级别硬性
// 限制、process_stop 已由 managedPids 白名单约束，都不再走确认层
const GATED_SYSTEM_TOOLS: Array<{ name: string; verb: string; detail: (args: Record<string, unknown>) => string }> = [
  {
    name: "open_application",
    verb: "打开应用",
    detail: (a) => (typeof a.target === "string" && a.target ? a.target : "(未指定目标)"),
  },
];

// 按权限级别构建需要用户确认的工具拦截配置（humanInTheLoopMiddleware）
function buildInterruptOn(workspaceDir: string, permission: PermissionLevel): Record<string, InterruptOnConfig> {
  const interruptOn: Record<string, InterruptOnConfig> = {};
  for (const { name, verb } of GATED_FILE_TOOLS) {
    interruptOn[name] = {
      allowedDecisions: ["approve", "reject"],
      when: (request) => {
        const raw = request.toolCall.args.path;
        if (typeof raw !== "string" || !raw) return false; // 无路径参数 → 工具自身会报错，不拦截
        const { inside } = resolveWorkspacePath(workspaceDir, raw);
        return needsConfirm(permission, "write", inside);
      },
      description: (toolCall) => {
        const raw = toolCall.args.path;
        const { inside } = resolveWorkspacePath(workspaceDir, typeof raw === "string" && raw ? raw : ".");
        const scope = inside ? "工作区内" : "工作区外";
        const note = inside && permission === "readonly" ? "（当前为「仅可查看」模式，写入需确认）" : "";
        return `${verb}｜${scope}：${typeof raw === "string" && raw ? raw : "(未指定路径)"}${note}`;
      },
    };
  }
  // 宿主机直执行的系统级工具不走文件权限分级；完全权限免确认自动执行，其余级别一律
  // 弹出确认，卡片文案由各工具的 detail 生成
  for (const { name, verb, detail } of GATED_SYSTEM_TOOLS) {
    interruptOn[name] = {
      allowedDecisions: ["approve", "reject"],
      when: () => permission !== "full",
      description: (toolCall) => `${verb}｜${detail(toolCall.args)}`,
    };
  }
  // run_command / process_start / process_stop 不进确认层：不做命令语义分析，写入
  // containment 完全交给 OS 沙箱在执行层按权限级别硬性保证（readonly=ro 档、
  // workspace=ws 档、full=宿主机），沙箱不可用时工具自身硬失败
  return interruptOn;
}

export function createKuribohAgent(config: AgentConfig, workspaceDir: string, permission: PermissionLevel, search: SearchSettings) {
  return createAgent({
    model: buildModel(config),
    // 计算器 / 时间 / 文件操作与搜索（写入按权限模式管控）/ 信息检索（Bocha 开关与模型商搜索）/ 系统工具（命令与进程，写入 containment 交 OS 沙箱，不弹确认），定义见 src/tools.ts
    tools: createTools(workspaceDir, permission, search, config),
    systemPrompt:
      "你是一个乐于助人的中文助手。可使用提供的工具（计算、获取时间、文件读写、文件搜索、信息检索、系统命令与进程管理）完成任务和回答问题。" +
      "需要操作本机系统时：run_command 执行命令（查询 CPU、内存、磁盘、网络、进程列表等），process_start 启动程序，process_stop 终止 Kuriboh 启动的进程，open_application 打开应用、文件或网址；" +
      "run_command / process_start 不弹确认，写入限制在执行层由 OS 沙箱硬性保证：「仅可查看」级别全盘只读执行，「工作区内修改」级别写入被限制在工作区、临时目录与语言缓存目录内，「完全权限」级别不经沙箱直接在宿主机执行；沙箱内命令可正常联网（如 go mod tidy、npm install）；沙箱内跑不了 GUI 程序，打开应用请用 open_application；" +
      "沙箱内命令写入越界会直接失败：如实向用户报告失败原因，不要换写法反复重试，改用 write_file / edit_file 工具（会按目标路径请用户确认）或提示用户切换权限模式；OS 沙箱不可用时这些命令在「仅可查看」与「工作区内修改」级别下会直接报错、不回退宿主机，「完全权限」不受影响；" +
      "process_stop 无需确认，但只能终止 Kuriboh 自己启动的进程；open_application 在宿主机执行，「完全权限」外执行前会请用户确认，被拒绝后不要换个写法重试；" +
      "按文件名或路径模式找文件用 glob_search，在文件内容里找文本用 grep_search，找到路径后再用 read_file 读取；" +
      "文件读写与搜索均在 OS 沙箱内执行（系统目录只读、写入仅限工作区、用户主目录与临时目录）；沙箱不可用或写入越界时这些工具会直接报错失败，不会回退到宿主机执行，失败时如实告知用户原因；" +
      "信息检索时调用一次 web_search 通常已足够，不要对同一问题反复搜索；需要正文时再用 web_fetch 读取具体链接。" +
      `当前工作区目录为 ${workspaceDir}，相对路径以工作区为基准；` +
      `${PERMISSION_PROMPTS[permission]}涉及文件操作时先确认路径与内容再写入。`,
    // 会话状态（含压缩结果）挂在 SQLite checkpointer 的 thread_id 上，调用方只需传新消息
    checkpointer,
    // 上下文自动压缩：token 估算超阈值时，把旧消息让模型总结成一条摘要，保留最近几轮
    // trigger 不配置则永不触发；分数阈值（fraction）需要模型 profile，自定义 baseUrl 接口用绝对 tokens 更稳
    middleware: [
      summarizationMiddleware({
        model: buildModel(config), // 做摘要的模型，可换成更便宜的
        trigger: { tokens: 16000 },
        keep: { messages: 20 },
      }),
      // 文件操作权限确认：按权限级别 + 路径位置拦截工具调用，等待网页端用户「允许 / 拒绝」
      // batched 模式：每轮模型输出里所有需确认的调用合并为一个中断，一次性回传 decisions
      humanInTheLoopMiddleware({
        interruptMode: "batched",
        interruptOn: buildInterruptOn(workspaceDir, permission),
      }),
    ],
  });
}

// ---------- 入口 ----------
async function main(): Promise<void> {
  applyProxy(loadSettings().proxy);
  // 启动原生窗口对话（Linux: WebKitGTK / Windows: WebView2 / macOS: WKWebView）
  // 配置的查看与修改均通过窗口内「模型设置」完成
  startWebUI();
}

main().catch((err) => {
  if (err.message?.includes("User force closed")) {
    console.log("\n已取消");
    process.exit(0);
  }
  console.error("运行失败:", err.message);
  process.exit(1);
});
