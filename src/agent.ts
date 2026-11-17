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
// unbash：完整 bash 语法解析器（纯 TS、零依赖），run_command 只读判定用它建 AST
import { forEachChild, parse, type Command, type ParsedScript, type Redirection, type SyntaxNode, type Word } from "unbash";

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
export type MinoAgent = ReturnType<typeof createMinoAgent>;

// 各权限级别的系统提示词说明（读取一律免确认；写入按权限管控，完全权限下命令与进程操作同样免确认）
const PERMISSION_PROMPTS: Record<PermissionLevel, string> = {
  readonly:
    "当前文件权限为「仅可查看」：读取任意路径的文件无需确认；所有写入、修改操作都会先请用户确认，被拒绝的操作不会执行。",
  workspace:
    "当前文件权限为「工作区内修改」：工作区内文件可自由读写；工作区外的写入会先请用户确认，被拒绝的操作不会执行。",
  full: "当前权限为「完全权限」：可以读写计算机上任意路径的文件，执行命令与进程操作同样无需用户确认。",
};

// 受权限管控的文件工具：读取（含工作区外）免确认，仅写入类操作（写入 / 增量修改）需按权限级别拦截
const GATED_FILE_TOOLS: Array<{ name: string; verb: string }> = [
  { name: "write_file", verb: "写入文件" },
  { name: "edit_file", verb: "修改文件" },
];

// 系统级工具：命令与进程操作影响整台机器，不套用文件权限分级；完全权限免确认，其余
// 级别逐次确认（run_command 的只读查询豁免在 buildInterruptOn 里单独配置）
const GATED_SYSTEM_TOOLS: Array<{ name: string; verb: string; detail: (args: Record<string, unknown>) => string }> = [
  {
    name: "process_start",
    verb: "启动进程",
    detail: (a) =>
      typeof a.command === "string"
        ? [a.command, ...(Array.isArray(a.args) ? a.args.map(String) : [])].join(" ")
        : "(未指定命令)",
  },
  {
    name: "process_stop",
    verb: "终止进程",
    detail: (a) => (typeof a.pid === "number" ? `PID ${a.pid}` : "(未指定 PID)"),
  },
  {
    name: "open_application",
    verb: "打开应用",
    detail: (a) => (typeof a.target === "string" && a.target ? a.target : "(未指定目标)"),
  },
];

// run_command 只读查询白名单：名单内命令只做查询、无副作用，任意权限级别下都免确认直接
// 执行。自带修改类子命令的命令（ip / hostnamectl / nvidia-smi）也在名单内，但另由
// MUTATING_ARG_RULES 对参数做拦截。刻意排除「看似只读实则可写」的常用命令：
// date（-s 可设时钟）、find（-delete/-exec）、awk（system()）、sed（-i/w）、sort（-o）、
// env（可直接 exec）、xargs、tee、sysctl / ifconfig（含修改子命令）、sudo 等；Windows 侧排除
// ipconfig（/release 断网）、wmic（可 invoke 方法）、reg / sc / taskkill、powershell / iex，
// macOS 排除 sysctl（-w 可改）、pmset / diskutil / defaults / networksetup（含修改
// 子命令）、osascript（可执行任意 AppleScript）、softwareupdate（--install）、
// open（走 open_application 工具）等——不在名单内一律弹确认。
// 词统一小写存储：PowerShell 命令名大小写
// 不敏感，匹配时统一转小写；POSIX 命令大小写敏感，直接按原值匹配。
const READONLY_COMMANDS = new Set([
  "uname", "lscpu", "lsblk", "lspci", "lsusb", "nvidia-smi", "free", "df", "du", "uptime", "w", "who",
  "whoami", "id", "groups", "cal", "hostname", "hostnamectl", "ip", "lsb_release", "printenv",
  "ps", "pgrep", "vmstat", "pwd", "ls", "echo", "printf", "cat", "head", "tail", "wc", "file",
  // 无副作用控制构件：if/while 条件（test/[）与监控循环（true/false/sleep）的成员
  "true", "false", "sleep", "test", "[",
  "stat", "grep", "egrep", "fgrep", "rg", "cut", "which", "type", "whereis", "netstat", "ss",
  "dmesg", "nproc", "arch", "getent", "locale", "lsmod", "sensors", "glxinfo", "vulkaninfo",
  "clinfo", "systeminfo", "tasklist",
  // macOS：版本 / 硬件配置 / I/O 注册表查询与 Spotlight 搜索，纯只读
  "sw_vers", "system_profiler", "ioreg", "hostinfo", "mdfind", "mdls",
  // Windows：只读 exe / PowerShell 别名（dir、type、where）与纯查询 cmdlet；
  // select/where/sort-object 与 format-table/list 是管道中的筛选与格式化，无副作用
  "driverquery", "findstr", "where", "dir",
  "get-process", "get-service", "get-childitem", "get-content", "get-command", "get-date",
  "get-computerinfo", "get-ciminstance", "get-netipaddress", "get-netipconfiguration",
  "get-psdrive", "get-volume", "select-object", "where-object", "sort-object",
  "format-table", "format-list", "select-string",
]);

// 白名单内、但自带修改类子命令/参数的命令：段内任何参数 token 命中规则即整段需确认。
// ip：addr/link/route 查询常见，但 add/del/set/flush 等动词改状态，netns exec 更能执行
// 任意命令；hostnamectl：无参即 status 只读，set-* 全是写入；nvidia-smi：-r 重置 GPU、
// -pm/-pl 持久化与功耗墙、-e/-c ECC 与计算模式、-ac/-lgc 时钟、-f 查询结果落盘
const MUTATING_ARG_RULES: Record<string, RegExp> = {
  ip: /^(add|del|delete|set|change|replace|flush|append|new|update|exec|attach|detach)$/,
  hostnamectl: /^set-/,
  "nvidia-smi": /^(-r|-f|--gpu-reset|-pm|-pl|-e|-c|-ac|-lc|-lgc|-rgc|-acp|-cc|-caa|--auto-boost-display)(=|\d|$)/,
};

// ---------- POSIX 侧：unbash AST 上的只读判定 ----------

// 词内任意深度不允许命令替换 / 算术展开 / 进程替换（展开阶段会执行代码）；简单变量
// 展开、花括号与 glob 展开只是数据，放行
function isStaticWord(word: Word): boolean {
  let ok = true;
  const walk = (node: SyntaxNode): void => {
    if (!ok) return;
    if (node.type === "CommandExpansion" || node.type === "ArithmeticExpansion" || node.type === "ProcessSubstitution") {
      ok = false;
      return; // 不再下钻：CommandExpansion 的 script 是 lazy，访问才触发解析
    }
    forEachChild(node, walk);
  };
  forEachChild(word, walk);
  return ok;
}

// 重定向：输入读（< 文件）免确认；fd 复制 / 关闭（>&n / <&n / n>&-）无副作用，但目标
// 必须是纯数字或 -（>&词 在展开结果非数字时是建文件的旧语法）；输出（> / >> / >|）
// 只放行 null 类设备；HereDoc / HereString、读写打开（<>）、&> 合并重定向一律拒绝
function checkRedirect(redirect: Redirection): boolean {
  if (redirect.type !== "Redirect") return false;
  const { operator, target } = redirect;
  if (!target) return false;
  if (operator === "<") return isStaticWord(target);
  if (operator === ">&" || operator === "<&") return isStaticWord(target) && /^(\d+|-)$/.test(target.value);
  if (operator === ">" || operator === ">>" || operator === ">|") {
    return isStaticWord(target) && ["/dev/null", "/dev/stdout", "/dev/stderr"].includes(target.value);
  }
  return false;
}

// 节点类型白名单递归；default 一律拒绝：case / select / 子 shell / 命令组 / 函数 /
// coproc / [[ ]] / (( )) / 算术 for 等结构宁可错杀（弹确认）不可错放
function checkNode(node: SyntaxNode): boolean {
  switch (node.type) {
    case "Script":
      return node.commands.every(checkNode);
    case "Statement":
      // background 为 & 后台执行：进程脱离本次调用上下文，拒绝
      return !node.background && checkNode(node.command);
    case "AndOr":
      return node.commands.every(checkNode);
    case "Pipeline":
      // prefixes 是 time / ! 前缀：不算查询本身，保持拒绝
      return node.prefixes.length === 0 && node.commands.every(checkNode);
    case "CompoundList":
      return node.commands.every(checkNode);
    case "If":
      return (
        checkNode(node.clause) &&
        checkNode(node.then) &&
        node.elif.every(checkNode) &&
        (!node.else || checkNode(node.else))
      );
    case "Elif":
      return checkNode(node.clause) && checkNode(node.then);
    case "While": // until 与 while 是同一节点
      return checkNode(node.clause) && checkNode(node.body);
    case "For":
      // 词表是纯数据：变量展开放行，执行类展开由 isStaticWord 拦截
      return (node.wordlist === undefined || node.wordlist.every(isStaticWord)) && checkNode(node.body);
    case "Redirected": // 复合命令整体重定向（while ...; done > /dev/null）
      return node.redirects.every(checkRedirect) && checkNode(node.command);
    case "Command":
      return checkCommand(node);
    default:
      return false;
  }
}

// 叶子命令：赋值前缀拒绝（VAR=x cmd 会写环境）；重定向逐个校验；命令名必须是白名单
// 内、不带引号与路径的裸词；参数必须静态，带修改类规则的命令参数还必须是裸词且不
// 命中规则
function checkCommand(cmd: Command): boolean {
  if (cmd.prefix.some((p) => p.type === "Assignment")) return false;
  if (!cmd.redirects.every(checkRedirect)) return false;
  if (!cmd.name) return false;
  let name: Word = cmd.name;
  let args = cmd.args;
  // timeout <时长> 前缀剥离后校验真实命令（仅 POSIX 分支会走到这里：Windows 的
  // timeout.exe 是 sleep 语义而非限时执行，不剥，timeout 不在名单自然走确认）
  if (name.text === "timeout" && name.parts === undefined) {
    const [duration, head, ...rest] = args;
    if (!duration || duration.type !== "Word" || duration.parts !== undefined || !/^\d+[smhd]?$/.test(duration.value)) {
      return false;
    }
    if (!head || head.type !== "Word") return false;
    name = head;
    args = rest;
  }
  if (name.parts !== undefined || name.text.includes("/")) return false;
  if (!READONLY_COMMANDS.has(name.text)) return false;
  const rule = MUTATING_ARG_RULES[name.text];
  return args.every((arg) => {
    if (arg.type !== "Word") return false; // 参数位赋值（export 形态）拒绝
    if (!isStaticWord(arg)) return false;
    // 修改类规则命令的参数必须是裸词且不命中规则（兼容 -pl=250 / -pl250 写法）
    return !rule || (arg.parts === undefined && !rule.test(arg.value));
  });
}

// 判定 run_command 的命令是否为纯只读查询（可免确认执行）。原则：宁可错杀（弹确认）
// 不可错放。POSIX（Linux / macOS）用 unbash 建完整 AST 后递归校验：复合命令
//（for / while / until / if-elif-else）的条件与体内每个叶子命令都只读才放行，任一
// 叶子非只读整条需确认；语法不完整或非白名单结构一律返回 false。Windows 的
// PowerShell 无 unbash 支持，沿用词法层做段级判定（圆括号语法已在词法层拦截，
// 不存在需要解析的复合命令）；换行必须当段分隔符而非普通空白：`uname\nrm x` 是
// 两条命令，按空白折叠会以首词 uname 放行而漏掉第二条。
function isReadOnlyCommand(command: string, platform: NodeJS.Platform = process.platform): boolean {
  if (platform !== "win32") {
    let ast: ParsedScript;
    try {
      ast = parse(command);
    } catch {
      return false;
    }
    // unbash 容错解析：语法错误仍返回部分 AST（如引号未闭合），不查 errors 会误放行
    if (ast.errors?.length) return false;
    return checkNode(ast);
  }
  // 词法扫描产出「段 → 词」结构；段以 ; | || && 换行分隔（每段一个独立命令）。
  // 词记录曾含引号 / 斜杠：命令名必须是不带引号与斜杠的裸词，防 .\ls 借道白名单
  type Tok = { value: string; quoted: boolean; slash: boolean };
  const segments: Tok[][] = [[]];
  let tok: Tok | null = null;
  let quote: "'" | '"' | null = null;
  const append = (c: string) => {
    const t = (tok ??= { value: "", quoted: false, slash: false });
    if (c === "/") t.slash = true;
    t.value += c;
  };
  const endTok = () => {
    if (tok) {
      segments[segments.length - 1].push(tok);
      tok = null;
    }
  };
  const endSeg = () => {
    endTok();
    segments.push([]);
  };
  // 读重定向目标词：跳过前导空白、支持引号包裹；目标词含 shell 元字符（$ ` ( ) \）即拒绝。
  // 唯一例外：PowerShell 的 $null（大小写不敏感）是丢弃输出的惯用目标，不落盘，放行
  const readRedirectTarget = (start: number): { word: string; end: number } | null => {
    let j = start;
    while (j < command.length && (command[j] === " " || command[j] === "\t")) j++;
    if (j >= command.length) return null; // 目标悬空：语法不完整
    let word = "";
    let q: string | null = null;
    while (j < command.length) {
      const ch = command[j];
      if (q) {
        if (ch === q) q = null;
        else word += ch;
        j++;
        continue;
      }
      if (ch === "'" || ch === '"') {
        q = ch;
        j++;
        continue;
      }
      if (ch === "$" && /^null/i.test(command.slice(j + 1))) {
        // $null / $NULL / $Null：后一字符必须是词边界，防 $nullx 之类借道
        const after = command[j + 5];
        if (after === undefined || " \t\n\r;|&<>".includes(after)) return { word: "$null", end: j + 5 };
        return null;
      }
      if (" \t\n\r;|&<>".includes(ch)) break;
      if ("$`()\\".includes(ch)) return null;
      word += ch;
      j++;
    }
    if (q || !word) return null; // 引号未闭合 / 空目标
    return { word, end: j };
  };
  // fd 复制重定向（>&n / <&n）：数字后必须是词边界，否则是 >&1x 之类未知语法 → 拒绝
  const readFdup = (amp: number): number | null => {
    let k = amp + 1;
    while (k < command.length && command[k] >= "0" && command[k] <= "9") k++;
    if (k === amp + 1) return null; // & 后无数字
    const after = command[k];
    if (after !== undefined && !" \t\n\r;|&<>".includes(after)) return null;
    return k;
  };

  for (let i = 0; i < command.length; i++) {
    const c = command[i];
    const next = command[i + 1];
    if (quote === "'") {
      // 单引号内一切字面，无任何展开
      if (c === "'") quote = null;
      else append(c);
      continue;
    }
    if (quote === '"') {
      if (c === '"') quote = null;
      else if (c === "`") return false; // 双引号内命令替换仍执行
      else if (c === "$" && next === "(") return false; // $(...) 命令替换（$((...)) 同样命中）
      else append(c); // 其余（含 \ 与 $VAR）按字面处理：误判只会多弹一次确认
      continue;
    }
    if (c === "'" || c === '"') {
      (tok ??= { value: "", quoted: false, slash: false }).quoted = true;
      quote = c;
      continue;
    }
    if (c === "\\") {
      if (next === undefined) return false; // 末尾悬空反斜杠：语法不完整
      i++;
      if (next !== "\n") append(next); // \<换行> 续行不产生字符；其余转义取字面值
      continue;
    }
    if (c === ";") {
      endSeg();
      continue;
    }
    if (c === " " || c === "\t") {
      endTok();
      continue;
    }
    if (c === "\n" || c === "\r") {
      endSeg();
      continue;
    }
    if (c === "&") {
      if (next === "&") {
        i++;
        endSeg(); // && 命令分隔
        continue;
      }
      return false; // 裸 & 后台执行（含 &> 等 bash 变体）
    }
    if (c === "|") {
      if (next === "|") i++; // || 与单 | 同为段分隔
      endSeg();
      continue;
    }
    if (c === ">") {
      // 输出重定向：仅放行 >&n fd 复制与 $null 目标，其余目标都会创建/截断文件 → 拒绝。
      // $null 是 PowerShell 丢弃输出的惯用目标；/dev/null 在 PowerShell 会按路径真创建
      // \dev\null 文件，须拒
      let j = i + 1;
      if (command[j] === ">" || command[j] === "|") j++; // >> 追加 / >| 强制覆盖，同规则
      endTok(); // 结束 fd 前缀词（如 2>&1 的 2）
      if (command[j] === "&") {
        const end = readFdup(j);
        if (end === null) return false;
        i = end - 1;
        continue;
      }
      const target = readRedirectTarget(j);
      if (target === null) return false;
      if (target.word !== "$null") return false;
      i = target.end - 1;
      continue;
    }
    if (c === "<") {
      // 输入重定向：< 文件只是读（读取免确认）；<< heredoc、<> 读写打开、<() 进程替换均拒绝
      let j = i + 1;
      if (command[j] === "<" || command[j] === ">" || command[j] === "(") return false;
      endTok();
      if (command[j] === "&") {
        // <&n fd 复制 / <&- 关闭：无副作用
        let k = readFdup(j);
        if (k === null && command[j + 1] === "-") k = j + 2;
        if (k === null) return false;
        i = k - 1;
        continue;
      }
      const target = readRedirectTarget(j);
      if (target === null) return false;
      i = target.end - 1;
      continue;
    }
    // 花括号是 scriptblock：where / select-object / sort-object 等白名单 cmdlet 都接受
    // scriptblock 参数并在执行时运行其中代码，必须整体拒绝
    if (c === "(" || c === ")" || c === "`" || c === "{" || c === "}") return false; // 子 shell / 命令替换 / scriptblock
    if (c === "$" && next === "(") return false;
    if (c === "#" && !tok) {
      // 词首 # 起注释，吃到行尾（换行留给分段逻辑处理）
      while (i + 1 < command.length && command[i + 1] !== "\n") i++;
      continue;
    }
    append(c);
  }
  if (quote) return false; // 引号未闭合
  endTok();

  // 叶子命令（每段一个独立命令；PowerShell 的复合语法是圆括号形式，词法层已拦）：
  // 命令名必须是不带引号与斜杠的裸词，防 .\ls 之类路径形式借道白名单
  const checkSimple = (words: Tok[]): boolean => {
    const head = words[0];
    if (head.quoted || head.slash) return false;
    // PowerShell 命令名大小写不敏感（Get-Process / get-process 等价），统一转小写匹配
    const name = head.value.toLowerCase();
    if (!READONLY_COMMANDS.has(name)) return false;
    // 带修改子命令的工具：任何参数命中规则即整段确认（后缀兼容 -pl=250 / -pl250 写法）
    const rule = MUTATING_ARG_RULES[name];
    if (rule && words.slice(1).some((t) => rule.test(t.value.toLowerCase()))) return false;
    return true;
  };

  return segments.every((seg) => seg.length === 0 || checkSimple(seg));
}

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
  // 系统级工具不走文件权限分级；完全权限免确认自动执行，其余级别一律弹出确认，卡片文案由各工具的 detail 生成
  for (const { name, verb, detail } of GATED_SYSTEM_TOOLS) {
    interruptOn[name] = {
      allowedDecisions: ["approve", "reject"],
      when: () => permission !== "full",
      description: (toolCall) => `${verb}｜${detail(toolCall.args)}`,
    };
  }
  // run_command 单列一档：完全权限免确认；其余级别下纯只读查询命令（白名单 + 严格词法
  // 判定）也免确认直接执行——uname / ps / df / cat 配置文件这类系统问询不该每次都打断用户
  interruptOn["run_command"] = {
    allowedDecisions: ["approve", "reject"],
    when: (request) => {
      if (permission === "full") return false;
      const command = request.toolCall.args.command;
      return !(typeof command === "string" && isReadOnlyCommand(command));
    },
    description: (toolCall) =>
      `执行命令｜${typeof toolCall.args.command === "string" && toolCall.args.command ? toolCall.args.command : "(未指定命令)"}`,
  };
  return interruptOn;
}

export function createMinoAgent(config: AgentConfig, workspaceDir: string, permission: PermissionLevel, search: SearchSettings) {
  return createAgent({
    model: buildModel(config),
    // 计算器 / 时间 / 文件操作与搜索（写入按权限模式管控）/ 信息检索（Bocha 开关与模型商搜索）/ 系统工具（命令与进程，完全权限免确认，run_command 纯只读查询亦免确认，其余确认），定义见 src/tools.ts
    tools: createTools(workspaceDir, permission, search, config),
    systemPrompt:
      "你是一个乐于助人的中文助手。可使用提供的工具（计算、获取时间、文件读写、文件搜索、信息检索、系统命令与进程管理）完成任务和回答问题。" +
      "需要操作本机系统时：run_command 执行命令（查询 CPU、内存、磁盘、网络、进程列表等），process_start 启动程序，process_stop 终止 Mino 启动的进程，open_application 打开应用、文件或网址；" +
      "run_command / process_start 默认在 OS 沙箱内执行（断网、系统目录只读、仅当前工作区可写），沙箱不可用时自动回退宿主机执行并在结果中标注；沙箱内跑不了 GUI 程序，打开应用请用 open_application；" +
      "这类操作不受工作区与文件权限限制；除「完全权限」模式外，修改类命令与进程操作执行前会先请用户确认（uname、ps、df、cat 配置文件这类纯只读查询命令直接执行），被拒绝后不要换个写法重试；" +
      "按文件名或路径模式找文件用 glob_search，在文件内容里找文本用 grep_search，找到路径后再用 read_file 读取；" +
      "文件读写与搜索均在 OS 沙箱内执行（断网、系统目录只读、写入仅限工作区、用户主目录与临时目录）；沙箱不可用或写入越界时这些工具会直接报错失败，不会回退到宿主机执行，失败时如实告知用户原因；" +
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
