import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fetch as undiciFetch, ProxyAgent } from "undici";
import * as cheerio from "cheerio";
import { JSDOM, VirtualConsole } from "jsdom";
import { Readability } from "@mozilla/readability";
import { tool } from "langchain";
import { z } from "zod";
import { rgPath } from "@vscode/ripgrep";
import type {
  AgentConfig,
  PermissionLevel,
  SearchSettings,
} from "./config.ts";

// ---------- 工具集：计算 / 文件操作（按工作区构建）/ 信息检索 / 系统工具 ----------
// agent.ts 通过 `import { createTools } from "./tools.ts"` 装配；新增工具在本文件追加即可。
// 工具结果统一返回字符串（前端 web.ts 的 tool_result 渲染直接展示）。

// 默认直连；仅当用户在聊天内容里指定代理（模型将其作为 proxy 参数传入）时才走代理
function httpFetch(
  url: string,
  init: {
    headers?: Record<string, string>;
    redirect?: "follow";
    method?: string;
    body?: string;
  },
  proxy?: string,
  timeoutMs = 20000
) {
  const opts = { ...init, signal: AbortSignal.timeout(timeoutMs) };
  return proxy
    ? undiciFetch(url, { ...opts, dispatcher: new ProxyAgent(proxy) })
    : fetch(url, opts);
}

// ========== 基础：计算器 / 当前时间 ==========

// 工具 1：计算器
const calculator = tool(
  async ({ expression }) => {
    // 注意：Function 构造器仅用于演示，生产环境请使用安全的数学库
    const result = Function(`"use strict"; return (${expression})`)();
    return `计算结果为 ${result}`;
  },
  {
    name: "calculator",
    description: "计算数学表达式。输入如 '(2 + 3) * 4'。",
    schema: z.object({
      expression: z.string().describe("要计算的数学表达式"),
    }),
  }
);

// 工具 2：获取当前时间
const getCurrentTime = tool(
  async () => new Date().toLocaleString("zh-CN", { hour12: false }),
  {
    name: "get_current_time",
    description: "获取当前日期和时间。",
    schema: z.object({}),
  }
);

// ========== 系统工具：命令执行与进程管理 ==========
// 不属于文件权限模型：agent.ts 中对这几个工具单独配置 humanInTheLoopMiddleware，
// 无论权限级别如何，每次执行前都会先请用户确认。
// run_command / process_start 优先在 OS 沙箱内执行（sidecar 是 sandbox/ 编出的
// mino-sandbox：断网、系统只读、仅工作区可写），沙箱未建立时回退宿主机执行；
// open_application 面向 GUI（沙箱内无显示服务），只在宿主机执行。

// sidecar 位置：开发态由 build:sandbox 产出在项目根，打包态由 CI 复制进应用目录
const SANDBOX_BIN = path.join(
  process.cwd(),
  `mino-sandbox${process.platform === "win32" ? ".exe" : ""}`
);
// 「沙箱不可用」判定契约：退出码 125 且 stderr 首行为 marker，两者同时成立才可信
//（用户命令也可能恰好退出 125）
const SANDBOX_EXIT = 125;
const SANDBOX_MARKER = "MINO_SANDBOX_UNAVAILABLE:";

// 可用性探测结果缓存到进程退出：不可用（sidecar 缺失 / 探测超时 / 非零退出）
// 时不反复探测。缓存带原因：run_command/process_start 回退时只判 ok，
// 文件工具硬失败时要把原因展示给用户
let sandboxProbe: Promise<{ ok: boolean; reason: string | null }> | null = null;
function isSandboxAvailable(): Promise<{ ok: boolean; reason: string | null }> {
  sandboxProbe ??= new Promise((resolve) => {
    const child = spawn(SANDBOX_BIN, ["probe"], {
      windowsHide: true,
      stdio: ["ignore", "ignore", "pipe"],
      signal: AbortSignal.timeout(5000),
    });
    let stderr = "";
    child.stderr?.on("data", (chunk: Buffer) => {
      if (stderr.length < 400) stderr += chunk.toString();
    });
    const fail = (reason: string) => resolve({ ok: false, reason });
    child.on("error", (err) => {
      fail(
        (err as NodeJS.ErrnoException).name === "AbortError"
          ? "探测超时"
          : "sidecar 缺失，请先运行 npm run build:sandbox"
      );
    });
    child.on("close", (code) => {
      if (code === 0) {
        resolve({ ok: true, reason: null });
        return;
      }
      // probe 失败同样走 125+marker 契约，剥出 sidecar 给的具体原因
      const first = stderr.split("\n")[0] ?? "";
      const marked = first.startsWith(SANDBOX_MARKER) ? first.slice(SANDBOX_MARKER.length).trim() : "";
      fail(marked || `探测失败（退出码 ${code}）`);
    });
  });
  return sandboxProbe;
}

// 从执行结果提取「沙箱未建立」的原因；非 null 即调用方需回退宿主机执行
function sandboxReason(r: { stderr: string; code: number | null }): string | null {
  const first = r.stderr.split("\n")[0] ?? "";
  return r.code === SANDBOX_EXIT && first.startsWith(SANDBOX_MARKER)
    ? first.slice(SANDBOX_MARKER.length).trim()
    : null;
}

// 跑一个子进程并等待结束：沙箱执行（spawn sidecar）与宿主回退共用，差别只在 file/argv。
// 输出用 Buffer 聚合、按字节设上限（多字节字符跨 chunk 不会被截成 U+FFFD），
// 结束时统一转字符串；cap 防止 yes 这类命令吃内存，展示前再截断
function runShellCommand(
  file: string,
  argv: string[],
  cwd: string,
  timeoutMs: number,
  opts?: { stdin?: string; cap?: number }
): Promise<{ stdout: string; stderr: string; code: number | null; timedOut: boolean }> {
  return new Promise((resolve) => {
    const CAP = opts?.cap ?? 200_000;
    const child = spawn(file, argv, {
      cwd,
      windowsHide: true,
      stdio: [opts?.stdin !== undefined ? "pipe" : "ignore", "pipe", "pipe"],
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (opts?.stdin !== undefined) {
      child.stdin?.on("error", () => {}); // EPIPE：对端不等输入就退出属正常，静默
      child.stdin?.end(opts.stdin);
    }
    const capped = (cap: number) => {
      const bufs: Buffer[] = [];
      let len = 0;
      return {
        push(chunk: Buffer) {
          if (len >= cap) return;
          const take = Math.min(chunk.length, cap - len);
          bufs.push(take === chunk.length ? chunk : chunk.subarray(0, take));
          len += take;
        },
        text: () => Buffer.concat(bufs).toString(),
      };
    };
    const out = capped(CAP);
    const err = capped(CAP);
    let errText = ""; // spawn error 的补充消息，拼在子进程 stderr 末尾
    let timedOut = false;
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      const stderr = err.text() + (errText ? "\n" + errText : "");
      resolve({ stdout: out.text(), stderr, code: child.exitCode, timedOut });
    };
    child.stdout?.on("data", (chunk: Buffer) => out.push(chunk));
    child.stderr?.on("data", (chunk: Buffer) => err.push(chunk));
    child.on("error", (err) => {
      // signal 超时触发 AbortError，随后 close 收尾
      if ((err as NodeJS.ErrnoException).name === "AbortError") timedOut = true;
      else if (!errText) errText = (err as Error).message;
      finish();
    });
    child.on("close", finish);
  });
}

type SandboxScope = "ro" | "ws" | "home";

// 沙箱内执行用户命令（sidecar run 子命令），结果附 unavailable 原因。
// scope 三档与 roDirs 只读授权由文件/搜索工具消费；run_command 不传维持 ws 现语义
function runInSandbox(
  argv: string[],
  cwd: string,
  timeoutMs: number,
  scope: SandboxScope = "ws",
  roDirs: string[] = []
): Promise<{ stdout: string; stderr: string; code: number | null; timedOut: boolean; unavailable: string | null }> {
  const scopeArgs = ["--scope", scope, ...roDirs.flatMap((d) => ["--ro", d])];
  return runShellCommand(SANDBOX_BIN, ["run", "--cwd", cwd, ...scopeArgs, "--", ...argv], cwd, timeoutMs).then((r) => ({
    ...r,
    unavailable: sandboxReason(r),
  }));
}

// 文件工具的沙箱硬失败语义：不可用一律拒绝执行并展示原因——
// 与 run_command 的回退宿主机刻意不同（写路径宁可失败不可越权）
const sandboxUnavailable = (reason: string | null) =>
  `OS 沙箱不可用（${reason || "未知原因"}）。文件工具仅在沙箱内执行，已拒绝操作。修复：npm run build:sandbox；Linux 需安装 bubblewrap`;

async function ensureSandbox(): Promise<string | null> {
  const probe = await isSandboxAvailable();
  return probe.ok ? null : sandboxUnavailable(probe.reason);
}

// 文件操作统一走 sidecar fs 子命令：125+marker 是沙箱未建立，返回原因由
// 调用方直接拒绝（不回退）；code 非 0 是操作本身失败，调用方展示 stderr 首行
async function runFsOp(
  sub: "read" | "write" | "list",
  cwd: string,
  scope: SandboxScope,
  target: string,
  stdin?: string,
  cap?: number
): Promise<
  | { ok: true; stdout: string; stderr: string; code: number | null; timedOut: boolean }
  | { ok: false; reason: string }
> {
  const r = await runShellCommand(
    SANDBOX_BIN,
    ["fs", sub, "--cwd", cwd, "--scope", scope, "--", target],
    cwd,
    30_000,
    { stdin, cap }
  );
  const reason = sandboxReason(r);
  if (reason !== null) return { ok: false, reason };
  if (r.timedOut) return { ok: false, reason: "文件操作超时（30 秒）" };
  return { ok: true, ...r };
}

// 用户命令 → shell argv（沙箱与宿主回退共用同一套，保证两条路径行为一致）。
// Windows 走 PowerShell：中文管道默认 GBK，先切 UTF-8 再执行用户命令；其余平台 sh -c
function shellArgv(command: string): { file: string; argv: string[] } {
  if (process.platform === "win32") {
    return {
      file: "powershell.exe",
      argv: [
        "-NoLogo",
        "-NonInteractive",
        "-Command",
        `[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; ${command}`,
      ],
    };
  }
  return { file: "/bin/sh", argv: ["-c", command] };
}

// 宿主机启动独立进程（process_start 回退、open_application 共用）：
// detached 独立进程组（Unix 下 pid 即 pgid，可组杀）、不占管道、unref 脱离事件循环
function spawnDetached(file: string, argv: string[]): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn(file, argv, { detached: true, stdio: "ignore" });
    child.once("error", reject);
    child.once("spawn", () => {
      child.unref(); // 脱离父进程事件循环：程序独立运行，不阻塞 Agent
      resolve(child.pid!);
    });
  });
}

// process_start 登记表（模块级，agent 重建不清空）：沙箱路径登记 pgid（Unix）/ pid
//（Windows），宿主回退登记 pid。process_stop 只终止表内进程，ESRCH 时清除登记
const managedPids = new Map<number, { command: string; time: number }>();

// 工厂：系统工具按工作区构建（run_command 默认在工作区目录下执行）
function createSystemTools(workspace: string) {
  const runCommand = tool(
    async ({ command, timeoutMs }) => {
      const timeout = Math.min(Math.max(timeoutMs ?? 30_000, 1_000), 120_000);
      const clip = (label: string, text: string): string =>
        text ? `\n${label}：\n${text.length > 8000 ? text.slice(0, 8000) + `\n…（已截断，共 ${text.length} 字符）` : text}` : "";
      const format = (r: { stdout: string; stderr: string; code: number | null; timedOut: boolean }) => {
        const head = r.timedOut ? `命令超时（${timeout / 1000} 秒），已终止` : `退出码：${r.code}`;
        const body = clip("标准输出", r.stdout) + clip("标准错误", r.stderr);
        return body ? `${head}${body}` : `${head}\n（无输出）`;
      };
      const shell = shellArgv(command);
      // 沙箱优先；未建立（125+marker）才回退宿主机直接执行并标注——
      // 命令本身已在 humanInTheLoopMiddleware 确认过，回退不追加二次确认
      if ((await isSandboxAvailable()).ok) {
        const r = await runInSandbox([shell.file, ...shell.argv], workspace, timeout);
        if (r.unavailable === null) return format(r);
        const host = await runShellCommand(shell.file, shell.argv, workspace, timeout);
        return `（沙箱不可用：${r.unavailable}；以下为宿主机直接执行的结果）\n${format(host)}`;
      }
      // sidecar 缺失或探测失败：沿用宿主机直接执行（与沙箱引入前行为一致）
      const host = await runShellCommand(shell.file, shell.argv, workspace, timeout);
      return format(host);
    },
    {
      name: "run_command",
      description:
        "执行一条系统命令并返回输出（Windows 为 PowerShell，macOS/Linux 为 sh）。默认在 OS 沙箱内执行：断网、系统目录只读、仅当前工作区可写；沙箱不可用时自动改在宿主机执行并在结果中标注。用于查询系统状态（CPU、内存、磁盘、网络、进程列表等）或运行脚本；默认 30 秒超时，输出超长会截断。纯只读查询命令（uname、ps、df、cat 等）直接执行；修改类命令执行前会请用户确认（「完全权限」模式下免确认）。",
      schema: z.object({
        command: z.string().describe("要执行的命令"),
        timeoutMs: z.number().int().optional().describe("可选，超时毫秒数，默认 30000，范围 1000-120000"),
      }),
    }
  );

  const processStart = tool(
    async ({ command, args }) => {
      const label = `${command}${args?.length ? " " + args.join(" ") : ""}`;
      // 沙箱 start：sidecar 在沙箱内启动进程，首行打印 pgid（Unix）/ pid（Windows）后
      // 即退出；sidecar 无长驻逻辑，5 秒足够拿到 PID
      if ((await isSandboxAvailable()).ok) {
        const r = await runShellCommand(
          SANDBOX_BIN,
          ["start", "--cwd", workspace, "--", command, ...(args ?? [])],
          workspace,
          5000
        );
        if (sandboxReason(r) === null) {
          const pid = Number.parseInt(r.stdout.trim().split("\n")[0] ?? "", 10);
          if (Number.isInteger(pid) && pid > 0) {
            managedPids.set(pid, { command: label, time: Date.now() });
            return `已在沙箱内启动 ${label}（PID ${pid}）`;
          }
          return `启动失败：${r.stderr.trim().split("\n")[0] || "sidecar 未返回 PID"}`;
        }
        // 沙箱未建立（如命令在沙箱内不存在）：回退宿主机启动，行为与下方的直接路径一致
      }
      try {
        const pid = await spawnDetached(command, args ?? []);
        managedPids.set(pid, { command: label, time: Date.now() });
        return `已启动 ${label}（PID ${pid}）`;
      } catch (err) {
        return `启动失败：${(err as Error).message}`;
      }
    },
    {
      name: "process_start",
      description:
        "启动一个独立运行的进程（如跑后台服务、命令行程序），立即返回 PID，不等待结束、不捕获输出；默认在沙箱内启动，沙箱不可用时在宿主机启动。需要带参数时用 args 逐个传入；打开 GUI 应用、文件或网址请改用 open_application。执行前会请用户确认。",
      schema: z.object({
        command: z.string().describe("可执行文件或命令，如 /usr/bin/python3、node"),
        args: z.array(z.string()).optional().describe("可选，传给进程的参数列表"),
      }),
    }
  );

  const processStop = tool(
    async ({ pid, force }) => {
      if (!Number.isInteger(pid) || pid <= 0) return "PID 必须是正整数";
      if (pid === process.pid) return "拒绝操作：不能终止 Mino 自身";
      const entry = managedPids.get(pid);
      if (!entry)
        return `进程 ${pid} 不是由 Mino 的 process_start 启动的，拒绝终止。可先用 run_command 查询确认（Windows 用 tasklist，macOS/Linux 用 ps）。`;
      try {
        // Unix：两条启动路径的进程都独立成组（pgid == pid），负 pid 组杀连子进程一起
        // 带走；Windows 无进程组概念，一律 TerminateProcess
        process.kill(process.platform === "win32" ? pid : -pid, force ? "SIGKILL" : "SIGTERM");
        managedPids.delete(pid);
        return `已向 ${entry.command}（PID ${pid}）发送${force ? "强制" : ""}终止信号`;
      } catch (err) {
        const e = err as NodeJS.ErrnoException;
        if (e.code === "ESRCH") {
          managedPids.delete(pid);
          return `进程 ${pid} 不存在或已退出（已从登记表清除）`;
        }
        return `终止失败：${e.message}`;
      }
    },
    {
      name: "process_stop",
      description:
        "终止 Mino 通过 process_start 启动的进程（传返回的 PID），默认温和终止，可选强制；Unix 上会连子进程整组终止。执行前会请用户确认。",
      schema: z.object({
        pid: z.number().int().describe("要终止的进程 PID（process_start 返回值）"),
        force: z.boolean().optional().describe("可选，强制终止（Unix 用 SIGKILL），默认 false"),
      }),
    }
  );

  // 打开应用 / 文件 / URL：GUI 程序在沙箱内起不来（无显示服务），只能宿主机执行；
  // 不登记 PID——桌面程序交给用户自己管理，process_stop 不应杀它们
  const openApplication = tool(
    async ({ target }) => {
      const argv =
        process.platform === "win32"
          ? ["cmd", "/c", "start", "", target] // start 的首个引号参数是窗口标题占位，缺省会被 target 占用
          : process.platform === "darwin"
            ? ["open", target]
            : ["xdg-open", target];
      try {
        await spawnDetached(argv[0], argv.slice(1));
        return `已打开 ${target}`;
      } catch (err) {
        return `打开失败：${(err as Error).message}`;
      }
    },
    {
      name: "open_application",
      description:
        "在用户桌面打开应用程序、文件或网址（用系统默认方式打开；宿主机执行，不经过沙箱），如打开计算器、用默认编辑器打开文档、用默认浏览器打开 URL。执行前会请用户确认。",
      schema: z.object({
        target: z.string().describe("应用名、文件路径或 URL，如 calc、/home/user/doc.pdf、https://example.com"),
      }),
    }
  );

  return [runCommand, processStart, processStop, openApplication];
}

// ========== 文件操作类（按权限模式管控） ==========
// 相对路径以工作区为基准解析；工具本身可访问任意绝对路径，
// 是否需要用户确认由 agent.ts 的 humanInTheLoopMiddleware 按权限级别拦截。
export function resolveWorkspacePath(
  workspace: string,
  input: string
): { path: string; inside: boolean } {
  const abs = path.resolve(workspace, input || ".");
  const inside = abs === workspace || abs.startsWith(workspace + path.sep);
  return { path: abs, inside };
}

// 权限策略：某操作在该权限级别下是否需要用户确认
// - readonly：任何写入（无论工作区内外）→ 确认
// - workspace：工作区外写入 → 确认
// - full：全部免确认
// 读取（含工作区外）一律免确认
export function needsConfirm(
  permission: PermissionLevel,
  op: "read" | "write",
  inside: boolean
): boolean {
  if (op === "read") return false;
  if (permission === "full") return false;
  if (inside) return permission === "readonly";
  return true;
}

// ========== 文件搜索：glob 按路径找文件、grep 按内容找文本（统一用捆绑 ripgrep、经 sidecar 沙箱执行），均为读取，免确认 ==========

// 搜索时跳过的目录：依赖、构建产物与缓存，体量大且几乎不含用户要找的内容
const NOISE_DIRS = [
  "node_modules", ".git", ".svn", ".hg",
  "dist", "build", "out", ".next", ".nuxt", "coverage",
  "__pycache__", ".venv", "venv", ".cache", ".idea", ".vscode",
];

// 跑一次 ripgrep（二进制随 @vscode/ripgrep 按平台安装），经 sidecar 在 OS 沙箱内
// 执行（scope ro：搜索是读操作），收满 maxMatches 行即提前 kill，避免超大目录 /
// 过宽模式拖垮搜索；30 秒超时兜底。extraRoDirs 是额外只读授权（仅 Windows 消费）：
// rg 二进制目录恒带（AppContainer 内执行需读权限），grep 单文件模式再补目标本体
function runRipgrep(
  args: string[],
  cwd: string,
  maxMatches: number,
  extraRoDirs: string[] = []
): Promise<{ lines: string[]; stderr: string; code: number | null; truncated: boolean; timedOut: boolean; unavailable: string | null }> {
  return new Promise((resolve) => {
    const child = spawn(
      SANDBOX_BIN,
      [
        "run",
        "--cwd",
        cwd,
        "--scope",
        "ro",
        ...[path.dirname(rgPath), ...extraRoDirs].flatMap((d) => ["--ro", d]),
        "--",
        rgPath,
        ...args,
      ],
      {
        cwd,
        windowsHide: true,
        // stdin 必须 ignore：目录搜索不传路径参数，rg 检测到 stdin 是未关闭的管道时会改为等待读取 stdin
        stdio: ["ignore", "pipe", "pipe"],
        signal: AbortSignal.timeout(30_000),
      }
    );
    const lines: string[] = [];
    let stderr = "";
    let partial = "";
    let truncated = false;
    let timedOut = false;
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      resolve({
        lines,
        stderr,
        code: child.exitCode,
        truncated,
        timedOut,
        unavailable: sandboxReason({ stderr, code: child.exitCode }),
      });
    };
    child.stdout.on("data", (chunk: Buffer) => {
      partial += chunk.toString();
      const parts = partial.split("\n");
      partial = parts.pop() ?? "";
      for (const raw of parts) {
        const line = raw.replace(/\r$/, "");
        if (!line) continue;
        if (lines.length >= maxMatches) {
          truncated = true;
          child.kill();
          return;
        }
        lines.push(line.length > 320 ? line.slice(0, 320) + "…" : line);
      }
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    child.on("error", (err) => {
      // AbortSignal 超时被杀记为 timedOut；其余（如找不到 rg 二进制）并入 stderr 统一报错
      if ((err as NodeJS.ErrnoException).name === "AbortError") timedOut = true;
      else stderr += (err as Error).message;
      finish();
    });
    child.on("close", finish);
  });
}

// 工厂：文件工具按工作区目录构建（切换工作区时由 web.ts 重建 agent 重新装配）。
// 五个文件工具一律经 sidecar 在 OS 沙箱内执行，沙箱不可用硬失败不回退
function createFileTools(workspace: string, permission: PermissionLevel) {
  // 工具：读文件（OS 沙箱 ro 档：全盘只读，读取不受工作区限制）
  const readFileTool = tool(
    async ({ path: file }) => {
      const target = resolveWorkspacePath(workspace, file).path;
      const unavailable = await ensureSandbox();
      if (unavailable) return unavailable;
      const r = await runFsOp("read", workspace, "ro", target, undefined, 1_000_000);
      if (!r.ok) return `读取失败：${r.reason}`;
      if (r.code !== 0) return `读取失败：${r.stderr.split("\n")[0] || `退出码 ${r.code}`}`;
      const content = r.stdout;
      return content.length > 20000
        ? content.slice(0, 20000) + `\n…（内容过长已截断，全文共 ${content.length} 字符）`
        : content || "(空文件)";
    },
    {
      name: "read_file",
      description:
        "读取指定路径文本文件（UTF-8）的内容，超长内容自动截断。相对路径以当前工作区为基准，也可用绝对路径读取工作区外的文件。",
      schema: z.object({
        path: z.string().describe("文件路径，相对当前工作区或绝对路径"),
      }),
    }
  );

  // 工具：写文件（写入 containment 由沙箱 OS 档位硬性保证，父目录不存在自动创建）
  const writeFileTool = tool(
    async ({ path: file, content }) => {
      const { path: target, inside } = resolveWorkspacePath(workspace, file);
      const unavailable = await ensureSandbox();
      if (unavailable) return unavailable;
      // 写权限面：full 恒 home 档；readonly/workspace 级区内写 ws 档——能执行到
      // 区外写说明已被 humanInTheLoopMiddleware 确认过，升级 home 档保留现有能力矩阵
      const scope: SandboxScope = permission === "full" ? "home" : inside ? "ws" : "home";
      const r = await runFsOp("write", workspace, scope, target, content);
      if (!r.ok) return `写入失败：${r.reason}`;
      if (r.code !== 0) return `写入失败：${r.stderr.split("\n")[0] || `退出码 ${r.code}`}`;
      return `已写入 ${target}（${content.length} 字符）`;
    },
    {
      name: "write_file",
      description:
        "把内容写入指定路径的文本文件（覆盖已有内容）；父目录不存在时自动创建。相对路径以当前工作区为基准，绝对路径可指向工作区外（工作区外写入可能需要用户确认）。",
      schema: z.object({
        path: z.string().describe("文件路径，相对当前工作区或绝对路径"),
        content: z.string().describe("要写入的完整内容"),
      }),
    }
  );

  // 工具：增量修改——read_file + write_file 的组合，不重写整个文件，只替换命中的片段。
  // 读走 ro 档，写回按 write_file 同一 scope 判定，替换在 Node 内存完成
  const editFile = tool(
    async ({ path: file, old_string, new_string, replace_all }) => {
      if (!old_string) return "修改失败：old_string 不能为空；新建文件请用 write_file。";
      if (old_string === new_string) return "修改失败：old_string 与 new_string 相同，无需修改。";
      const unavailable = await ensureSandbox();
      if (unavailable) return unavailable;
      const { path: target, inside } = resolveWorkspacePath(workspace, file);
      const r = await runFsOp("read", workspace, "ro", target, undefined, 1_000_000);
      if (!r.ok) return `修改失败：${r.reason}`;
      if (r.code !== 0) return `修改失败：${r.stderr.split("\n")[0] || `退出码 ${r.code}`}`;
      // 读到上限字节的文件可能已被截断，替换截断内容再写回会静默丢掉文件尾部，一律拒绝
      if (Buffer.byteLength(r.stdout) >= 1_000_000)
        return "修改失败：文件超出 100 万字节上限，不适合增量修改；请用 read_file 分段读取后用 write_file 重写。";
      const content = r.stdout;
      const count = content.split(old_string).length - 1;
      if (count === 0)
        return "修改失败：文件中未找到 old_string。请核对片段与文件实际内容是否逐字符一致（缩进、制表符、行尾空白都算差异），或先用 read_file 查看目标位置附近内容。";
      if (count > 1 && !replace_all)
        return `修改失败：old_string 在文件中出现 ${count} 次，不唯一。请扩大片段范围（多带一行上下文）使其唯一，或传 replace_all: true 全部替换。`;
      // split/join 是字面拼接：replace 的字符串 replacement 会解释 $& 等特殊模式，不能用
      const updated = content.split(old_string).join(new_string);
      const scope = permission === "full" ? "home" : inside ? "ws" : "home";
      const w = await runFsOp("write", workspace, scope, target, updated);
      if (!w.ok) return `修改失败：${w.reason}`;
      if (w.code !== 0) return `修改失败：${w.stderr.split("\n")[0] || `退出码 ${w.code}`}`;
      return `已修改 ${target}：替换 ${replace_all ? count : 1} 处，文件现为 ${updated.length} 字符。`;
    },
    {
      name: "edit_file",
      description:
        "增量修改：把已有文件中精确匹配 old_string 的文本替换为 new_string，文件其余部分原样保留。old_string 必须与文件内容逐字符一致（含缩进与空白），默认要求在文件中唯一出现，相同片段出现多处需传 replace_all: true。未命中或文件不存在会报错；新建文件请用 write_file。",
      schema: z.object({
        path: z.string().describe("文件路径，相对当前工作区或绝对路径"),
        old_string: z.string().describe("要被替换的原文本，须与文件内容完全一致（含缩进与空白）"),
        new_string: z.string().describe("替换后的新文本"),
        replace_all: z.boolean().optional().describe("相同片段出现多处时传 true 全部替换；默认仅允许唯一匹配"),
      }),
    }
  );

  // 工具：列目录（OS 沙箱 ro 档；条目 JSON 由 sidecar 产出，Node 侧仅格式化）
  const listDirectoryTool = tool(
    async ({ path: dir = "." }) => {
      const target = resolveWorkspacePath(workspace, dir).path;
      const unavailable = await ensureSandbox();
      if (unavailable) return unavailable;
      const r = await runFsOp("list", workspace, "ro", target);
      if (!r.ok) return `列目录失败：${r.reason}`;
      if (r.code !== 0) return `列目录失败：${r.stderr.split("\n")[0] || `退出码 ${r.code}`}`;
      let entries: Array<{ name: string; type: string; size?: number }>;
      try {
        entries = JSON.parse(r.stdout || "[]");
      } catch {
        // 条目过多撑爆 200K 缓冲时 stdout 被截断，JSON 解不开
        return "列目录失败：目录条目过多（输出超限），请改用 glob_search 按模式筛选";
      }
      if (!entries.length) return "(空目录)";
      return entries
        .map((e) => {
          const type = e.type === "dir" ? "目录" : e.type === "file" ? "文件" : "其他";
          const size = e.type === "file" && typeof e.size === "number" ? `，${e.size} 字节` : "";
          return `- ${e.name}（${type}${size}）`;
        })
        .join("\n");
    },
    {
      name: "list_directory",
      description:
        "列出指定目录下的文件与子目录（名称、类型、大小），不递归进入子目录。相对路径以当前工作区为基准，也可用绝对路径列出工作区外的目录。",
      schema: z.object({
        path: z.string().optional().describe("目录路径，默认当前工作区根目录"),
      }),
    }
  );

  // 工具：按文件名 / 路径模式（glob）搜索文件路径，不读文件内容。
  // 用捆绑 rg --files（经沙箱）：刻意无视 gitignore（--no-ignore）并包含隐藏文件
  // （--hidden），噪声目录大括号一次排除（后序 -g 优先）
  const globSearchTool = tool(
    async ({ pattern, path: dir = "." }) => {
      if (!pattern) return "请提供要匹配的 glob 模式。";
      try {
        const root = resolveWorkspacePath(workspace, dir).path;
        if (!fs.existsSync(root)) return `目录不存在：${root}`;
        if (!fs.statSync(root).isDirectory()) return `目标不是目录：${root}`;
        const unavailable = await ensureSandbox();
        if (unavailable) return unavailable;
        const args = [
          "--files",
          "--hidden",
          "--no-ignore",
          "-g",
          pattern,
          "-g",
          `!**/{${NOISE_DIRS.join(",")}}/**`,
        ];
        // 根层锚定语义（'*.ts' 不进子目录）：rg 无等价开关，靠 --max-depth 表达，
        // 无 ** 的模式深度固定为「模式内 / 数 + 1」
        if (!pattern.includes("**")) args.push("--max-depth", String(pattern.split("/").length));
        const { lines, stderr, code, truncated, timedOut, unavailable: reason } = await runRipgrep(args, root, 201);
        if (reason) return sandboxUnavailable(reason);
        // rg 退出码：0 有文件，1 无匹配，2 出错；部分目录不可读时仍输出可用结果
        if (code === 2 && !lines.length) {
          if (stderr.includes("No files were searched"))
            return `没有匹配「${pattern}」的文件（候选全被忽略规则过滤掉了）。`;
          return `搜索失败：${stderr.split("\n")[0]?.trim() || "ripgrep 执行出错"}`;
        }
        if (timedOut && !lines.length) return "搜索失败：rg 超过 30 秒未完成";
        if (code === null && !lines.length) return `搜索失败：${stderr.split("\n")[0]?.trim() || "ripgrep 执行出错"}`;
        // 早停于 201 行：>200 时精确计数不再可得
        const shown = lines.slice(0, 200).sort();
        if (!shown.length) return `没有匹配「${pattern}」的文件。`;
        let result = shown.join("\n");
        if (truncated || lines.length > 200) result += `\n（匹配超过 200 个，仅显示前 200 个）`;
        if (timedOut) result += `\n（搜索超过 30 秒被中止，以上为已找到的结果）`;
        return result;
      } catch (err) {
        return `搜索失败：${(err as Error).message}`;
      }
    },
    {
      name: "glob_search",
      description:
        "按文件名 / 路径模式搜索文件路径（不读内容）。pattern 为 glob 模式：* 单层任意字符、** 跨任意目录、? 单字符、[abc] 字符集、{a,b} 多选，按相对搜索目录的完整路径匹配（'*.ts' 只匹配根层，'**/*.ts' 含子目录）。默认搜索当前工作区，path 可指定其他目录。跳过 node_modules、.git 等依赖与缓存目录。",
      schema: z.object({
        pattern: z.string().describe("glob 模式，如 '**/*.ts'、'src/**/*.{js,ts}'"),
        path: z.string().optional().describe("搜索起始目录，默认当前工作区根目录"),
      }),
    }
  );

  // 工具：按文本 / 正则表达式搜索文件内容（ripgrep）
  const grepSearchTool = tool(
    async ({ pattern, path: target = ".", isRegex = false, include, ignoreCase = false }) => {
      if (!pattern) return "请提供要搜索的文本或正则表达式。";
      try {
        const root = resolveWorkspacePath(workspace, target).path;
        if (!fs.existsSync(root)) return `路径不存在：${root}`;
        const stat = fs.statSync(root);
        const isDir = stat.isDirectory();
        if (!isDir && !stat.isFile()) return `目标不是文件或目录：${root}`;
        const unavailable = await ensureSandbox();
        if (unavailable) return unavailable;
        const args = [
          "--with-filename",
          "--line-number",
          "--no-heading",
          "--max-filesize=2M", // 跳过大文件，避免拖慢搜索
          ...(isRegex ? [] : ["--fixed-strings"]),
          ...(ignoreCase ? ["--ignore-case"] : []),
        ];
        if (isDir) {
          // --hidden 让 .env 等隐藏文件仍可被搜到，噪声目录靠 glob 排除；
          // rg 的 glob 规则后出现的优先，因此用户 include 在前、噪声排除在后
          args.push("--hidden");
          if (include) args.push("--glob", include);
          args.push("--glob", `!**/{${NOISE_DIRS.join(",")}}/**`);
          args.push("--", pattern); // 不传路径 = 递归搜索 cwd，输出相对路径
        } else {
          args.push("--", pattern, root); // 单文件显式指定，不受忽略规则与 glob 影响
        }
        // 目录模式 cwd=根；单文件模式 cwd=工作区 + --ro 目标本体（Windows 读取授权）
        const { lines, stderr, code, truncated, timedOut, unavailable: reason } = await runRipgrep(
          args,
          isDir ? root : workspace,
          50,
          isDir ? [] : [root]
        );
        if (reason) return sandboxUnavailable(reason);
        // rg 退出码：0 有匹配，1 无匹配，2 出错
        if (code === 2 && !lines.length) {
          // include / 大小上限 / 忽略规则把候选文件全部筛掉时 rg 也退出 2，按无匹配处理更贴近本意
          if (stderr.includes("No files were searched"))
            return `没有找到匹配「${pattern}」的内容（候选文件都被 include、大小上限或忽略规则过滤掉了）。`;
          const msg = stderr.split("\n")[0]?.trim();
          return `搜索失败：${msg || "ripgrep 执行出错"}`;
        }
        if (!lines.length) return `没有找到匹配「${pattern}」的内容。`;
        const notes: string[] = [];
        if (truncated)
          notes.push("匹配较多，仅显示前 50 处，可指定更小的 path 或更精确的模式");
        if (timedOut) notes.push("搜索超过 30 秒被中止，以上为已找到的结果");
        return (
          lines.join("\n") + (notes.length ? `\n（${notes.join("；")}）` : "")
        );
      } catch (err) {
        return `搜索失败：${(err as Error).message}`;
      }
    },
    {
      name: "grep_search",
      description:
        "按文本或正则表达式搜索文件内容，返回「路径:行号:该行内容」。默认从当前工作区递归搜索，path 可指定文件或目录（含工作区外）；include 可只搜文件名匹配 glob 的文件。跳过 node_modules、.git 等目录与二进制文件。",
      schema: z.object({
        pattern: z.string().describe("要搜索的文本或正则表达式"),
        path: z.string().optional().describe("搜索起点，文件或目录，默认当前工作区根目录"),
        isRegex: z.boolean().optional().describe("pattern 是否按正则表达式处理，默认按字面文本"),
        include: z
          .string()
          .optional()
          .describe("可选，只搜索文件名匹配此 glob 的文件，如 '*.ts'（不含 / 时匹配任意层级的文件名）"),
        ignoreCase: z.boolean().optional().describe("可选，忽略大小写，默认区分大小写"),
      }),
    }
  );

  return [readFileTool, writeFileTool, editFile, listDirectoryTool, globSearchTool, grepSearchTool];
}

// 装配完整工具集：文件操作按权限模式管控；搜索引擎按设置开关装配进 web_search。
// 需要激活模型的配置（模型商搜索复用它的 API Key / Base URL），agent 重建时随之更新
export function createTools(
  workspace: string,
  permission: PermissionLevel,
  search: SearchSettings,
  config: AgentConfig
) {
  return [
    calculator,
    getCurrentTime,
    ...createFileTools(workspace, permission),
    ...createSystemTools(workspace),
    createWebSearchTool(search, config),
    webFetchTool,
  ];
}

// ========== 信息检索类 ==========

// 单条搜索结果（各引擎统一的结构化返回，便于在工具层合并 / 去重 / 排序）
interface SearchHit {
  title: string;
  desc: string;
  url: string;
}

// 模型商搜索接口：复用当前激活模型的 API Key 直接调用其搜索能力。
// 智谱（web_search）与 DeepSeek（/v1/tools/search）提供独立搜索端点；
// OpenAI 无独立端点，经 Responses API 挂内置 web_search 工具让模型边搜边答，
// 再从回答的 url_citation 注解里提取来源，适配成统一的 SearchHit
async function searchProvider(
  query: string,
  limit: number,
  config: AgentConfig,
  proxy?: string
): Promise<SearchHit[]> {
  if (!config.apiKey) throw new Error("当前模型未配置 API Key");
  if (config.provider === "deepseek") {
    // 用户填的 Base URL 可能带 /v1（OpenAI 兼容习惯），剥掉后统一拼端点
    const base = (config.baseUrl || "https://api.deepseek.com")
      .replace(/\/+$/, "")
      .replace(/\/v1$/, "");
    const res = await httpFetch(
      `${base}/v1/tools/search`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${config.apiKey}`,
        },
        body: JSON.stringify({ query, count: limit }),
      },
      proxy,
      15000
    );
    if (!res.ok)
      throw new Error(
        res.status === 401 ? "HTTP 401（API Key 无效）" : `HTTP ${res.status}`
      );
    const data = (await res.json()) as {
      results?: Array<{ title?: string; url?: string; summary?: string }>;
    };
    return (data.results ?? [])
      .map((h) => ({
        title: h.title ?? "",
        // DeepSeek 的 summary 很长，保留 1000 字符，其余截断避免撑爆上下文
        desc: (h.summary ?? "").slice(0, 1000),
        url: h.url ?? "",
      }))
      .filter((h) => h.title || h.url);
  }
  if (config.provider === "openai") {
    const base = (config.baseUrl || "https://api.openai.com/v1").replace(
      /\/+$/,
      ""
    );
    const res = await httpFetch(
      `${base}/responses`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${config.apiKey}`,
        },
        body: JSON.stringify({
          model: config.model,
          tools: [{ type: "web_search" }],
          input: query,
        }),
      },
      proxy,
      60000 // 模型带搜索的完整推理，耗时远超普通搜索接口
    );
    if (!res.ok) {
      // 模型不支持 web_search 等错误以 400 返回，带上服务端信息便于诊断
      let detail = "";
      try {
        detail =
          ((await res.json()) as { error?: { message?: string } }).error
            ?.message ?? "";
      } catch {
        /* 响应体不是 JSON 时忽略 */
      }
      throw new Error(
        res.status === 401
          ? "HTTP 401（API Key 无效）"
          : `HTTP ${res.status}${detail ? `（${detail}）` : ""}`
      );
    }
    const data = (await res.json()) as {
      output?: Array<{
        type?: string;
        content?: Array<{
          type?: string;
          text?: string;
          annotations?: Array<{
            type?: string;
            title?: string;
            url?: string;
          }>;
        }>;
      }>;
    };
    let text = "";
    const seen = new Set<string>();
    const hits: SearchHit[] = [];
    for (const item of data.output ?? []) {
      if (item.type !== "message") continue;
      for (const block of item.content ?? []) {
        if (block.type === "output_text" && block.text) text += block.text;
        for (const a of block.annotations ?? []) {
          if (a.type !== "url_citation" || !a.url || seen.has(a.url)) continue;
          seen.add(a.url);
          hits.push({ title: a.title ?? a.url, desc: "", url: a.url });
        }
      }
    }
    // 引用来源在前，模型生成的搜索综述殿后（同样截断 1000 字符）
    if (text || hits.length)
      hits.push({ title: "搜索结果综述", desc: text.slice(0, 1000), url: "" });
    return hits;
  }
  if (config.provider !== "zhipu")
    throw new Error(
      "当前模型商未提供搜索接口（目前智谱、DeepSeek、OpenAI 支持）"
    );
  // 智谱 OpenAI 兼容端点为 /api/paas/v4（chat/completions 挂在其下），web_search 同级
  const base = (
    config.baseUrl || "https://open.bigmodel.cn/api/paas/v4"
  ).replace(/\/+$/, "");
  const res = await httpFetch(
    `${base}/web_search`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.apiKey}`,
      },
      body: JSON.stringify({
        search_engine: "search_std",
        search_query: query,
        count: limit,
        search_recency_filter: "noLimit",
      }),
    },
    proxy,
    15000
  );
  if (!res.ok)
    throw new Error(
      res.status === 401 ? "HTTP 401（API Key 无效）" : `HTTP ${res.status}`
    );
  const data = (await res.json()) as {
    response?: Array<{
      name?: string;
      url?: string;
      snippet?: string;
      snippet_content?: string;
    }>;
  };
  return (data.response ?? [])
    .map((h) => ({
      title: h.name ?? "",
      desc: h.snippet_content || h.snippet || "",
      url: h.url ?? "",
    }))
    .filter((h) => h.title || h.url);
}

// Bocha 搜索核心逻辑（付费 API，Key 由用户在设置中填写；国内可直连）
async function searchBocha(
  query: string,
  limit: number,
  apiKey: string,
  proxy?: string
): Promise<SearchHit[]> {
  const res = await httpFetch(
    "https://api.bochaai.com/v1/web-search",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({ query, count: limit, summary: true, freshness: "noLimit" }),
    },
    proxy,
    15000
  );
  if (!res.ok)
    throw new Error(
      res.status === 401
        ? "HTTP 401（博查 API Key 无效，请在设置中检查）"
        : `HTTP ${res.status}`
    );
  const data = (await res.json()) as {
    data?: {
      webPages?: {
        value?: Array<{
          name?: string;
          url?: string;
          snippet?: string;
          summary?: string;
        }>;
      };
    };
  };
  return (data.data?.webPages?.value ?? [])
    .map((h) => ({
      title: h.name ?? "",
      desc: h.summary || h.snippet || "",
      url: h.url ?? "",
    }))
    .filter((h) => h.title || h.url);
}

// SerpAPI 搜索核心逻辑（付费 API，国内通常需代理）：固定先 google 再 brave 级联，
// google 用 gl/hl 固定中国区中文（实测对中文查询质量最好），失败或无结果自动换 brave
async function searchSerpapi(
  query: string,
  limit: number,
  apiKey: string,
  proxy?: string
): Promise<SearchHit[]> {
  const engines = [
    { name: "google", extra: { gl: "cn", hl: "zh-cn" } },
    { name: "brave", extra: {} },
  ] as const;
  const errors: string[] = [];
  for (const { name, extra } of engines) {
    const params = new URLSearchParams({
      engine: name,
      q: query,
      num: String(limit),
      ...extra,
      api_key: apiKey,
    });
    try {
      const res = await httpFetch(
        `https://serpapi.com/search.json?${params}`,
        { method: "GET" },
        proxy,
        20000
      );
      if (!res.ok)
        throw new Error(
          res.status === 401
            ? "HTTP 401（SerpAPI API Key 无效，请在设置中检查）"
            : `HTTP ${res.status}`
        );
      const data = (await res.json()) as {
        organic_results?: Array<{
          title?: string;
          link?: string;
          snippet?: string;
        }>;
        // SerpAPI 用 HTTP 200 + error 字段表达业务失败（如引擎对部分查询不给结果）
        error?: string;
      };
      if (data.error && !data.organic_results?.length)
        throw new Error(data.error);
      const hits = (data.organic_results ?? [])
        .map((h) => ({
          title: h.title ?? "",
          desc: h.snippet ?? "",
          url: h.link ?? "",
        }))
        .filter((h) => h.title || h.url);
      if (hits.length) return hits;
      errors.push(`${name}: 没有找到相关结果`);
    } catch (err) {
      const msg = (err as Error).message;
      // Key 无效属致命错误，换引擎也救不了，直接抛出终止级联
      if (msg.includes("401")) throw new Error(msg);
      errors.push(`${name}: ${msg}`);
    }
  }
  throw new Error(errors.join("；"));
}

// 工厂：统一搜索入口。默认用当前模型商的搜索接口（复用其 API Key）；
// 用户启用付费引擎（博查 / SerpAPI）后按卡片顺序依次尝试，失败或无结果时自动回落模型商搜索。
// 不给模型暴露引擎参数：调用方式由用户设置决定，避免模型乱传值触发校验失败与重试
function createWebSearchTool(search: SearchSettings, config: AgentConfig) {
  // 按用户拖定的卡片顺序构建尝试队列：第一个优先，失败尝试下一个启用的引擎
  const paidEngines: Array<{
    name: string;
    run: (query: string, limit: number, proxy?: string) => Promise<SearchHit[]>;
  }> = [];
  for (const id of search.engineOrder) {
    if (id === "bocha" && search.bocha && search.bochaApiKey)
      paidEngines.push({
        name: "博查",
        run: (q, n, p) => searchBocha(q, n, search.bochaApiKey, p),
      });
    else if (id === "serpapi" && search.serpapi && search.serpapiApiKey)
      paidEngines.push({
        name: "SerpAPI",
        run: (q, n, p) => searchSerpapi(q, n, search.serpapiApiKey, p),
      });
  }
  const providerReady =
    (config.provider === "zhipu" ||
      config.provider === "deepseek" ||
      config.provider === "openai") &&
    !!config.apiKey;
  const formatHits = (hits: SearchHit[]) =>
    hits.map((h) => `【${h.title}】\n${h.desc}\n${h.url}`).join("\n\n");
  const desc = paidEngines.length
    ? "搜索互联网信息。优先使用已启用的付费搜索引擎，失败时自动回落模型商搜索接口。一次调用通常已包含足够信息，不需要对同一问题反复搜索。"
    : providerReady
      ? "搜索互联网信息（当前模型商的搜索接口）。一次调用通常已包含足够信息，不需要对同一问题反复搜索。"
      : "搜索互联网信息。（当前模型商未提供搜索接口，可在设置中启用博查或 SerpAPI 搜索。）";
  return tool(
    async ({ query, limit, proxy }) => {
      // 参数一律在运行时归一化：模型传 null / 越界值时给出合理默认，而不是抛 schema 错误
      const count =
        Number.isInteger(limit) && limit! >= 1 && limit! <= 10 ? limit! : 5;
      const via = proxy ?? undefined;
      // 已启用的付费引擎按序尝试，任一成功即返回；全部失败再回落模型商搜索，两边都败才报错
      if (paidEngines.length) {
        const failures: string[] = [];
        for (const engine of paidEngines) {
          try {
            const hits = await engine.run(query, count, via);
            if (hits.length) {
              const note = failures.length
                ? `搜索引擎：${engine.name}\n（${failures.join("；")}；已切换）\n\n`
                : `搜索引擎：${engine.name}\n\n`;
              return `${note}${formatHits(hits)}`;
            }
            failures.push(`${engine.name}：没有找到相关结果`);
          } catch (err) {
            failures.push(`${engine.name}：${(err as Error).message}`);
          }
        }
        let providerError = "";
        try {
          const hits = await searchProvider(query, count, config, via);
          if (hits.length)
            return `搜索引擎：模型商搜索\n（${failures.join("；")}；已回落模型商搜索）\n\n${formatHits(hits)}`;
          providerError = "没有找到相关结果";
        } catch (err) {
          providerError = (err as Error).message;
        }
        return `付费引擎与模型商搜索均未返回结果，可稍后重试或换个关键词。\n${failures.join("\n")}\n模型商搜索：${providerError}`;
      }
      try {
        const hits = await searchProvider(query, count, config, via);
        if (hits.length) return `搜索引擎：模型商搜索\n\n${formatHits(hits)}`;
        return "没有找到相关结果，可换个关键词重试。";
      } catch (err) {
        return `搜索失败：${(err as Error).message}。可在设置中启用博查或 SerpAPI 搜索。`;
      }
    },
    {
      name: "web_search",
      description: desc,
      schema: z.object({
        query: z.string().describe("搜索关键词"),
        limit: z
          .number()
          .nullish()
          .describe("返回结果条数，1–10，默认 5"),
        proxy: z
          .string()
          .nullish()
          .describe("可选，HTTP 代理地址（如 http://127.0.0.1:7890），仅在用户明确指定时填写"),
      }),
    }
  );
}

// 工具 8：抓取网页正文
const webFetchTool = tool(
  async ({ url, maxLength, proxy }) => {
    // 运行时归一化（同 web_search 的 limit）：模型传 null / 越界值时给合理默认，不抛 schema 错误
    const cap =
      Number.isInteger(maxLength) && maxLength! >= 100 && maxLength! <= 50000
        ? maxLength!
        : 8000;
    try {
      const res = await httpFetch(
        url,
        {
          headers: {
            "User-Agent":
              "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
            Accept: "text/html,application/json,text/plain,*/*",
          },
          redirect: "follow",
        },
        proxy
      );
      if (!res.ok) return `请求失败：HTTP ${res.status}`;
      const type = res.headers.get("content-type") ?? "";
      if (!/text|html|json|xml/i.test(type)) {
        return `非文本内容（${type}，${res.headers.get("content-length") ?? "?"} 字节），无法读取。`;
      }

      const body = await res.text();
      let text: string;
      const isHtml =
        /html/i.test(type) ||
        /^\s*<(?:!doctype|html|head|body|main|article|div|p)\b/i.test(body);

      if (isHtml) {
        const dom = new JSDOM(body, {
          url,
          virtualConsole: new VirtualConsole(),
        });
        const article = new Readability(dom.window.document).parse();
        // 优先使用 Readability 提取的正文
        const html = article?.content ?? body;
        const $ = cheerio.load(html);

        // Readability 成功时尽量少清理，失败时清理整页噪声
        if (!article) {
          $("script, style, textarea, noscript, iframe, svg, nav, header, footer, aside").remove();
        } else {
          $("script, style, noscript, iframe, svg").remove();
        }

        // 保留基本段落结构
        $("br").replaceWith("\n");
        $("p, div, section, article, h1, h2, h3, h4, li, blockquote, tr")
          .append("\n");

        text = $.root().text();

        if (article?.title) {
          text = `${article.title}\n\n${text}`;
        }

        text = text
          .replace(/\r\n?/g, "\n")
          .replace(/[ \t]+/g, " ")
          .replace(/\n[ \t]+/g, "\n")
          .replace(/\n{3,}/g, "\n\n")
          .trim();
      } else {
        // JSON / 纯文本原样保留
        text = body;
      }
      return text.length > cap
        ? text.slice(0, cap) + `\n…（正文过长已截断，共 ${text.length} 字符）`
        : text || "(空内容)";
    } catch (err) {
      return `抓取失败：${(err as Error).message}`;
    }
  },
  {
    name: "web_fetch",
    description:
      "抓取指定网址的正文文本（网页 / JSON / 纯文本），HTML 标签会被清理，超长自动截断。",
    schema: z.object({
      url: z.string().describe("完整网址，必须以 http:// 或 https:// 开头"),
      maxLength: z
        .number()
        .nullish()
        .describe("返回正文的最大字符数，100–50000，默认 8000"),
      proxy: z
        .string()
        .optional()
        .describe("可选，HTTP 代理地址（如 http://127.0.0.1:7890），仅在用户明确指定时填写"),
    }),
  }
);

