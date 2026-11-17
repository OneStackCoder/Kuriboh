# AGENTS.md

给在本仓库工作的 AI / 协作者的约束。改动前先读这里，再读对应文件。

## 项目定位

Kuriboh 是一个桌面 AI Agent：Node.js 进程内跑 LangChain.js Agent，用原生 webview（Linux WebKitGTK / Windows WebView2 / macOS WKWebView）承载单页 UI，Go 写的 `launcher/` 只负责开窗口和打包，Go 写的 `sandbox/` 编译出 `kuriboh-sandbox` sidecar 承载系统命令与文件工具的 OS 沙箱。

## 运行与验证

```bash
npm install
npm start          # 直接运行 TypeScript（Node ≥ 24 原生类型剥离，无编译步骤）
npm run typecheck  # tsc --noEmit，改完 TS 必须跑
npm run build:sandbox  # 编译 sandbox/ 的 Go sidecar 到项目根 kuriboh-sandbox（需 Go ≥ 1.21）
npm run build      # 先编 sidecar，再 esbuild 打包成 build/app/app.mjs，复制、压缩 public/（仅发布用）
```

没有测试框架。行为改动需说明手动验证路径（如 `npm start` 后点终端、执行 `exit` 观察页签行为）；无法验证时明确说明，不要声称已验证。

## 目录职责

- `src/agent.ts`：`createKuribohAgent(config, workspaceDir, permission)` 构建 Agent、模型工厂、权限提示词、工具拦截。
- `src/config.ts`：配置读写、`CONFIG_DIR`、`DEFAULT_WORKSPACE_DIR`、`PermissionLevel` 等唯一来源。
- `src/tools.ts`：LangChain 工具（read/write/edit/list、glob_search/grep_search 文件与内容搜索（统一用捆绑 @vscode/ripgrep）、calculator、时间、web_search 统一搜索、网页抓取、run_command / process_start / process_stop 系统命令与进程管理、open_application 打开应用/文件/网址（一律需用户确认，run_command / process_start 默认经 `kuriboh-sandbox` sidecar 进 OS 沙箱执行，沙箱不可用自动回退宿主机；六个文件工具同样全部经 sidecar 进 OS 沙箱执行，沙箱不可用一律硬失败不回退））。搜索默认用当前模型商的搜索能力（复用其 API Key：智谱、DeepSeek 有独立搜索端点，OpenAI 经 Responses API 内置 web_search 适配）；`settings.json` 的 search 可多选启用付费引擎（bocha 博查 / serpapi，后者内部固定先 Google 后 Brave 级联），`engineOrder` 定义的卡片顺序即优先级——第一个失败自动尝试下一个，再回落模型商搜索。
- `src/web.ts`：webview 宿主、`window.KuribohAgent` RPC、事件推送、静态资源白名单、内嵌终端后端。
- `public/index.html`：全部前端（原生 JS，单文件，无构建）。
- `launcher/`：Go 启动器（开窗、目录选择、打包校验）。
- `sandbox/`：Go sidecar `kuriboh-sandbox`（`build:sandbox` 产出）：run_command / process_start 与文件工具的 OS 沙箱后端，Linux=bubblewrap+Landlock、Windows=受限访问令牌+ACL（macOS=Seatbelt / sandbox-exec，编译级验证、待真机实测）。
- `assets/`：图标源文件与各尺寸产物。
- `.github/workflows/build.yml`：三平台打包。

## 硬性约定

1. **品牌与命名**：产品名 `Kuriboh`，代码标识 `KuribohAgent`，默认工作区 `~/kuriboh/default_workspace`，配置目录 `~/.config/Kuriboh`，协议 `kuriboh://`。不要再引入 `GoAgent` / `goagent` 字样。
2. **RPC 契约**：后端只通过 `webview.expose("KuribohAgent", ...)` 暴露接口，前端只调 `window.KuribohAgent.*`；事件走 `window.onKuribohAgentEvent` / `onTermEvent`。新增方法必须返回可 JSON 序列化的值，并且前后端同时改。
3. **路径集中管理**：配置目录、工作区默认值只能来自 `src/config.ts` 的常量，禁止在别处拼 `~/.config/Kuriboh` 之类的字面量。用户已有 `workspaces.json` 不迁移。
4. **权限模型不能绕过**：`readonly` / `workspace` / `full` 三级，读操作免确认，写操作经 `needsConfirm` + `humanInTheLoopMiddleware` 拦截。新增文件工具必须走 `resolveWorkspacePath`，不得提供绕过权限检查的写路径。六个文件工具（read_file / write_file / edit_file / list_directory / glob_search / grep_search；edit_file 为 read+write 组合，写回走 write 同一 scope）一律经 sidecar 在 OS 沙箱内执行，沙箱不可用一律硬失败不回退（与 run_command 的回退语义刻意不同）；写入 containment 由 OS 按 ro/ws/home 三档硬性保证（封 symlink 逃逸；Linux 为 bwrap + Landlock 双层防线），确认后的区外写也仅限 HOME 与临时目录。系统命令与进程操作（`run_command` / `process_start` / `process_stop` / `open_application`）不属于文件权限分级：`readonly` / `workspace` 级别必须经 `humanInTheLoopMiddleware` 逐次确认（例外：`run_command` 的纯只读查询命令——`agent.ts` 的 `READONLY_COMMANDS` 白名单 + `isReadOnlyCommand` 严格判定（POSIX 侧用 unbash 库解析成 AST 递归校验：复合命令 for / while / until / if-elif-else 条件与体内每个叶子命令都只读才放行，解析错误或白名单外结构（子 shell / 函数 / case / heredoc / 后台执行 / 命令替换 / 进程替换 / 赋值前缀等）一律拒绝；Windows PowerShell 无 unbash 支持，走词法层段级判定），原则宁可错杀不可错放——免确认直接执行），`full`（完全权限）级别免确认直接执行。`run_command` / `process_start` 默认在 OS 沙箱内执行（`sandbox/` sidecar：断网、全盘只读、仅白名单目录可写、读取不限工作区且三平台全盘可读；Windows 受限令牌不拦 socket，沙箱内命令进程可联网，属已确认取舍）；sidecar 缺失或 probe 失败静默回退宿主机执行，125+marker 回退在结果中标注原因；`process_stop` 仅允许终止 Kuriboh 启动的进程（`managedPids` 白名单）；打开 GUI 应用/文件/网址一律用 `open_application` 在宿主机执行（沙箱内无显示服务）。
5. **Agent 重建而非原地改**：配置、工作区、权限变化后调用 `createKuribohAgent` 重新构建（见 `syncAgent`），不要直接改运行中 agent 的状态。
6. **终端实现**：不引入 `node-pty`。Linux 用 `script -qec` + `stty`，macOS 用 `script -q /dev/null`，Windows 用 PowerShell。退出事件语义要和前端保持一致：`code === 0` 关闭页签，非 0 / 启动失败保留提示条。
7. **前端零依赖新增**：`public/index.html` 内联所有 JS/CSS，不引入框架、不加 CDN（应用离线运行且走 `kuriboh://` 白名单）。模型输出必须经 `DOMPurify.sanitize(marked.parse(...))` 再插入 DOM。渲染所需第三方资源要登记到 `src/web.ts` 的 `VENDOR` 白名单。
8. **平台与打包**：`npm run build` 用 esbuild 把源码与 JS 依赖（`--packages=bundle`）打成单个 `app.mjs`，只有 `better-sqlite3`、`@webviewjs/webview*`、`@vscode/ripgrep` 保持 external；打包时只复制运行时必需的少量 `node_modules`（原生模块 + `VENDOR` 引用的前端静态资源），新增运行时依赖必须同步 `build.yml` 的 `stage_runtime_deps`。原生依赖按平台在 CI 各自 `npm ci` 获取，新增时需确认三个矩阵平台（linux-x64、darwin-arm64、win32-x64）都有可用产物，控制体积。Go sidecar `kuriboh-sandbox` 由 `npm run build`（先跑 `sandbox/build.mjs`，需 Go ≥ 1.21）在 runner 本机平台编译，三平台打包分支各复制一份进 app 目录——launcher 以 app 目录为 node 进程 cwd，Node 按 `process.cwd()` 定位 sidecar，二者必须同目录。
9. **安全红线**：不打印、不提交 API Key；密钥只存在用户配置目录；不新增会上传用户文件或会话内容的逻辑。

## 代码风格

- TypeScript：2 空格缩进、双引号、分号、`camelCase`；模块级函数优先，避免为一次性逻辑造抽象。
- `public/index.html` 内联 JS 沿用单引号、无框架写法。
- 注释用中文，只写「为什么」，不复述代码；不写大段 JSDoc。
- 依赖改动要最小化：能只用 Node 内置模块就不要加包；删掉不再使用的代码，不留兼容垫片和注释掉的旧实现。

## 变更要求

- 只做被要求的改动，不顺手重构、不扩大 diff。
- 改行为就同步 `README.md`（尤其启动命令、依赖、权限说明）。
- 提交信息说明「为什么」，不要只列文件。
