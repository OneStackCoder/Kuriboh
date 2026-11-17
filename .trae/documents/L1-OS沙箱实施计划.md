# L1 OS 沙箱（kuriboh-sandbox）实施计划

## Context

System Tools（run_command / process_start / process_stop）目前直接在宿主机执行，仅靠逐次确认兜底。本计划引入 OS 级沙箱：命令在受限环境运行（**断网、全盘只读、仅工作区与私有 /tmp 可写；读取不限制在工作区——与 read_file 工具能力对齐，uid 权限照常生效**），沙箱不可用时自动回退「确认后宿主机执行」并在结果中标注。架构为 Node.js + Go Sandbox Runtime（经用户确认由 Rust 调整为 Go，复用仓库既有 Go 工具链与 CI setup-go）：Node 不再直接 spawn sh/powershell，改 spawn Go sidecar `kuriboh-sandbox`，平台后端 Linux=bubblewrap、macOS=sandbox-exec（Seatbelt）、Windows=AppContainer。

**已拍板决策**：
1. 文件工具（read/write/glob/grep）留进程内走现有三级权限模型，不进沙箱。
2. L1 范围：run_command、process_start 进沙箱；新增 `open_application`（宿主机、逐次确认）接管「打开桌面应用」；process_stop 加 PID 白名单（只允许终止 Kuriboh 启动的进程）。
3. run_command 沙箱默认断网；沙箱不可用 → 回退现有确认执行路径 + 标注。

**本机已实证**（Ubuntu 26.04 + bwrap 0.11.1）：参数集经过两轮实测——首轮逐目录 bind 验证了可执行、断网、工作区可写、/etc 只读、进程列表可见、退出码透传；第二轮按「读取不限制在工作区内」的拍板改为 `--ro-bind / /` 全量只读，参数集简化且 merged-usr 坑自然消失。

**实现后追加实测**（linux.go 已落地，CLI 全绿）：
- probe=0；退出码 42 / 信号 143（128+15）透传；stdout 透传。
- **读不限制**：~/.bashrc、/etc/passwd、/var 均可读；uid 权限照常（/etc/shadow Permission denied）。
- **写仅限工作区与私有 /tmp**：~/、/var、/etc 写入均 Read-only file system；沙箱 /tmp 写入对宿主不可见。
- HOME 继承宿主真实值（读 ~ 正常，写 ~ 被只读挡住）；TMPDIR 指私有 tmpfs；ps 可见；断网（curl 退出码 7）。
- start 打印 pgid，`kill -TERM -<pgid>` 组杀成功。
- **sidecar 收 SIGTERM（Node 超时的正常路径）→ signal handler 组杀整树，sidecar 以 137 退出，可靠**。
- **sidecar 被 SIGKILL 时 `--die-with-parent` 实测未级联**：bwrap 主进程死掉，孙进程被 subreaper（PPID≈4249）收养存活。孤儿兜底轮询跑在 sidecar 内，sidecar 已死时同样无效。即宿主强杀 sidecar/Node 可能残留沙箱进程（记入已知限制）；Node 正常超时走 SIGTERM，不受影响。
- 工作区恰为 /tmp 时 `--bind /tmp /tmp` 会盖掉 tmpfs（bind 后者胜出），沙箱内 /tmp 即宿主 /tmp——属工作区语义，非泄漏。
- 宿主环境变量（如 http_proxy）继承进沙箱；代理指向 127.0.0.1 时因断网天然失效，L1 接受。
- **windows.go 已落地**：三平台交叉编译 + GOOS=windows go vet 通过（x/sys pin v0.30.0，其 go 指令 1.18，兼容 CI 由 launcher/go.mod 决定的 go 1.21 工具链）；run/start 经 `prepareSandbox` 一并授权工作区 (OI)(CI)F 与 %USERPROFILE% (OI)(CI)RX（已拍板放开用户目录读取；probe 不授权、无持久化副作用；任一授权失败判沙箱不可用，Node 回退宿主）；运行行为待 Windows 真机手测（probe 失败自动回退保底）。
- **Node 侧已落地并实测**（src/tools.ts / src/agent.ts / 构建集成）：真实沙箱、fake sidecar（注入 125+marker）、无 sidecar 三档共 18 项断言全过（见「验证」末尾）；launcher/main.go 已确认 `cmd.Dir = appDir/app`，打包态 node 进程 cwd 即 app 目录，`process.cwd()` 定位 sidecar 在 AppImage / zip / .app 三种布局下均成立。
- **darwin.go 已落地**（sandbox-exec 单行 profile）：GOOS=darwin go vet + darwin/linux/windows 三平台交叉编译通过；运行行为待 macOS 真机手测（probe 失败自动回退保底）。与 Linux 的语义差异：tmp 是宿主共享 /tmp（非私有 tmpfs；TMPDIR 显式重定向过去，否则默认 /var/folders/… 被 deny 拦住不可写）；(allow default) 未禁 mach*，GUI 程序可能真能启动（Linux 因无显示 socket 天然不可用）。

## Node ↔ Sidecar 契约

- 二进制定位：`path.join(process.cwd(), "kuriboh-sandbox" + (win32 ? ".exe" : ""))`（仿 web.ts 的 ROOT 模式；开发态 cwd=项目根，打包态 cwd=app 目录）。
- 子命令：`probe` ｜ `run --cwd <p> -- <argv…>` ｜ `start --cwd <p> -- <argv…>`（run 也是 argv 数组：Node 侧把 shell argv 整体传入，沙箱内实际由 `sh -c` / `powershell -Command` 执行用户命令）。
- **不可用判定（双保险）**：退出码 125 **且** stderr 首行 `KURIBOH_SANDBOX_UNAVAILABLE: <原因>`（125 单独可能来自用户命令，不可仅凭退出码判断）。
- run 模式：sidecar 透传 stdio，以子进程退出码退出；start 模式：Unix 下 sidecar 首行输出 pgid 后退出（pid==pgid），Windows 输出 pid。

## 平台后端要点

**Linux（bubblewrap）**——参数集（已实测，`--ro-bind / /` 读取放开版）：
```
bwrap --ro-bind / /  --dev /dev  --proc /proc  --tmpfs /tmp
  --bind <ws> <ws>  --chdir <ws>  --unshare-net  --unshare-ipc
  [--die-with-parent]  --setenv TMPDIR /tmp
  -- <argv…>
```
- `--ro-bind / /` 全量只读挂宿主 rootfs：读取不限制在工作区（与 read_file 能力对齐），uid 权限照常、无提权；写入全被只读挡住。HOME 继承宿主真实值（读 ~ 正常、写 ~ 被挡）。
- `--dev /dev`、`--proc /proc`、`--tmpfs /tmp` 须在 ro-bind 之后按序覆盖；/tmp 变为沙箱私有 tmpfs。merged-usr（/bin→/usr/bin 符号链接）无需逐目录 bind，坑自然消失。
- run 带 `--die-with-parent`、start 不带（发射后不管，靠 pgid 组杀）。注意：die-with-parent 实测**不级联孙进程**，run 超时杀整树的真正防线是 sidecar 的 SIGTERM handler 组杀（见「实现后追加实测」）。
- probe 全保真：用真实挂载集跑 `true`（不能只测 bwrap 存在，参数集错误是静默失败）。
- **不用 --unshare-pid**：保住 `ps`/进程列表查询（最初的需求场景）；同 uid kill 残留风险记入已知限制，L2 加 seccomp。

**macOS（sandbox-exec）**：`sandbox-exec -p '<单行 profile>' -- <argv…>`（profile 作为单个 argv 传入，无需临时文件）；profile：`(version 1)(allow default)(deny network*)(deny file-write*)(allow file-write* (subpath "/private/tmp"))(allow file-write* (subpath "<ws>"))`。无 netns，网络状态查询仍可用。sidecar 需 SIGTERM handler（`signal.Notify`，Unix 构建标签门控）`syscall.Kill(-child_pgid, SIGKILL)` 组杀后透传退出码。（**已落地、编译级验证**：GOOS=darwin go vet + 交叉编译通过，运行待 macOS 真机手测，probe 失败自动回退保底。实现要点：/tmp 与 /private/tmp 双写法放行——Seatbelt 按路径字符串匹配、不解析符号链接；工作区经 `filepath.EvalSymlinks` 后原路径与真实路径双放行；TMPDIR 重定向到 /tmp——macOS 默认 TMPDIR 是 /var/folders/…，不重定向则 mktemp 全被 deny 拦下）

**Windows（AppContainer，已落地、编译级验证，运行待真机）**：`x/sys/windows` v0.30.0 覆盖大部分 typed API（NewProcThreadAttributeList / StartupInfoEx / EXPLICIT_ACCESS+TRUSTEE / GetNamedSecurityInfo+SetNamedSecurityInfo / FreeSid / Job Object 全套 / STD 句柄）；手写仅剩 userenv 三 API（DeriveAppContainerSidFromAppContainerName → 失败再 CreateAppContainerProfile、GetAppContainerFolderPath）、SetEntriesInAclW（DACL 合并）、CoTaskMemFree，以及 SECURITY_CAPABILITIES 结构与属性常量 0x00060007（**capability 数 0 即断网**）。要点：
- 工作区授权（`prepareSandbox`，run/start 共用；probe 不授权）：GetNamedSecurityInfo → SetEntriesInAclW（GRANT_ACCESS 合并、幂等）→ SetNamedSecurityInfo 给容器 SID 授工作区 (OI)(CI)F、%USERPROFILE% (OI)(CI)RX（`fileRxAccess`=0x1200A9，已拍板放开用户目录读取，尽量对齐 Linux 全盘可读；任一授权失败判沙箱不可用）；**ACE 持久化在宿主文件系统**（Linux bind 是会话级）。
- TEMP/TMP 显式重建 Unicode 环境块（CREATE_UNICODE_ENVIRONMENT）重定向到容器私有目录（GetAppContainerFolderPath，等价私有 tmpfs）。
- run：直接继承本进程 std 句柄透传（STARTF_USESTDHANDLES + 句柄标 INHERIT，未用 CreatePipe 复制循环）+ CREATE_NO_WINDOW；Job Object + KILL_ON_JOB_CLOSE（CREATE_SUSPENDED → Assign → Resume 防逃逸）——sidecar 被杀时内核级联杀整树。
- start：DETACHED_PROCESS、不进 Job、零 stdio，打印 pid。
- argv → 命令行：escapeArg 按 CommandLineToArgvW 反解析规则转义（CreateProcessW 只收整条命令行字符串，且缓冲区须可写）。
- probe = 容器内跑 `cmd /c ver`（不碰工作区 ACL，探测不产生持久化副作用）。
- 与 Linux 语义差异：**读取范围由宿主 ACL 决定**——系统目录默认含 ALL APPLICATION PACKAGES 读 ACE；用户目录默认不可读，已按拍板给 %USERPROFILE% 持久化加 (OI)(CI)RX 放开（关闭继承的部分子目录仍读不到，其余盘位依旧受 ACL 制约，做不到 ro-bind 式全盘可读）；run 模式因 KILL_ON_JOB_CLOSE，sidecar 退出时命令留下的后台孙进程会被一并杀掉（Unix 侧无此行为）。

## 文件改动清单

**新建 `sandbox/`（Go module `kuriboh/sandbox`，已落地；依赖 `golang.org/x/sys` v0.30.0，仅 windows.go 引用）**
- `go.mod`：module kuriboh/sandbox，go 1.21（与 launcher 一致，CI 复用同一 setup-go 工具链，无需新增）。
- `main.go`：子命令解析、125+marker 统一出口；`unix.go`（`!windows` 构建标签）：`SysProcAttr{Setpgid}`、`signal.Notify` 组杀、`os.Getppid()==1` 孤儿兜底轮询、退出码透传（code 或 128+signal）；`linux.go` / `darwin.go` / `windows.go`（构建标签互斥）均已实现 probe/run/start（linux 实测全绿；darwin / windows 编译级验证，运行待真机手测）。

**`src/tools.ts`（已落地并实测）**
- `runShellCommand` 改签名 `(file, argv, cwd, timeoutMs)`（泛化现有 spawn，沙箱与宿主回退共用一套；200K 缓冲 / AbortSignal.timeout / close/error 竞争处理）。
- 新增基础设施：`SANDBOX_BIN` 路径解析（`process.cwd()` + 平台后缀）、模块级 probe 缓存（`sandboxProbe`：5s 超时 / ENOENT / 非零退出均判不可用，结果缓存到进程退出）、`sandboxReason`（125 且 stderr 首行 marker 双条件判定）、`runInSandbox`（结果附 `unavailable` 原因）、`shellArgv`（win PowerShell 先切 UTF-8、其余 `/bin/sh -c`，沙箱与回退共用保证行为一致）、`spawnDetached`（detached + stdio ignore + unref）。
- `run_command`：沙箱优先。回退分两档：probe 失败（sidecar 缺失/超时/非零退出，含 macOS 后端未实现期）→ 静默宿主执行、不标注（与沙箱引入前行为一致）；125+marker → 宿主执行，结果前加「（沙箱不可用：<原因>；以下为宿主机直接执行的结果）」。
- `process_start`：沙箱 `start` 模式（5s 超时，stdout 首行解析 pgid/pid），返回「已在沙箱内启动 <label>（PID <pid>）」；probe 失败或 125+marker → 宿主 `spawnDetached`（回退不标注）；模块级 `managedPids: Map<number, {command, time}>` 登记两条路径，agent 重建不清空。
- `process_stop`：先查 `managedPids` 白名单，不在表内拒绝终止；`pid === process.pid` 自杀保护；Unix `kill(-pid)` 组杀（两条路径 pgid==pid 已实测）、Windows `kill(pid)`；ESRCH 时清登记。
- 新增 `open_application`（schema: `target` 字符串）：win `cmd /c start "" <target>`（start 首个引号参数是窗口标题占位）、mac `open`、linux `xdg-open`；`spawnDetached` 宿主机执行，不登记 PID。

**`src/agent.ts`（已落地）**
- `GATED_SYSTEM_TOOLS` 增加 `open_application`（verb「打开应用」，detail=target）。
- 系统提示词：run_command / process_start 默认在 OS 沙箱内执行（断网、系统目录只读、仅当前工作区可写），沙箱不可用自动回退宿主机并在结果中标注；沙箱内跑不了 GUI 程序，打开应用用 open_application；process_stop 仅限 Kuriboh 启动的进程。

**构建 / CI（已落地）**
- `package.json`：+`"build:sandbox"`（`node sandbox/build.mjs`：go build + 复制二进制到项目根，Windows 加 `.exe`，供 `npm start` 开发态用）。
- `.github/workflows/build.yml`：`npm run build` 内先跑 `sandbox/build.mjs`（Build app bundle 步骤，runner 本机平台编出 `kuriboh-sandbox(.exe)` 到仓库根，复用既有 setup-go）；packaging 三平台分支各加一行 cp 进 app 目录（launcher 以 app 目录为 node 进程 cwd，`process.cwd()` 定位要求二者同目录）。
- `.gitignore`：+`/kuriboh-sandbox`、`/kuriboh-sandbox.exe`，以及 sandbox/ 内 `go build .` 的散落产物 `/sandbox/sandbox`、`/sandbox/sandbox.exe`。

**文档**
- `AGENTS.md`：目录职责加 `sandbox/`；红线 4 补（沙箱语义、回退、open_application、process_stop 白名单）；红线 8 补 Go sidecar（kuriboh-sandbox 二进制）staging；运行与验证补 build:sandbox。
- `README.md`：依赖表加 Linux bubblewrap（可选，缺失自动回退）。

## 验证

1. **装 Go**：`sudo apt install golang-go`（Ubuntu 26.04 候选 1.26；无 root 时官方 tarball 解压到 `~/.local/go`）→ `node sandbox/build.mjs`。
2. **sidecar CLI**：`probe`（退出 0）；`run -- 'exit 42'`（透传 42）；断网/工作区可写//etc 只读（同已实测命令）；`start -- /tmp -- sleep 300` → `kill -TERM -<pgid>` 验组死；制造不可用（改 PATH 或临时改名 bwrap 探测）→ 125+marker。
3. **typecheck**：`npm run typecheck`（注意 PATH 需加 `~/.nvm/versions/node/v24.20.0/bin`）。
4. **Node 侧**（只 import `src/tools.ts`，勿 import agent.ts——会开 webview 窗口）：调 run_command 验证沙箱执行与回退标注、process_stop 白名单拒杀未登记 PID、open_application 返回文案。
5. **端到端**：`npm run build:sandbox && npm start`，手动验证确认卡片（前端零改动）、run_command 断网、process_start sleep → process_stop 组杀、open_application 打开真实应用。
6. **Windows/macOS**（本环境不可验证）：靠回退兜底；用户手测清单：probe/run/start、断网、工作区 ACL、任务管理器查残留进程。

**已实测（本机 Linux，Node 侧全链路）**：`npm run typecheck` 通过、`npm run build:sandbox` 产出项目根二进制（1.9MB），18 项断言全过——真实沙箱 12 项（pwd=工作区、读 ~/.bashrc、写 HOME 被 Read-only file system 挡、写工作区 OK、exit 42 透传、1s 超时终止无残留、process_start 返回 pgid==pid、process_stop 组杀、ESRCH 清登记、白名单外 PID 拒绝、自杀保护等）；fake sidecar 注入 125+marker 5 项（run_command 回退带「（沙箱不可用：fake-injected-failure；以下为宿主机直接执行的结果）」标注、process_start 宿主回退登记并组杀）；无 sidecar 1 项（静默宿主执行无标注）。

## 已知限制（注明 L2 方向）

- 不 unshare-pid（保进程列表查询）→ 同 uid 进程间 kill 阻不断，L2 加 seccomp 过滤 kill/ptrace。
- 宿主强杀（SIGKILL）sidecar/Node 时沙箱进程可能残留：die-with-parent 实测不级联孙进程，sidecar 内的孤儿轮询随 sidecar 一起消亡。Node 正常超时路径（SIGTERM）经 signal handler 组杀，已验证可靠。
- 沙箱内 GUI 应用不可用（无显示 socket）——open_application 留宿主执行的依据。
- daemon 双 fork 可能逃逸 pgid 组杀；Windows 孙进程逃逸单 pid kill。
- Windows 读取范围受宿主 ACL 制约（系统目录默认可读），与 Linux ro-bind 全盘可读不完全一致——已按拍板给 %USERPROFILE% 持久化加 (OI)(CI)RX 放开用户目录，但关闭继承的子目录仍读不到、其余盘位依旧受限。
- Windows 工作区 ACL 授权持久化在宿主文件系统（Linux bind 为会话级）。
- Windows run 模式因 KILL_ON_JOB_CLOSE，sidecar 退出时命令留下的后台孙进程会被一并杀掉（比 Unix 严格；Unix 的 run 后台子进程可存活）。
- Windows AppContainer 分支未经真机运行验证，首次实测可能需按反馈调整（probe 失败自动回退保底）。
- macOS tmp 为宿主共享 /tmp（/private/tmp），非 Linux 式私有 tmpfs——沙箱内临时文件对宿主可见，并与宿主进程共享该目录。
- macOS profile 用 (allow default)（仅 deny 网络与写盘），未禁 mach*：GUI 程序在沙箱内可能真启动（Linux 因无显示 socket 天然不可用）；sandbox-exec 被 Apple 标记为废弃但持续可用，L2 可改 deny default + 枚举放行收紧。
