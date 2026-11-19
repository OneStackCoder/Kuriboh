# Kuriboh 沙箱（kuriboh-sandbox）技术原理

Kuriboh 对两类高风险操作做 OS 级沙箱隔离：**系统命令 / 进程启动**（run_command / process_start）与**文件读写搜索**（read_file / write_file / edit_file / list_directory / glob_search / grep_search）。本文说明这套沙箱的架构、平台实现与安全边界；使用层面的依赖与权限说明见 [README.md](README.md)。

## 为什么是一个 Go sidecar

OS 级沙箱机制（Linux bubblewrap / Windows 受限访问令牌 / macOS Seatbelt）都要求「先建立沙箱，再在沙箱内 exec 新进程」——进程无法把自己圈进沙箱。而 Node 无法放弃自身能力去 exec：主进程承载 webview 宿主、Agent 与 RPC，必须继续运行。因此所有受限操作交给独立二进制 `kuriboh-sandbox`（`sandbox/` 用 Go 编写，`npm run build:sandbox` 产出）：Node spawn 它 → 它建立沙箱 → 沙箱内 exec 目标命令或自身。

```
Node 主进程（src/tools.ts）
    │ spawn kuriboh-sandbox …
    ▼
kuriboh-sandbox（Go sidecar）── 建立沙箱 ──▶ OS 沙箱
    │                                      Linux:      bubblewrap + Landlock
    │                                      Windows:    Restricted Token + ACL
    │                                      macOS:      Seatbelt (sandbox-exec)
    ▼
沙箱内执行：用户命令 / rg 搜索 / 自 exec 做纯 Go 文件 IO
```

沙箱保证的语义：**全盘只读、仅白名单目录可写**；读取不限制在工作区，三平台全盘可读（uid / DACL 权限照常生效，他人私有文件照常拒绝）。网络不隔离（沙箱只 containment 写入，网络不在威胁模型，对齐 DSH）：Linux bwrap 不加 `--unshare-net`、macOS Seatbelt 不 `deny network*`、Windows 受限令牌不拦 socket（`go mod tidy` / `npm install` 等包管理命令需联网拉依赖，见下文各平台章节），三平台沙箱内命令进程可联网、属已确认取舍。

## 统一的硬失败语义

| 工具 | sidecar 子命令 | 沙箱不可用时 |
| --- | --- | --- |
| run_command / process_start（readonly / workspace 级） | `run` / `start` | **硬失败拒绝**，不回退 |
| read_file / write_file / edit_file / list_directory | `fs read/write/list` | **硬失败拒绝**，不回退 |
| glob_search / grep_search | `run`（跑捆绑 rg） | **硬失败拒绝**，不回退 |

沙箱内工具一律不回退：这些路径不经用户逐次确认（或属免确认读取），写入 containment 全靠沙箱在执行层硬性保证，静默落到无约束的宿主机即越权——**写路径宁可失败不可越权**。权限级别决定路由：`readonly` 级命令在 `ro` 档全盘只读执行，`workspace` 级在 `ws` 档执行（写入被限制在工作区、临时目录与语言缓存目录内），`full` 级不经沙箱直接在宿主机执行（完全权限语义，不受本沙箱约束）。edit_file 是 `fs read` + `fs write` 的组合：读走 ro 档，写回走 write_file 同一 scope 判定。

## scope 三档

| 档 | 可写范围 | 使用方 |
| --- | --- | --- |
| `ro` | 全盘只读（仅私有临时目录可写） | read_file / list_directory / rg 搜索；`readonly` 级 run_command / process_start |
| `ws` | 工作区 ∪ 临时目录 ∪ 语言缓存目录（npm / NuGet / pip / Go / Cargo / Maven 等默认缓存，见 `sandbox/cache.go`） | `workspace` 级 run_command / process_start；权限面允许的工作区内写入 |
| `home` | 工作区 ∪ 用户主目录 ∪ 临时目录 | 经用户确认的工作区外写入（恒含工作区） |

即便用户在确认卡片批准了工作区外写入，OS 也只放开到 `home` 档——写入不可能越过「HOME ∪ 工作区 ∪ 临时目录 ∪ 语言缓存目录」，这就是写入 containment。

## CLI 契约

```text
kuriboh-sandbox probe                                     # 探测沙箱机制可用（全保真，见下）
kuriboh-sandbox run   --cwd <dir> [--scope <ro|ws|home>] -- <argv…>
                                                       # 沙箱内执行，透传 stdio 与退出码
kuriboh-sandbox start  --cwd <dir> [--scope <ro|ws|home>] -- <argv…>   # 沙箱内启动，首行打印 pgid/pid 后退出
kuriboh-sandbox fs <read|write|list> --cwd <dir> --scope <ro|ws|home> -- <绝对路径>
                                                       # 沙箱内文件 IO（write 经 stdin 传内容）
```

- **不可用契约**：沙箱无法建立时，sidecar 以 stderr 首行 `KURIBOH_SANDBOX_UNAVAILABLE: <原因>` + 退出码 125 退出。两者**同时成立**才判定「沙箱未建立」——退出码 125 单独不可信，用户命令也可能恰好退出 125。
- **probe 全保真**：不是检查依赖二进制是否存在，而是按真实配置完整建一次沙箱、跑无害命令（Linux 上即 `bwrap + Landlock` 全量生效后执行 `/usr/bin/true`），能暴露 profile 语法错误、setuid 缺失等真实故障。Node 侧探测结果缓存到进程退出，避免每次操作都付出探测成本。

## 平台实现

### Linux：bubblewrap + Landlock 双层防线

bwrap（bubblewrap）通过 mount namespace 建立隔离：

- `--ro-bind / /`——rootfs 整体只读挂载；
- 工作区 / 用户主目录按 scope 决定只读或可写挂载；
- `--tmpfs /tmp`——沙箱私有临时目录，与宿主 /tmp 互不可见；
- `--dev /dev`、`--proc /proc`——最小设备与进程文件系统；
- 不加 `--unshare-net`——保留网络：`go mod tidy` / `npm install` 等包管理命令需联网拉依赖；写入 containment 已由只读挂载 + Landlock 保证，网络不在沙箱威胁模型。

Landlock 是 Linux ≥ 5.13 内核自带的 LSM（无需安装，版本满足即自动启用）：对进程施加**内核态写入白名单**，白名单内路径之外的任何写打开直接 EACCES。bwrap 与 Landlock 互相独立、各自生效——bwrap 保证挂载布局，Landlock 保证即使布局被某种方式绕过，写权限仍被内核拦截。启用时机在沙箱内进程 exec 下一个程序之前（见「自 exec 双层设计」）。

### Windows：Restricted Token（受限访问令牌）+ ACL

从自身令牌派生受限令牌（`CreateRestrictedToken`，标志 `DISABLE_MAX_PRIVILEGES | WRITE_RESTRICTED`），挂入固定的 Kuriboh 限制 SID。`WRITE_RESTRICTED` 的语义恰好对齐 Linux 的 `--ro-bind / /`：

- **读放行**：读 / 执行访问只走普通 DACL 校验（用户身份不变）——**全盘可读**，他人私有文件照常被拒；`DISABLE_MAX_PRIVILEGES` 清空特权，封堵 SeBackup / SeTakeOwnership 等 ACL 旁路。
- **写管住**：写访问走双重校验（普通 DACL **且** 限制 SID 获授权）——宿主盘上默认不含该 SID 的 ACE，**全盘默认禁写**；再按 scope 对白名单目录授予 F（ws=工作区 ∪ 语言缓存目录，home=HOME ∪ 工作区），子目录容器继承。
- **临时目录**：每次启动私有实例（授予 F 并重定向 `TEMP` / `TMP`），run 结束即删。
- **进程清理**：Job Object（KILL_ON_JOB_CLOSE）+ 挂起启动、Assign 后 Resume，sidecar 退出即清场。
- **已知取舍**：受限令牌不拦 socket，沙箱内命令进程**可联网**（Linux / macOS 同样不隔离网络，已确认接受）；Everyone 可写目录对沙箱进程可写（同 uid 语义，Linux 本就如此）。受限令牌与 ACL 为内核强制，单层防线即生效。

### macOS：Seatbelt（sandbox-exec）

使用系统自带 `sandbox-exec`，profile 以单行字符串经 `-p` 传入（无需临时文件）：

```scheme
(allow default) (deny file-write*)
  (allow file-write* (subpath "/tmp") (subpath "<按 scope 放行的目录>") …)
```

- 网络保留（`allow default` 即放行 socket）：`go mod tidy` 等包管理命令可联网，与 Linux / Windows 一致；
- Seatbelt 按路径**字符串**匹配、不解析符号链接，因此放行路径做双写法：`/tmp` 与真实路径 `/private/tmp`，工作区 / 主目录也经 `EvalSymlinks` 解析真实路径后放行；
- 沙箱内把 `TMPDIR` 重定向到 `/tmp`（macOS 默认的 `/var/folders/…` 不在放行列表内）；
- 与 Linux 不同，macOS 的 `/tmp` 是**宿主共享目录**（非私有实例），沙箱内临时文件对宿主可见。

> macOS 后端目前为编译级验证（CI 的 darwin-arm64 矩阵确认可编译），运行行为待真机实测。

## 自 exec 双层设计

文件 IO 没有外部命令可借用（沙箱里没有 shell / cat），因此 fs 三操作用纯 Go 实现，同一二进制分内外两层跑：

```
kuriboh-sandbox fs read …            # 外层：解析参数 → 建沙箱 → 在沙箱内 exec 自身
  └─ kuriboh-sandbox _fsread …       # 内层：已在沙箱中，启用 Landlock → 直接 os.ReadFile
```

外层负责建立沙箱与授权，内层做纯 Go IO（write 的内容经 stdin 传入，含父目录自动创建）。`run` 在 Linux 上同理：bwrap 内 exec 自身 `_exec` 内层，启用 Landlock 后再 exec 用户目标命令，保证用户命令也受 Landlock 白名单约束。

## 安全边界

- **写入 containment**：OS 按 ro/ws/home 三档硬性保证，见上表；确认后的区外写也仅限 HOME、临时目录与语言缓存目录。
- **symlink 逃逸封堵**：工作区 / 主目录解析真实路径后挂载与授权（Linux bind + Landlock 白名单、macOS 双写法），指向区外的符号链接无法借道。
- **网络不隔离（已知取舍）**：三平台沙箱内命令均可联网（`curl`、`pip install`、`go mod tidy` 等照常工作）——沙箱防的是「越权写盘」而非「联网」，下载的内容也只能写进白名单目录。信息检索类工具（web_search / web_fetch）在 Node 进程内直接请求，不经沙箱。
- **进程管理**：process_stop 仅允许终止 Kuriboh 自己启动的进程（pgid / pid 白名单，Unix 下组杀不误伤）。
- **权限确认**：不做命令语义分析，写入 containment 完全交给本沙箱在执行层按权限级别硬性保证。文件写入按 readonly / workspace / full 三级确认；run_command / process_start 免确认执行（readonly=ro 档、workspace=ws 档、full=不经沙箱宿主机直跑）；process_stop 只能终止 Kuriboh 自己启动的进程、同样免确认；open_application 在宿主机执行、「完全权限」外逐次经用户确认（详见 AGENTS.md 红线 4）。

## 已知局限

- macOS 后端编译级验证、待真机实测；
- 网络不隔离：三平台沙箱内命令进程均可联网（Windows 受限令牌不拦 socket 等），属已确认取舍；
- 工作区或目标文件位于 `/tmp` 下时，Linux 的 `--tmpfs /tmp` 会遮蔽宿主 /tmp，read/list 将失败——工作区请放在常规目录；
- rg 搜索与文件操作统一 30 秒超时；
- fs write 为截断后写入、非原子：进程被强杀可能留下截断文件；
- glob_search 弃用 globby 后的细微差异：超大匹配计数显示为「超过 200 个」；`--no-ignore` 下会列出被 gitignore 的文件（与 globby 旧行为一致）；Windows 路径分隔符为 `\`。

## 代码地图

| 位置 | 职责 |
| --- | --- |
| `sandbox/main.go` | CLI 分发、125+marker 不可用契约、自 exec 内层 |
| `sandbox/linux.go` | bwrap 参数构造（各平台文件中含头注释说明平台语义） |
| `sandbox/landlock.go` / `landlock_stub.go` | Landlock 白名单（5.13+ 编译启用，旧内核空实现） |
| `sandbox/windows.go` | Restricted Token（受限访问令牌）+ ACL |
| `sandbox/darwin.go` | Seatbelt profile |
| `sandbox/fs.go` | fs 内层纯 Go IO（read / write / list） |
| `sandbox/unix.go` | 进程等待与 SIGTERM 组杀 |
| `src/tools.ts` | Node 侧基建：probe 缓存（isSandboxAvailable）、runInSandbox、runFsOp、runRipgrep（沙箱内跑 rg） |
