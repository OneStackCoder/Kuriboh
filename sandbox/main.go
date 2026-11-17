// kuriboh-sandbox：System Tools（run_command / process_start）与文件工具的 OS 级沙箱 sidecar。
//
// Node 侧不再直接 spawn sh/powershell 或用进程内 fs，改 spawn 本二进制：
//
//	kuriboh-sandbox probe                          —— 探测沙箱机制是否可用（全保真：按真实挂载/容器配置跑无害命令）
//	kuriboh-sandbox run  --cwd <dir> [--scope <ro|ws|home>] -- <argv…>
//	                                            —— 沙箱内执行，透传 stdio 与退出码（--scope 默认 ws）
//	kuriboh-sandbox start --cwd <dir> -- <argv…>   —— 沙箱内启动，首行打印 pgid（Unix）/ pid（Windows）后退出
//	kuriboh-sandbox fs <read|write|list> --cwd <dir> --scope <ro|ws|home> -- <绝对路径>
//	                                            —— 外层：建沙箱后在其中 exec 自身（自 exec 双层）
//	kuriboh-sandbox _fs<read|write|list> --scope <s> --cwd <dir> -- <绝对路径>
//	                                            —— 内层：已被外层 exec 进沙箱，直接做纯 Go IO（fs.go）
//	kuriboh-sandbox _exec --scope <ro|ws|home> --cwd <dir> -- <argv…>
//	                                            —— 内层（仅 Linux 外层构造）：启用 Landlock 后 exec 目标命令
//
// 沙箱语义（各平台后端保证）：断网、全盘只读、仅白名单目录可写；
// 读取不限制在工作区，三平台全盘可读（uid/DACL 权限照常生效；Windows 受限令牌
// 不拦 socket，断网缺失见 windows.go 头注释；临时目录 Linux/Windows 为私有实例，
// macOS 为宿主共享 /tmp，见 darwin.go 头注释）。
// scope 三档：ro=全盘禁写（read/list 用）；ws=工作区∪tmp 可写（run/start 现语义）；
// home=工作区∪$HOME∪tmp 可写（full 级写工作区外文件用，恒含工作区）。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// 不可用统一出口：stderr 首行 marker + 退出码 125，两者同时出现 Node 才判定
// 「沙箱不可用 → 回退宿主机执行」。125 单独不可信：用户命令也可能恰好退出 125。
func unavailable(reason string) {
	fmt.Fprintf(os.Stderr, "KURIBOH_SANDBOX_UNAVAILABLE: %s\n", reason)
	os.Exit(125)
}

func usage() {
	fmt.Fprintln(os.Stderr, "用法: kuriboh-sandbox probe | run --cwd <目录> [--scope <ro|ws|home>] -- <argv…> | start --cwd <目录> -- <argv…> | fs <read|write|list> --cwd <目录> --scope <ro|ws|home> -- <绝对路径>")
	os.Exit(2)
}

func validScope(s string) bool {
	return s == "ro" || s == "ws" || s == "home"
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "probe":
		if err := sandboxProbe(); err != nil {
			unavailable(err.Error())
		}
	case "run", "start":
		cwd, scope, argv, ok := parseRunArgs(os.Args[2:])
		if !ok || (os.Args[1] == "run" && !validScope(scope)) {
			usage()
		}
		// 工作区挂载是沙箱配置的一部分，目录不存在就无法建沙箱；
		// 报不可用让 Node 回退宿主执行（宿主侧同样会给出明确报错）
		if st, err := os.Stat(cwd); err != nil || !st.IsDir() {
			unavailable("工作目录不可用: " + cwd)
		}
		// start 只有 process_start 一个调用方，恒 ws 语义，不吃 scope
		if os.Args[1] == "start" {
			scope = "ws"
		}
		// run/start 改道自 exec：Linux 包 _exec 内层（bwrap 内启用 Landlock 后
		// 再 exec 目标命令），macOS/Windows 原样直 exec（单层内核防线）。
		// fs 外层的自 exec argv 不走这条改道
		inner, err := execArgv(cwd, scope, argv)
		if err != nil {
			unavailable(err.Error())
		}
		if os.Args[1] == "run" {
			err = sandboxRun(cwd, scope, inner)
		} else {
			err = sandboxStart(cwd, inner)
		}
		// 返回 error 只代表「沙箱无法建立」（后端缺失、挂载失败等）；
		// 用户命令的退出码不走这条路径，由 sandboxRun 内部直接 os.Exit 透传
		if err != nil {
			unavailable(err.Error())
		}
	case "fs":
		sub, cwd, scope, target, ok := parseFsArgs(os.Args[2:])
		if !ok || !validScope(scope) || !filepath.IsAbs(target) {
			usage()
		}
		if st, err := os.Stat(cwd); err != nil || !st.IsDir() {
			unavailable("工作目录不可用: " + cwd)
		}
		// 读类操作恒只读档：写权限面为零，Node 侧误传也不放大
		if sub == "read" || sub == "list" {
			scope = "ro"
		}
		self, err := os.Executable()
		if err != nil {
			unavailable("定位 sidecar 自身失败: " + err.Error())
		}
		// 沙箱内全盘可读：自 exec 读 sidecar 自身、读 target 本体均无需逐路径授权
		inner := []string{self, "_fs" + sub, "--scope", scope, "--cwd", cwd}
		if err := sandboxRun(cwd, scope, append(inner, "--", target)); err != nil {
			unavailable(err.Error())
		}
	case "_fsread", "_fswrite", "_fslist":
		// 内层：外层已把我们 exec 进 OS 沙箱。Linux 按 scope 启用 Landlock
		// 写白名单（第二道防线，尽力启用：内核不支持时静默跳过，见 landlock.go），
		// 然后做纯 Go IO
		scope, cwd, target, ok := parseInnerFsArgs(os.Args[2:])
		if !ok || !validScope(scope) || !filepath.IsAbs(target) {
			usage()
		}
		enableLandlock(scope, cwd)
		fsInner(strings.TrimPrefix(os.Args[1], "_fs"), target)
	case "_exec":
		// 内层：仅 Linux 外层构造（run/start 改道）。启用 Landlock 第二道防线
		// 后把进程映像替换为目标命令（execInner，各平台后端文件）
		cwd, scope, argv, ok := parseRunArgs(os.Args[2:])
		if !ok || !validScope(scope) {
			usage()
		}
		execInner(cwd, scope, argv)
	default:
		usage()
	}
}

// 解析 run 的参数段：--cwd <dir>（必填）[--scope <s>] -- <argv…>，
// "--" 后整段是子命令 argv（Node 侧构建完整 shell argv，如 unix 的
// ["sh","-c",cmd]，沙箱与宿主回退共用同一套）
func parseRunArgs(args []string) (cwd, scope string, argv []string, ok bool) {
	i := 0
	for i < len(args) {
		switch args[i] {
		case "--cwd":
			if i+1 >= len(args) || cwd != "" {
				return "", "", nil, false
			}
			cwd = args[i+1]
			i += 2
		case "--scope":
			if i+1 >= len(args) || scope != "" {
				return "", "", nil, false
			}
			scope = args[i+1]
			i += 2
		case "--":
			if cwd == "" || i+1 >= len(args) {
				return "", "", nil, false
			}
			if scope == "" {
				scope = "ws"
			}
			return cwd, scope, args[i+1:], true
		default:
			return "", "", nil, false
		}
	}
	return "", "", nil, false
}

// 解析 fs 外层参数段：<sub> --cwd <dir> --scope <s> -- <target>（-- 后必须恰好一个绝对路径）
func parseFsArgs(args []string) (sub, cwd, scope, target string, ok bool) {
	if len(args) == 0 || args[0] != "read" && args[0] != "write" && args[0] != "list" {
		return "", "", "", "", false
	}
	sub, args = args[0], args[1:]
	i := 0
	for i < len(args) {
		switch args[i] {
		case "--cwd":
			if i+1 >= len(args) || cwd != "" {
				return "", "", "", "", false
			}
			cwd = args[i+1]
			i += 2
		case "--scope":
			if i+1 >= len(args) || scope != "" {
				return "", "", "", "", false
			}
			scope = args[i+1]
			i += 2
		case "--":
			if cwd == "" || scope == "" || i+2 != len(args) {
				return "", "", "", "", false
			}
			return sub, cwd, scope, args[i+1], true
		default:
			return "", "", "", "", false
		}
	}
	return "", "", "", "", false
}

// 解析 _fs 内层参数段：--scope <s> --cwd <dir> -- <target>（-- 后必须恰好一个参数）。
// cwd 供 Linux 内层构造 Landlock 写白名单（ws/home 档含工作区）
func parseInnerFsArgs(args []string) (scope, cwd, target string, ok bool) {
	i := 0
	for i < len(args) {
		switch args[i] {
		case "--scope":
			if i+1 >= len(args) || scope != "" {
				return "", "", "", false
			}
			scope = args[i+1]
			i += 2
		case "--cwd":
			if i+1 >= len(args) || cwd != "" {
				return "", "", "", false
			}
			cwd = args[i+1]
			i += 2
		case "--":
			if scope == "" || cwd == "" || i+2 != len(args) {
				return "", "", "", false
			}
			return scope, cwd, args[i+1], true
		default:
			return "", "", "", false
		}
	}
	return "", "", "", false
}
