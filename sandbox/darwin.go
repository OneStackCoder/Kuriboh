//go:build darwin

// macOS 后端：sandbox-exec（Seatbelt profile）实现沙箱。
package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// 构造单行 Seatbelt profile，作为单个 argv 传给 sandbox-exec -p（无需临时文件）。
//
// (allow default) 保留读取与进程/系统信息查询——读取不限制在工作区（与 read_file
// 能力对齐，uid 权限照常）；(deny network*) 断网（macOS 无 netns 可用，
// ifconfig / netstat 等只读 ioctl/sysctl 的状态查询不受影响）；
// (deny file-write*) 全盘禁写，再按 scope 放行 subpath：
// ro=仅 tmp；ws=+工作区（现 run/start 语义）；home=+工作区∪$HOME（恒含工作区）。
//
// Seatbelt 按路径字符串匹配、不解析符号链接，所以别名要双写法放行：
// /tmp 是 /private/tmp 的符号链接；工作区/HOME 也可能含符号链接（如 /var → /private/var），
// 原路径与 EvalSymlinks 后的真实路径都得在规则里。
func seatbeltProfile(workspace, scope string) string {
	var b strings.Builder
	b.WriteString("(version 1)(allow default)(deny network*)(deny file-write*)")
	seen := map[string]bool{}
	allow := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			fmt.Fprintf(&b, "(allow file-write* (subpath %q))", p)
		}
	}
	allow("/private/tmp")
	allow("/tmp")
	if workspace != "" && scope != "ro" {
		if real, err := filepath.EvalSymlinks(workspace); err == nil {
			allow(real)
		}
		allow(filepath.Clean(workspace))
	}
	if scope == "home" {
		// HOME 有效性由 sandboxRun 先行校验
		if home := os.Getenv("HOME"); home != "" {
			if real, err := filepath.EvalSymlinks(home); err == nil {
				allow(real)
			}
			allow(filepath.Clean(home))
		}
	}
	return b.String()
}

// 子进程环境：继承宿主全部变量（HOME 指向真实主目录，可读不可写，与 Linux 一致），
// 仅重定向 TMPDIR 到放行的 /tmp——macOS 默认 TMPDIR 是 /var/folders/…，
// 不重定向则 mktemp 等临时文件操作全部被 deny file-write* 拦下。
// 注意 macOS 的 /tmp 是宿主共享目录（非 Linux 式私有 tmpfs），临时文件对宿主可见
func sandboxEnv() []string {
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "TMPDIR=") {
			env = append(env, kv)
		}
	}
	return append(env, "TMPDIR=/tmp")
}

// 组装 sandbox-exec 命令行，run 交给 runAndWait、start 交给 startLaunch（共用进程编排）。
// sandbox-exec 没有 -- 分隔符，子命令紧跟 -p <profile>；Node 侧传入的 argv[0]
// 固定是 shell（如 /bin/sh），不会以 - 开头被误认成 sandbox-exec 的选项
func sandboxExecCommand(cwd, scope string, argv []string) *exec.Cmd {
	cmd := exec.Command("sandbox-exec", append([]string{"-p", seatbeltProfile(cwd, scope)}, argv...)...)
	cmd.Env = sandboxEnv()
	return cmd
}

func sandboxProbe() error {
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		return errors.New("sandbox-exec 不可用（macOS 沙箱依赖，系统应自带 /usr/bin/sandbox-exec）")
	}
	// 全保真探测：与 run 同款 profile 跑 /usr/bin/true，暴露 profile 语法错误、
	// sandbox-init 被拒等真实失败——只查二进制存在不靠谱。probe 无工作区参数，
	// 用 /tmp 占位：顺带走一遍符号链接解析路径，规则构造与 run 侧完全同源
	var errBuf bytes.Buffer
	cmd := sandboxExecCommand("/tmp", "ws", []string{"/usr/bin/true"})
	cmd.Stderr = &errBuf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Run(); err != nil {
		// sandbox-exec 的 stderr 带具体原因，带回去给 Node 显示
		if reason := strings.TrimSpace(errBuf.String()); reason != "" {
			return fmt.Errorf("sandbox-exec 探测失败: %s", reason)
		}
		return fmt.Errorf("sandbox-exec 探测失败: %v", err)
	}
	return nil
}

func sandboxRun(cwd, scope string, roDirs []string, argv []string) error {
	if scope == "home" {
		// home 档放行 $HOME，缺失/无效时明确报沙箱不可用而不是让命令在 profile 内静默被拒
		home := os.Getenv("HOME")
		if home == "" {
			return errors.New("home 档需要 HOME 环境变量")
		}
		if st, err := os.Stat(home); err != nil || !st.IsDir() {
			return fmt.Errorf("HOME 不可用: %s", home)
		}
	}
	// runAndWait 在正常路径透传子命令退出码后 os.Exit，不返回；
	// spawn 失败走 unavailable 出口。
	// roDirs 忽略：(allow default) 读取已全盘放行，无需逐路径授权
	runAndWait(sandboxExecCommand(cwd, scope, argv))
	return nil
}

func sandboxStart(cwd string, argv []string) error {
	// 发射后不管：startLaunch 首行打印 pgid（Setpgid 后 pid==pgid，sandbox-exec
	// 与其子命令同组）后立即退出，终止只靠 process_stop 按 pgid 组杀。
	// start 恒 ws 语义（唯一调用方 process_start）
	return startLaunch(sandboxExecCommand(cwd, "ws", argv))
}
