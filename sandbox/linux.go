//go:build linux

// Linux 后端：bubblewrap（bwrap）实现沙箱。
package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// bwrap 基础参数集。
// --ro-bind / /：宿主 rootfs 全量只读可见——读取不限制在工作区（与 read_file 工具能力
// 对齐），uid 文件权限照常生效、无提权；写入被只读挡住，改不了宿主任何文件。
// --dev / --proc / --tmpfs 在 ro-bind 之后按序覆盖为沙箱私有实例；
// /tmp 是沙箱私有 tmpfs（写临时文件的常规去处，不污染宿主）。
// 不用 --unshare-pid：保住 ps 等进程列表查询，同 uid kill 残留记入已知限制（L2 加 seccomp）。
func baseBwrapArgs() []string {
	return []string{
		"--ro-bind", "/", "/",
		"--dev", "/dev",
		"--proc", "/proc",
		"--tmpfs", "/tmp",
		"--unshare-net", "--unshare-ipc",
	}
}

// 组装完整 bwrap 命令行：基础集 + 按 scope 的可写绑定 + 环境重定向 + 子命令。
// HOME 继承宿主真实值（读 ~ 正常，ws 档写 ~ 被 rootfs 只读挡住）；
// TMPDIR 指向私有 tmpfs。
// roDirs 是 Windows 专用参数（AppContainer 逐路径授权读取），Linux 的
// ro-bind / / 已全盘可读，忽略
func bwrapCommand(cwd, scope string, argv []string, dieWithParent bool) *exec.Cmd {
	args := baseBwrapArgs()
	switch scope {
	case "home":
		// home 档恒含工作区：full 级工作区可能不在 HOME 下（如 /srv/ws），只绑 HOME 会误拒。
		// HOME 有效性由 sandboxRun 先行校验
		home := os.Getenv("HOME")
		args = append(args, "--bind", home, home, "--bind", cwd, cwd)
	case "ro":
		// 不绑工作区：rootfs 只读即全盘禁写
	default: // ws：工作区是沙箱内唯一可写宿主目录
		args = append(args, "--bind", cwd, cwd)
	}
	args = append(args, "--chdir", cwd)
	if dieWithParent {
		// run 模式带：sidecar 被 Node 杀死时 bwrap 级联杀整树，是信号组杀之外的第二道保险
		args = append(args, "--die-with-parent")
	}
	args = append(args, "--setenv", "TMPDIR", "/tmp", "--")
	return exec.Command("bwrap", append(args, argv...)...)
}

func sandboxProbe() error {
	if _, err := exec.LookPath("bwrap"); err != nil {
		return errors.New("bwrap 未安装（Linux 沙箱依赖 bubblewrap）")
	}
	// 全保真探测：用 run 同款挂载与网络隔离跑 true。只查 bwrap 存在不靠谱——
	// userns 权限、参数集错误都是静默失败，要真跑一遍才暴露。probe 无工作区参数，
	// --bind/--chdir 是与 run 的唯一差异
	var errBuf bytes.Buffer
	cmd := exec.Command("bwrap", append(baseBwrapArgs(),
		"--setenv", "TMPDIR", "/tmp", "--", "/usr/bin/true")...)
	cmd.Stderr = &errBuf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Run(); err != nil {
		// bwrap 的 stderr 带具体原因（userns 被禁、挂载失败等），带回去给 Node 显示
		if reason := strings.TrimSpace(errBuf.String()); reason != "" {
			return fmt.Errorf("bwrap 探测失败: %s", reason)
		}
		return fmt.Errorf("bwrap 探测失败: %v", err)
	}
	return nil
}

func sandboxRun(cwd, scope string, roDirs []string, argv []string) error {
	if scope == "home" {
		// home 档绑定 $HOME，缺失/无效时明确报沙箱不可用而不是让 bwrap 报晦涩错误
		home := os.Getenv("HOME")
		if home == "" {
			return errors.New("home 档需要 HOME 环境变量")
		}
		if st, err := os.Stat(home); err != nil || !st.IsDir() {
			return fmt.Errorf("HOME 不可用: %s", home)
		}
	}
	// runAndWait 在正常路径透传子命令退出码后 os.Exit，不返回；
	// bwrap spawn 失败走 unavailable 出口，同样不返回。
	// roDirs 忽略：Linux 全盘只读可见，无需逐路径授权
	runAndWait(bwrapCommand(cwd, scope, argv, true))
	return nil
}

func sandboxStart(cwd string, argv []string) error {
	// 不带 die-with-parent：进程要独立存活，终止只靠 process_stop 按 pgid 组杀；
	// start 恒 ws 语义（唯一调用方 process_start）
	return startLaunch(bwrapCommand(cwd, "ws", argv, false))
}

// run/start 改道自 exec（双层防线）：bwrap 内先跑 _exec 内层启用 Landlock，
// 再 exec 目标命令。沙箱内 rootfs 只读可见，能读 sidecar 自身
func execArgv(cwd, scope string, argv []string) ([]string, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("定位 sidecar 自身失败: %w", err)
	}
	return append([]string{self, "_exec", "--scope", scope, "--cwd", cwd, "--"}, argv...), nil
}

// _exec 内层（main.go 分发）：启用 Landlock 后把进程映像替换为目标命令——
// pid 不变，runAndWait 的进程组、SIGTERM 组杀、孤儿兜底、退出码透传语义零变化。
// Exec 失败对齐 shell 的 127 惯例：argv[0] 起不来是目标命令的问题，刻意不走
// unavailable(125)——不触发 Node 侧「沙箱不可用」的宿主回退（宁失败不越权重跑）
func execInner(cwd, scope string, argv []string) {
	enableLandlock(scope, cwd)
	// syscall.Exec 不查 PATH（bwrap 的 execvp 语义、exec.Command 都查），
	// argv[0] 裸名如 sh 必须先解析成绝对路径
	path, err := exec.LookPath(argv[0])
	if err == nil {
		err = syscall.Exec(path, argv, os.Environ())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "沙箱内启动命令失败: "+err.Error())
		os.Exit(127)
	}
}
