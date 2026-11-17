//go:build !windows

// Unix（Linux/macOS）共享进程编排：平台后端构造好沙箱化的 exec.Cmd 交给这里执行。
// 进程组管理是平台无关逻辑，抽在这里避免 linux.go / darwin.go 各写一份。
package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

// runAndWait：阻塞执行并等待，stdio 与退出码原样透传。
// Setpgid 让子命令独立成组：start 模式靠 pgid 组杀整树（shell -c 会 fork 子进程），
// run 模式在 Node 超时杀本进程时也能把整树带走。
func runAndWait(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		unavailable("沙箱进程启动失败: " + err.Error())
	}
	pgid := cmd.Process.Pid
	done := make(chan struct{})

	// Node 侧 AbortSignal 超时会对本进程发 SIGTERM：转为组杀沙箱内整树。
	// 必须捕获而不是默认退出，否则树里的孙进程会残留
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		defer signal.Stop(sigCh)
		select {
		case <-sigCh:
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		case <-done:
		}
	}()

	// 孤儿兜底：Node 直接 SIGKILL 本进程时收不到任何信号（如 macOS 无 die-with-parent），
	// 轮询父进程是否已换成 init，是则组杀，避免沙箱进程变孤儿继续跑
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if os.Getppid() == 1 {
					_ = syscall.Kill(-pgid, syscall.SIGKILL)
					return
				}
			case <-done:
				return
			}
		}
	}()

	err := cmd.Wait()
	close(done)
	if err == nil {
		os.Exit(cmd.ProcessState.ExitCode())
	}
	ee, isExit := err.(*exec.ExitError)
	if !isExit {
		unavailable("等待沙箱进程失败: " + err.Error())
	}
	if code := ee.ExitCode(); code >= 0 {
		os.Exit(code)
	}
	// 被信号杀死（ExitCode 为 -1）：透传 128+signo，与 shell 惯例一致
	os.Exit(128 + int(ee.Sys().(syscall.WaitStatus).Signal()))
}

// startLaunch：启动后首行打印 pgid（Setpgid 后 pid==pgid）随即退出，发射后不管。
// stdio 全部置空：子进程不占用 Node 的任何管道；终止只靠 process_stop 按 pgid 组杀
func startLaunch(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	fmt.Println(cmd.Process.Pid)
	return nil
}
