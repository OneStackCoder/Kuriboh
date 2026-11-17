//go:build !linux

// 非 Linux 无 Landlock：内层不设第二道防线——macOS Seatbelt 与
// Windows AppContainer+ACL 本身就是内核级强制，单层防线即生效。
package main

func enableLandlock(scope, cwd string) {}

// 非 Linux 的 run/start 不套 _exec：外层原样直 exec 用户命令（单层内核
// 防线），_exec 内层走不到
func execArgv(cwd, scope string, argv []string) ([]string, error) {
	return argv, nil
}

// 仅兜协议异常：正常路径非 Linux 平台不会构造 _exec 子命令
func execInner(cwd, scope string, argv []string) {
	unavailable("_exec 仅由 Linux 外层构造")
}
