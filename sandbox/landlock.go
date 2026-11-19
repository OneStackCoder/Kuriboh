//go:build linux

// Landlock：Linux 写白名单的第二道防线，在 bwrap 之后的内层进程上启用
// （main.go 的 _fs* case）。
//
// 为什么必须在沙箱内层：Landlock 规则按 inode 生效，bwrap 沙箱内 /tmp 是私有
// tmpfs（与宿主 /tmp 不同 inode），在外层启用会把沙箱内 /tmp 误判为白名单外。
//
// 语义刻意宽松（尽力启用）：内核无 Landlock（< 5.13、LSM 未启用）或任一环节
// 失败时静默跳过，绝不判沙箱不可用、不拒绝执行——bwrap 主防线仍完整，
// Landlock 是纵深加固，不是可用性前提。
package main

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// 写白名单映射，与 bwrap 绑定集合同源（linux.go bwrapCommand）：
// ro=∅（read/list 恒只读档，全盘禁写含私有 /tmp）；ws=工作区∪/tmp∪语言缓存目录；
// home=工作区∪HOME∪/tmp（恒含工作区，与 bwrap home 档一致，缓存目录在 HOME 下天然覆盖）。
// HOME 有效性由外层 sandboxRun home 档先行校验。
func landlockWritableDirs(scope, cwd string) []string {
	switch scope {
	case "home":
		return []string{cwd, os.Getenv("HOME"), "/tmp"}
	case "ro":
		return nil
	default: // ws
		return append([]string{cwd, "/tmp"}, langCacheDirs()...)
	}
}

// handled 取全部写类 rights，刻意不含读类（EXECUTE/READ_FILE/READ_DIR）——
// 沙箱语义要求读取不限制在工作区，全盘读不能进 Landlock 管控面。
// 只 handled {WRITE_FILE, TRUNCATE, REFER} 不够：MAKE_REG/REMOVE_FILE 等不在
// 管控面时，建文件、删除完全绕过 Landlock，第二道防线名不副实。
// 按内核 ABI 版本追加：REFER v2（5.19）、TRUNCATE v3（6.2）。
func landlockHandled(abi int) uint64 {
	h := uint64(unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM)
	if abi >= 2 {
		h |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		h |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	return h
}

// 按 scope 启用 Landlock 写白名单。所有失败路径一律静默返回（见文件头注释）。
// x/sys 只收录了常量与 syscall 号、未封装函数，以下手工调 syscall
func enableLandlock(scope, cwd string) {
	// 带 VERSION flag 探测内核 ABI 版本：ENOSYS=内核无此 syscall，
	// EOPNOTSUPP=Landlock LSM 未启用，都属「内核无 Landlock」
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 || abi == 0 {
		return
	}
	// size 固定 8（只声明 Access_fs 字段）：老内核不会 E2BIG，
	// 新内核把未声明的 net/scoped 字段视为不 handled——本就不在管控目标内
	attr := unix.LandlockRulesetAttr{Access_fs: landlockHandled(int(abi))}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), 8, 0)
	if errno != 0 {
		return
	}
	rulesetFd := int(fd)
	defer unix.Close(rulesetFd)
	// 白名单目录放行 rights 与 handled 同集：目录树内的全部写操作合法
	for _, dir := range landlockWritableDirs(scope, cwd) {
		pathFd, err := unix.Open(dir, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return // 白名单路径开不了（不该发生）：整体放弃，别只放行一部分把正常操作也拦了
		}
		rule := unix.LandlockPathBeneathAttr{Parent_fd: int32(pathFd), Allowed_access: attr.Access_fs}
		_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE,
			uintptr(rulesetFd), unix.LANDLOCK_RULE_PATH_BENEATH,
			uintptr(unsafe.Pointer(&rule)), 0, 0, 0)
		unix.Close(pathFd)
		if errno != 0 {
			return
		}
	}
	// restrict_self 要求先放弃提权路径，否则 EINVAL
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return
	}
	unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFd), 0, 0)
}
