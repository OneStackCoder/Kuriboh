//go:build windows

// Windows 后端：Restricted Token（受限访问令牌，WRITE_RESTRICTED）+ ACL 实现沙箱
//（本环境不可运行验证，靠 probe 失败自动回退兜底）。
//
// 受限令牌从本进程令牌派生：保留完整用户身份与 logon SID（窗口站/桌面访问正常），
// 挂固定 Kuriboh SID 作限制 SID、清空全部特权后启动。WRITE_RESTRICTED 的语义正好
// 实现「读放行、写管住」：
//   - 读/执行访问只走普通 ACL 校验——用户能读的沙箱进程都能读（全盘可读，
//     对齐 Linux ro-bind / /），deny ACE 与他人私有文件照常拦得住；
//   - 写访问走双重校验：普通校验 AND 限制 SID 授权。宿主 DACL 默认不含 Kuriboh SID
//     的 ACE，故全盘默认禁写；写入白名单靠 grantAcl 把 (OI)(CI)F 授给 Kuriboh SID
//     （scope 三档：ro 零授权 / ws 工作区∪语言缓存目录 / home 工作区∪%USERPROFILE%，恒含工作区）。
// 特权清空封堵 SeBackup/SeTakeOwnership/SeDebug 等绕过 ACL 的路径。
// 已知取舍（用户确认并文档化）：受限令牌不拦 socket——Windows 沙箱内可联网
//（Linux/macOS 断网不变）；同 uid 语义下 Everyone 可写目录对沙箱进程同样可写，
// 与 Linux 同 uid 行为一致。
// TEMP/TMP 每次启动重定向到 %TEMP% 下的私有实例，run 等待结束即删，
// start 分离模式进程仍在用、泄漏可接受（空目录，宿主用户本就可见）。
package main

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// x/sys 未收录的 API（受限令牌、CreateProcessAsUser、DACL 合并）用 LazyDLL 手写声明；
// NewLazySystemDLL 走系统目录搜索，避免 DLL 预加载攻击
var (
	advapi32                = windows.NewLazySystemDLL("advapi32.dll")
	procCreateRestricted    = advapi32.NewProc("CreateRestrictedToken")
	procCreateProcessAsUser = advapi32.NewProc("CreateProcessAsUserW")
	procSetEntriesInAcl     = advapi32.NewProc("SetEntriesInAclW")
)

// CreateRestrictedToken 的 Flags（x/sys 未定义）
const (
	disableMaxPrivileges = 0x00000001
	writeRestricted      = 0x00000008
)

// 0x1F01FF 即 C 的 FILE_ALL_ACCESS，对应 icacls 的 (OI)(CI)F；x/sys 未定义
const fileAllAccess = windows.ACCESS_MASK(0x001F01FF)

// 固定的限制 SID：子授权取 "KURI"/"BOH0"/"SAND"/"2026" 的 ASCII 编码——
// 大值避开 NT 权威下的 well-known RID，icacls 输出里一眼可辨；常数固定使
// 授权出去的 ACE 跨版本/重启依然有效。由 API 分配，调用方用 windows.FreeSid 释放
func kuribohRestrictedSid() (*windows.SID, error) {
	var sid *windows.SID
	if err := windows.AllocateAndInitializeSid(&windows.SECURITY_NT_AUTHORITY, 4,
		0x4B555249, 0x424F4830, 0x53414E44, 0x32303236, 0, 0, 0, 0, &sid); err != nil {
		return nil, err
	}
	return sid, nil
}

// 从本进程令牌派生受限主令牌：不删不禁任何 SID（保住用户身份与 logon SID），
// 只挂 Kuriboh SID 作限制 SID（WRITE_RESTRICTED）并清空特权（DISABLE_MAX_PRIVILEGES）。
// 从自家令牌派生的受限令牌交给 CreateProcessAsUser 不需要 SeAssignPrimaryTokenPrivilege
//（DropMyRights 同款先例），普通用户态即可建立沙箱
func restrictedToken(restrict *windows.SID) (windows.Token, error) {
	var self windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_QUERY, &self); err != nil {
		return 0, fmt.Errorf("打开本进程令牌失败: %w", err)
	}
	defer self.Close()
	attrs := [1]windows.SIDAndAttributes{{Sid: restrict}}
	var out windows.Token
	// 参数序：Flags、0 个删除 SID、0 个删特权、限制 SID 列表长 1
	r, _, e := procCreateRestricted.Call(uintptr(self),
		uintptr(disableMaxPrivileges|writeRestricted),
		0, 0, 0, 0, 1,
		uintptr(unsafe.Pointer(&attrs[0])),
		uintptr(unsafe.Pointer(&out)))
	if r == 0 {
		return 0, fmt.Errorf("创建受限令牌失败: %w", e)
	}
	return out, nil
}

// 把目录 DACL 合并授权给 Kuriboh SID：(OI)(CI)F 可写（工作区/HOME/私有临时目录）。
// GRANT_ACCESS 是合并语义，重复执行幂等；ACE 持久化在宿主文件系统上，与 Linux
// bind 挂载的会话级不同——目录删除后随目录一起消失；继承标志挂上的同时系统会把
// ACE 自动传播到已存在的子树（关闭继承的对象除外）
func grantAcl(dir string, sid *windows.SID, mask windows.ACCESS_MASK) error {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("读取 %s 的 DACL 失败: %w", dir, err)
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(sd))))
	oldAcl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("解析 %s 的 DACL 失败: %w", dir, err)
	}
	entry := windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:      windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
	var newAcl *windows.ACL
	ret, _, _ := procSetEntriesInAcl.Call(1, uintptr(unsafe.Pointer(&entry)),
		uintptr(unsafe.Pointer(oldAcl)), uintptr(unsafe.Pointer(&newAcl)))
	if ret != 0 {
		return fmt.Errorf("合并 %s 的 DACL 失败: %d", dir, ret)
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(newAcl))))
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, newAcl, nil)
}

// run/fs/start 共同的沙箱准备：建限制 SID 与受限令牌，按 scope 授权写入白名单，
// 再建本次运行的私有临时目录（授 F 并重定向 TEMP/TMP）。授权失败一并判沙箱
// 不可用：语义打折的沙箱不如让 Node 明确感知（run_command 回退宿主 / 文件工具硬失败）
func prepareSandbox(cwd, scope string) (windows.Token, *windows.SID, string, error) {
	sid, err := kuribohRestrictedSid()
	if err != nil {
		return 0, nil, "", err
	}
	fail := func(err error) (windows.Token, *windows.SID, string, error) {
		windows.FreeSid(sid)
		return 0, nil, "", err
	}
	switch scope {
	case "home":
		// 恒含工作区：full 级工作区可能不在 HOME 下（如 D:\work），只授 HOME 会误拒
		home, err := os.UserHomeDir()
		if err != nil {
			return fail(fmt.Errorf("获取用户主目录失败: %w", err))
		}
		if err := grantAcl(home, sid, fileAllAccess); err != nil {
			return fail(err)
		}
		if err := grantAcl(cwd, sid, fileAllAccess); err != nil {
			return fail(err)
		}
	case "ro":
		// 只读档零授权：读全盘天然放行、写全盘天然被拒，无需任何 ACE
	default: // ws：工作区 + 各语言缓存目录（cache.go）
		if err := grantAcl(cwd, sid, fileAllAccess); err != nil {
			return fail(err)
		}
		for _, dir := range langCacheDirs() {
			if err := grantAcl(dir, sid, fileAllAccess); err != nil {
				return fail(err)
			}
		}
	}
	token, err := restrictedToken(sid)
	if err != nil {
		return fail(err)
	}
	// 私有临时目录：不重定向的话沙箱进程写不了宿主 %TEMP%——写走限制 SID 校验，
	// 宿主 DACL 无 Kuriboh SID 的 ACE，依赖临时文件的命令会失败。宿主用户对它本就
	// 有全权（同 uid），与 Linux 私有 tmpfs 不同，残留内容对宿主可见（同 macOS 共享 /tmp）
	temp, err := os.MkdirTemp("", "kuriboh-sandbox-")
	if err != nil {
		token.Close()
		return fail(fmt.Errorf("创建私有临时目录失败: %w", err))
	}
	if err := grantAcl(temp, sid, fileAllAccess); err != nil {
		token.Close()
		_ = os.RemoveAll(temp)
		return fail(err)
	}
	return token, sid, temp, nil
}

// CreateProcess 只接受整条命令行字符串，而契约传的是 argv 数组；
// 按 CommandLineToArgvW 的反解析规则转义再拼接
func escapeArg(arg string) string {
	if arg == "" {
		return `""`
	}
	if !strings.ContainsAny(arg, " \t\"") {
		return arg
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for _, r := range arg {
		switch r {
		case '\\':
			slashes++
		case '"':
			// 引号前的连续反斜杠翻倍（它们后面跟的是引号），再转义引号本身
			b.WriteString(strings.Repeat(`\`, slashes*2+1))
			b.WriteByte('"')
			slashes = 0
		default:
			b.WriteString(strings.Repeat(`\`, slashes))
			slashes = 0
			b.WriteRune(r)
		}
	}
	// 末尾的反斜杠后面跟的是收尾引号，同样要翻倍
	b.WriteString(strings.Repeat(`\`, slashes*2))
	b.WriteByte('"')
	return b.String()
}

// 显式构造 Unicode 环境块（结尾双 NUL）：不依赖 Go 的环境继承行为，
// TEMP/TMP 直接替换成本次运行的私有临时目录
func buildEnvBlock(temp string) *uint16 {
	pairs := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		u := strings.ToUpper(kv)
		if strings.HasPrefix(u, "TEMP=") || strings.HasPrefix(u, "TMP=") {
			continue
		}
		pairs = append(pairs, kv)
	}
	if temp != "" {
		pairs = append(pairs, "TEMP="+temp, "TMP="+temp)
	}
	var block []uint16
	for _, kv := range pairs {
		block = append(block, utf16.Encode([]rune(kv))...)
		block = append(block, 0)
	}
	return &append(block, 0)[0]
}

// 以受限令牌创建进程。detached=false 是 run 模式：继承本进程 std 句柄透传 stdio
//（Node ↔ sidecar ↔ 沙箱命令），进 Job Object + KILL_ON_JOB_CLOSE——sidecar 被杀
//（Node 超时）时句柄关闭，内核级联杀整树，比 Unix 的 signal handler 兜底更硬；
// CREATE_SUSPENDED → Assign → Resume 防止 Assign 前进程已逃出 Job。detached=true
// 是 start 模式：不进 Job（进程要独立存活）、DETACHED_PROCESS、零 stdio（不占用
// Node 的管道）
func launchSandbox(cwd string, argv []string, token windows.Token, temp string, detached bool) (windows.ProcessInformation, func(), error) {
	var pi windows.ProcessInformation

	si := windows.StartupInfo{}
	si.Cb = uint32(unsafe.Sizeof(si))
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT)
	if detached {
		flags |= windows.DETACHED_PROCESS
	} else {
		flags |= windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW
		// 透传 stdio：句柄需先标记可继承，子进程才能拿到同一对管道；
		// GetStdHandle 失败（无控制台/管道）时置零，配合 CREATE_NO_WINDOW 不弹窗
		si.Flags |= windows.STARTF_USESTDHANDLES
		for std, dst := range map[uint32]*windows.Handle{
			windows.STD_INPUT_HANDLE:  &si.StdInput,
			windows.STD_OUTPUT_HANDLE: &si.StdOutput,
			windows.STD_ERROR_HANDLE:  &si.StdErr,
		} {
			h, herr := windows.GetStdHandle(std)
			if herr == nil && h != 0 {
				_ = windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT)
				*dst = h
			}
		}
	}

	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = escapeArg(a)
	}
	// CreateProcessW 系可能改写 lpCommandLine 缓冲区，必须用可写内存，不能用 UTF16PtrFromString
	cmdBuf := utf16.Encode([]rune(strings.Join(parts, " ")))
	var cwdPtr *uint16
	var err error
	if cwd != "" {
		if cwdPtr, err = windows.UTF16PtrFromString(cwd); err != nil {
			return pi, nil, fmt.Errorf("工作目录路径非法: %w", err)
		}
	}
	inherit := uintptr(0)
	if !detached {
		inherit = 1
	}
	r, _, e := procCreateProcessAsUser.Call(uintptr(token), 0,
		uintptr(unsafe.Pointer(&cmdBuf[0])), 0, 0, inherit,
		uintptr(flags), uintptr(unsafe.Pointer(buildEnvBlock(temp))),
		uintptr(unsafe.Pointer(cwdPtr)), uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		return pi, nil, fmt.Errorf("创建沙箱进程失败: %w", e)
	}

	if detached {
		// 发射后不管：句柄立刻关，pid 已记在返回值里
		_ = windows.CloseHandle(pi.Thread)
		_ = windows.CloseHandle(pi.Process)
		return pi, func() {}, nil
	}

	var job windows.Handle
	if job, err = windows.CreateJobObject(nil, nil); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		return pi, nil, fmt.Errorf("创建 Job Object 失败: %w", err)
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)
		_ = windows.TerminateProcess(pi.Process, 1)
		return pi, nil, fmt.Errorf("配置 Job Object 失败: %w", err)
	}
	if err = windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		// 挂 Job 失败意味着失去级联清理保障（残留沙箱进程），宁可终止重来
		_ = windows.CloseHandle(job)
		_ = windows.TerminateProcess(pi.Process, 1)
		return pi, nil, fmt.Errorf("Job Object 挂载失败: %w", err)
	}
	_, _ = windows.ResumeThread(pi.Thread)
	_ = windows.CloseHandle(pi.Thread)
	return pi, func() {
		_ = windows.CloseHandle(pi.Process)
		_ = windows.CloseHandle(job)
	}, nil
}

func sandboxProbe() error {
	sid, err := kuribohRestrictedSid()
	if err != nil {
		return err
	}
	defer windows.FreeSid(sid)
	token, err := restrictedToken(sid)
	if err != nil {
		return err
	}
	defer token.Close()
	// 全保真：与 run 同机制建私有临时目录 + 受限令牌进程跑 cmd /c ver，
	// OpenProcessToken / CreateRestrictedToken / CreateProcessAsUser 一次验全。
	// 临时目录结束即删，探测不产生持久化副作用
	temp, err := os.MkdirTemp("", "kuriboh-sandbox-")
	if err != nil {
		return fmt.Errorf("创建私有临时目录失败: %w", err)
	}
	defer os.RemoveAll(temp)
	if err := grantAcl(temp, sid, fileAllAccess); err != nil {
		return err
	}
	pi, cleanup, err := launchSandbox("", []string{"cmd", "/c", "ver"}, token, temp, false)
	if err != nil {
		return err
	}
	defer cleanup()
	if _, werr := windows.WaitForSingleObject(pi.Process, windows.INFINITE); werr != nil {
		return fmt.Errorf("等待探测进程失败: %w", werr)
	}
	var code uint32
	if err := windows.GetExitCodeProcess(pi.Process, &code); err != nil {
		return fmt.Errorf("读取探测退出码失败: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("探测命令退出码 %d", code)
	}
	return nil
}

func sandboxRun(cwd, scope string, argv []string) error {
	token, sid, temp, err := prepareSandbox(cwd, scope)
	if err != nil {
		return err
	}
	defer windows.FreeSid(sid)
	defer token.Close()
	// run 等待结束进程已退，临时目录无人再用，尽力删除
	defer os.RemoveAll(temp)
	pi, cleanup, err := launchSandbox(cwd, argv, token, temp, false)
	if err != nil {
		return err
	}
	defer cleanup()
	if _, werr := windows.WaitForSingleObject(pi.Process, windows.INFINITE); werr != nil {
		unavailable("等待沙箱进程失败: " + werr.Error())
	}
	var code uint32
	if err := windows.GetExitCodeProcess(pi.Process, &code); err != nil {
		unavailable("读取沙箱退出码失败: " + err.Error())
	}
	os.Exit(int(code))
	return nil
}

func sandboxStart(cwd string, argv []string) error {
	token, sid, temp, err := prepareSandbox(cwd, "ws")
	if err != nil {
		return err
	}
	defer windows.FreeSid(sid)
	defer token.Close()
	pi, _, err := launchSandbox(cwd, argv, token, temp, true)
	if err != nil {
		return err
	}
	// 契约：Windows 无进程组，start 打印单 pid；孙进程逃逸单 pid kill 记入已知限制。
	// temp 不删：进程独立存活还在用，泄漏可接受
	fmt.Println(pi.ProcessId)
	return nil
}
