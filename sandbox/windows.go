//go:build windows

// Windows 后端：AppContainer + ACL Runner 实现沙箱（本环境不可运行验证，靠 probe 失败自动回退兜底）。
//
// AppContainer 是 token 级隔离：进程携带独立的低特权 token 启动，SECURITY_CAPABILITIES
// 挂 0 个 capability 即无任何网络授权（断网），对宿主文件系统默认零写权限——写入白名单
// 完全靠把 DACL 显式授权给容器 SID（scope 三档：ro 全禁写 / ws 工作区 F / home 工作区∪
// %USERPROFILE% F）。读取范围由宿主 ACL 决定（系统目录默认含容器可读 ACE，用户目录
// 默认不可读）：%USERPROFILE% 恒持久化加 (OI)(CI)RX 授权（关闭继承的部分子目录仍读不到，
// 其余盘位依旧受 ACL 制约，做不到 Linux ro-bind 式全盘可读）；fs read/list 对 HOME 外的
// target 本体逐次 RX 授权兜住。
// TEMP/TMP 重定向到容器私有目录，等价 Unix 的私有 tmpfs。
package main

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 容器名兼作 profile 标识：首次创建 profile 时系统会在 %LOCALAPPDATA%\AppContainer\
// <SID> 下生成容器私有目录，之后 Derive 即可取回 SID；重复创建是幂等的
const appContainerName = "Mino.Sandbox"

// x/sys 未收录的 API（AppContainer、DACL 合并）用 LazyDLL 手写声明；
// NewLazySystemDLL 走系统目录搜索，避免 DLL 预加载攻击
var (
	userenv                    = windows.NewLazySystemDLL("userenv.dll")
	advapi32                   = windows.NewLazySystemDLL("advapi32.dll")
	ole32                      = windows.NewLazySystemDLL("ole32.dll")
	procDeriveAppContainerSid  = userenv.NewProc("DeriveAppContainerSidFromAppContainerName")
	procCreateAppContainerProf = userenv.NewProc("CreateAppContainerProfile")
	procContainerFolderPath    = userenv.NewProc("GetAppContainerFolderPath")
	procSetEntriesInAcl        = advapi32.NewProc("SetEntriesInAclW")
	procCoTaskMemFree          = ole32.NewProc("CoTaskMemFree")
)

// CreateProcess 属性列表携带 SECURITY_CAPABILITIES 才会以 AppContainer token 启动
const procThreadAttributeSecurityCapabilities = 0x00060007

// C SECURITY_CAPABILITIES（x/sys 未定义）。Capabilities 为 nil 且 count 为 0 即断网：
// 不挂任何 capability SID，token 上就没有网络与文件授权
type securityCapabilities struct {
	appContainerSid *windows.SID
	capabilities    *uintptr // PSID*，恒 nil
	capabilityCount uint32
	reserved        uint32
}

// 0x1F01FF 即 C 的 FILE_ALL_ACCESS，对应 icacls 的 (OI)(CI)F；x/sys 未定义
const fileAllAccess = windows.ACCESS_MASK(0x001F01FF)

// 0x1200A9 即 FILE_GENERIC_READ | FILE_GENERIC_EXECUTE，对应 icacls 的 (OI)(CI)RX；x/sys 未定义
const fileRxAccess = windows.ACCESS_MASK(0x001200A9)

// 容器 SID：先 Derive（profile 已存在的快路径），失败再创建 profile（首次运行，
// 顺带生成容器私有目录）。SID 由 API 分配，调用方用 windows.FreeSid 释放
func appContainerSid() (*windows.SID, error) {
	name, err := windows.UTF16PtrFromString(appContainerName)
	if err != nil {
		return nil, err
	}
	var sid *windows.SID
	hr, _, _ := procDeriveAppContainerSid.Call(
		uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&sid)))
	if hr == 0 {
		return sid, nil
	}
	display, _ := windows.UTF16PtrFromString("Mino sandbox")
	description, _ := windows.UTF16PtrFromString("Mino run_command/process_start sandbox")
	hr, _, _ = procCreateAppContainerProf.Call(
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(display)),
		uintptr(unsafe.Pointer(description)),
		0, 0,
		uintptr(unsafe.Pointer(&sid)))
	if hr != 0 {
		return nil, fmt.Errorf("创建 AppContainer 失败: 0x%08x", int32(hr))
	}
	return sid, nil
}

// 容器私有目录路径（等价 Unix 的私有 tmpfs）。取不到时返回空串，
// TEMP 保持宿主值——容器对宿主 %TEMP% 无写权限，依赖临时文件的命令会失败
func sandboxTempDir() string {
	name, err := windows.UTF16PtrFromString(appContainerName)
	if err != nil {
		return ""
	}
	var path *uint16
	hr, _, _ := procContainerFolderPath.Call(
		uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&path)))
	if hr != 0 || path == nil {
		return ""
	}
	defer procCoTaskMemFree.Call(uintptr(unsafe.Pointer(path)))
	return windows.UTF16PtrToString(path)
}

// 把目录 DACL 合并授权给容器 SID：工作区传 (OI)(CI)F（可写）、用户主目录传 (OI)(CI)RX（只读）。
// GRANT_ACCESS 是合并语义，重复执行幂等；ACE 持久化在宿主文件系统上，
// 与 Linux bind 挂载的会话级不同——目录删除后随目录一起消失。
// target 也可能是文件本体（fs read 授权单个文件）：继承标志对非容器对象无意义，置零
func grantAcl(dir string, sid *windows.SID, mask windows.ACCESS_MASK) error {
	inherit := uint32(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	if st, err := os.Stat(dir); err == nil && !st.IsDir() {
		inherit = 0
	}
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
		Inheritance:       inherit,
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

// run/fs 共同的沙箱准备：取容器 SID，按 scope 授权写入白名单、用户主目录
// （%USERPROFILE%）恒 RX（沙箱语义要求读取不限制在工作区；AppContainer 默认读不了用户目录），
// 再把 roDirs 逐个 RX——沙箱内自 exec 要求能读 sidecar 自身目录，fs read/list 要求
// 能读 HOME 外的 target 本体。授权失败一并判沙箱不可用：语义打折的沙箱
// 不如让 Node 明确感知（run_command 回退宿主 / 文件工具硬失败）
func prepareSandbox(cwd, scope string, roDirs []string) (*windows.SID, error) {
	sid, err := appContainerSid()
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*windows.SID, error) {
		windows.FreeSid(sid)
		return nil, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("获取用户主目录失败: %w", err)
	}
	if err := grantAcl(home, sid, fileRxAccess); err != nil {
		return fail(err)
	}
	switch scope {
	case "home":
		// 恒含工作区：full 级工作区可能不在 HOME 下（如 D:\work），只授 HOME 会误拒
		if err := grantAcl(home, sid, fileAllAccess); err != nil {
			return fail(err)
		}
		if err := grantAcl(cwd, sid, fileAllAccess); err != nil {
			return fail(err)
		}
	case "ro":
		// 只读档：cwd 也不可写，仅 RX 维持「读取不限制在工作区」
		if err := grantAcl(cwd, sid, fileRxAccess); err != nil {
			return fail(err)
		}
	default: // ws：现 run/start 语义
		if err := grantAcl(cwd, sid, fileAllAccess); err != nil {
			return fail(err)
		}
	}
	for _, dir := range roDirs {
		if err := grantAcl(dir, sid, fileRxAccess); err != nil {
			return fail(err)
		}
	}
	return sid, nil
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
// TEMP/TMP 直接替换成容器私有目录
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

// 在 AppContainer 内创建进程。detached=false 是 run 模式：
// 继承本进程 std 句柄透传 stdio（Node ↔ sidecar ↔ 沙箱命令），进 Job Object +
// KILL_ON_JOB_CLOSE——sidecar 被杀（Node 超时）时句柄关闭，内核级联杀整树，
// 比 Unix 的 signal handler 兜底更硬；CREATE_SUSPENDED → Assign → Resume
// 防止 Assign 前进程已逃出 Job。detached=true 是 start 模式：不进 Job（进程要
// 独立存活）、DETACHED_PROCESS、零 stdio（不占用 Node 的管道）
func launchInContainer(cwd string, argv []string, sid *windows.SID, detached bool) (windows.ProcessInformation, func(), error) {
	var pi windows.ProcessInformation

	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return pi, nil, fmt.Errorf("初始化属性列表失败: %w", err)
	}
	caps := securityCapabilities{appContainerSid: sid}
	if err := attrs.Update(procThreadAttributeSecurityCapabilities,
		unsafe.Pointer(&caps), unsafe.Sizeof(caps)); err != nil {
		attrs.Delete()
		return pi, nil, fmt.Errorf("设置 AppContainer 属性失败: %w", err)
	}

	siEx := windows.StartupInfoEx{}
	siEx.Cb = uint32(unsafe.Sizeof(siEx))
	siEx.ProcThreadAttributeList = attrs.List()
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)
	abort := func(reason string) (windows.ProcessInformation, func(), error) {
		attrs.Delete()
		return pi, nil, fmt.Errorf("%s: %w", reason, err)
	}
	if detached {
		flags |= windows.DETACHED_PROCESS
	} else {
		flags |= windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW
		// 透传 stdio：句柄需先标记可继承，子进程才能拿到同一对管道；
		// GetStdHandle 失败（无控制台/管道）时置零，配合 CREATE_NO_WINDOW 不弹窗
		siEx.Flags |= windows.STARTF_USESTDHANDLES
		for std, dst := range map[uint32]*windows.Handle{
			windows.STD_INPUT_HANDLE:  &siEx.StdInput,
			windows.STD_OUTPUT_HANDLE: &siEx.StdOutput,
			windows.STD_ERROR_HANDLE:  &siEx.StdErr,
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
	// CreateProcessW 可能改写 lpCommandLine 缓冲区，必须用可写内存，不能用 UTF16PtrFromString
	cmdBuf := utf16.Encode([]rune(strings.Join(parts, " ")))
	var cwdPtr *uint16
	if cwd != "" {
		if cwdPtr, err = windows.UTF16PtrFromString(cwd); err != nil {
			return abort("工作目录路径非法")
		}
	}
	err = windows.CreateProcess(nil, &cmdBuf[0], nil, nil, !detached,
		flags, buildEnvBlock(sandboxTempDir()), cwdPtr, &siEx.StartupInfo, &pi)
	// 属性列表在 CreateProcess 返回后即可释放
	attrs.Delete()
	if err != nil {
		return pi, nil, fmt.Errorf("创建沙箱进程失败: %w", err)
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
	sid, err := appContainerSid()
	if err != nil {
		return err
	}
	defer windows.FreeSid(sid)
	// 全保真：与 run 同机制跑 cmd /c ver——userenv API、属性列表、容器内创建进程
	// 一次验全。不碰工作区 ACL，探测不能产生持久化副作用
	pi, cleanup, err := launchInContainer("", []string{"cmd", "/c", "ver"}, sid, false)
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

func sandboxRun(cwd, scope string, roDirs []string, argv []string) error {
	sid, err := prepareSandbox(cwd, scope, roDirs)
	if err != nil {
		return err
	}
	defer windows.FreeSid(sid)
	pi, cleanup, err := launchInContainer(cwd, argv, sid, false)
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
	sid, err := prepareSandbox(cwd, "ws", nil)
	if err != nil {
		return err
	}
	defer windows.FreeSid(sid)
	pi, _, err := launchInContainer(cwd, argv, sid, true)
	if err != nil {
		return err
	}
	// 契约：Windows 无进程组，start 打印单 pid；孙进程逃逸单 pid kill 记入已知限制
	fmt.Println(pi.ProcessId)
	return nil
}
