// 各语言包管理器 / 工具链的默认缓存目录清单，供 ws 档放行写入。
// 动机：workspace 级 run_command 免确认的前提是「写入被沙箱圈在工作区」，但
// npm install / dotnet build / cargo build 等第一步就是写用户级缓存（HOME 下），
// 不放行则常规构建流程全部卡壳。只认各工具的默认位置；用户用环境变量自改的
// 缓存路径（npm_config_cache、NUGET_PACKAGES、GOMODCACHE 等）不在覆盖范围。
// 已知取舍：沙箱内命令因此可写宿主共享缓存，缓存投毒可能影响宿主后续构建——
// 这些目录本就在用户自己的写权限内，且不放开任何执行面，风险限于用户自己。
package main

import (
	"os"
	"path/filepath"
	"runtime"
)

// 返回当前平台上「存在」的各语言缓存目录。必须过滤存在性：bwrap --bind 与
// Windows grantAcl 对不存在的路径都会失败并连带判整个沙箱不可用，Landlock 对
// 白名单路径 O_PATH 打开失败会放弃整条第二道防线；没装对应工具链的目录静默跳过。
func langCacheDirs() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var dirs []string
	add := func(parts ...string) {
		p := filepath.Join(parts...)
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			dirs = append(dirs, p)
		}
	}
	if runtime.GOOS == "windows" {
		local := os.Getenv("LOCALAPPDATA")
		if local == "" {
			local = filepath.Join(home, "AppData", "Local")
		}
		add(local, "npm-cache")
		add(local, "pnpm", "store")
		add(local, "Yarn", "Cache")
		add(local, "pip", "Cache")
		add(local, "uv", "cache")
		add(local, "NuGet", "v3-cache")
		add(local, "go-build")
		add(local, "node-gyp")
		add(local, "electron", "Cache")
		add(local, "electron-builder", "Cache")
		add(home, ".nuget", "packages")
		add(home, "go", "pkg", "mod")
		add(home, ".cargo", "registry")
		add(home, ".m2", "repository")
		add(home, ".gradle", "caches")
		add(home, ".gradle", "wrapper")
		add(home, ".conda", "pkgs")
		return dirs
	}
	// Linux 与 macOS 共用的 HOME 下缓存
	add(home, ".npm")
	add(home, ".yarn", "berry", "cache")
	add(home, ".nuget", "packages")
	add(home, ".cargo", "registry")
	add(home, ".m2", "repository")
	add(home, ".gradle", "caches")
	add(home, ".gradle", "wrapper")
	add(home, ".conda", "pkgs")
	add(home, "go", "pkg", "mod")
	if runtime.GOOS == "darwin" {
		lc := filepath.Join(home, "Library", "Caches")
		add(lc, "Yarn")
		add(lc, "pip")
		add(lc, "uv")
		add(lc, "go-build")
		add(lc, "node-gyp")
		add(lc, "electron")
		add(lc, "electron-builder")
		add(lc, "CocoaPods")
		add(home, "Library", "pnpm", "store")
		return dirs
	}
	add(home, ".cache", "yarn")
	add(home, ".cache", "pip")
	add(home, ".cache", "uv")
	add(home, ".cache", "go-build")
	add(home, ".cache", "node-gyp")
	add(home, ".cache", "electron")
	add(home, ".cache", "electron-builder")
	add(home, ".local", "share", "pnpm", "store")
	return dirs
}
