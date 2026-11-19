// fs 子命令的内层实现：fs 外层在 OS 沙箱内以 argv
// [self, "_fs<sub>", "--scope", <s>, "--", <absPath>] 重新 exec 本二进制，
// 此文件的函数因此在沙箱内直接做纯 Go IO。无构建标签，三平台共用。
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// 与 Node 侧旧实现（readdir withFileTypes）对齐：dir / file / other，
// size 仅文件且 stat 成功时给出
type fsEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size,omitempty"`
}

func fsFail(err error) {
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}

// 内容写入链路：外层进程透传 stdin（Node spawn 的管道），这里整段读入再落盘
func fsInner(sub, target string) {
	var err error
	switch sub {
	case "read":
		data, e := os.ReadFile(target)
		if e != nil {
			fsFail(e)
		}
		_, err = os.Stdout.Write(data)
	case "write":
		data, e := io.ReadAll(os.Stdin)
		if e != nil {
			fsFail(e)
		}
		// 对齐 Node 旧实现的 recursive mkdir：写深层新文件不要求父目录已存在
		if e := os.MkdirAll(filepath.Dir(target), 0o755); e != nil {
			fsFail(e)
		}
		err = os.WriteFile(target, data, 0o644)
	case "list":
		entries, e := os.ReadDir(target)
		if e != nil {
			fsFail(e)
		}
		out := make([]fsEntry, 0, len(entries))
		for _, ent := range entries {
			item := fsEntry{Name: ent.Name(), Type: "other"}
			switch {
			case ent.IsDir():
				item.Type = "dir"
			case ent.Type().IsRegular():
				item.Type = "file"
			}
			if info, ie := ent.Info(); ie == nil && item.Type == "file" {
				item.Size = info.Size()
			}
			out = append(out, item)
		}
		var b []byte
		if b, err = json.Marshal(out); err == nil {
			_, err = os.Stdout.Write(append(b, '\n'))
		}
	default:
		fsFail(fmt.Errorf("未知子命令: %s", sub))
	}
	if err != nil {
		fsFail(err)
	}
}
