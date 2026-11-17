// 构建 mino-sandbox sidecar 并复制到项目根（Node 侧按 process.cwd()/mino-sandbox 定位，
// 开发态 cwd=项目根；打包态由 CI 把二进制 cp 进 app 目录）。
// execFileSync 直接传参数数组，避免 Windows shell 的引号歧义
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const isWin = process.platform === "win32";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const pkg = path.join(root, "sandbox");
const out = path.join(root, `mino-sandbox${isWin ? ".exe" : ""}`);
// 先编到临时名再替换：Windows 下运行中的旧二进制被锁，直接覆盖同名文件会失败
const tmp = `${out}.new`;
// cwd 必须是 sandbox 模块目录（仓库根没有 go.mod，go build 会报 cannot find main module）
execFileSync("go", ["build", "-ldflags", "-s -w", "-o", tmp, "."], { stdio: "inherit", cwd: pkg });
fs.copyFileSync(tmp, out);
fs.rmSync(tmp);
console.log(`已构建 ${out}`);
