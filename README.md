# YZU Auto Login

Windows 11 常驻托盘的扬州大学校园网自动登录工具。程序不显示主窗口，WebUI 仅监听本机回环地址；锁屏不会影响当前用户会话中的运行。

## 当前阶段

已实现托盘常驻、本机 WebUI、AES-GCM 加密配置、可配置的连通性探测与日志。检测到校园网门户后，程序会执行统一认证登录，并选择“电信互联网服务”完成认证；提交后会立即重新探测，确认网络恢复。

## 开发运行

```powershell
go mod tidy
go build -ldflags="-H=windowsgui" -o YZUAutoLogin.exe .
.\YZUAutoLogin.exe
```

首次启动会在可执行文件同级目录创建 `config.json`、随机生成的 `secret.key` 和 `logs\app.log`。在浏览器打开 `http://127.0.0.1:8765`，填写账号、密码并保存。密码由 AES-GCM 加密；请勿丢失或泄露 `secret.key`，它必须与 `config.json` 一起保留。

默认探测要求 `http://www.msftconnecttest.com/connecttest.txt` 返回精确的 `Microsoft Connect Test` 正文；任何其他响应都会作为门户拦截处理。可在 WebUI 调整探测地址和预期正文。

探测或认证失败只会更新状态并写入日志，程序会在下个探测周期自动重试，不会自行退出。

`-H=windowsgui` 会避免启动时出现控制台窗口。

## 门户接入所需信息

当前登录流程依据 2026-08-20 抓取的 HAR 实现。若校园网更新了统一认证页面、出现验证码，或修改了“电信互联网服务”名称，请重新抓取从登录到联网成功的 HAR 以便适配。不要外传含有账号、Cookie 或令牌的 HAR 文件。
