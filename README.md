# DIYVM Local Passkey

`pure-extension` 分支是 DIYVM Local Passkey `0.3.0` 的 Chrome Web Store 架构版。
插件不需要安装 `PasskeyHost.exe`，也不使用 `webAuthenticationProxy`。凭据生成、
签名、加密和存储都在扩展内部完成。

## 当前能力

- 支持 `webauthn.io`、`amazon.com` 及其 HTTPS 子域。
- 使用浏览器 Web Crypto 生成独立 ES256 / P-256 密钥。
- 支持可发现凭据、`excludeCredentials`、`allowCredentials` 和签名计数器。
- 私钥、RP ID、账户信息和计数器整体使用 AES-256-GCM 加密后保存到 IndexedDB。
- 随机 Vault Key 使用主密码经 PBKDF2-SHA-256 派生的密钥包装。
- 解锁后的 Vault Key 只保存到 Chrome `storage.session`；Chrome 关闭或空闲
  15 分钟后重新锁定。
- 每次注册或登录都会显示独立的 DIYVM 扩展确认窗口，可选择本地通行密钥、
  Chrome/系统验证器或取消。
- 插件页面支持加密备份导入和导出；恢复后仍需原主密码。
- 自动跟随系统深浅色显示 A/C 两套官网风格。

纯插件不会读取或复制 Windows Hello、Chrome 密码管理器、USB 安全密钥或其他
验证器中的私钥。

## 安装测试包

GitHub Actions 会在 `main`、`pure-extension` 的推送和拉取请求上执行：

1. TypeScript 类型检查。
2. 自动测试。
3. 扩展构建。
4. 生成根目录包含 `manifest.json` 的 ZIP 和 SHA-256 文件。

下载 Actions 产物后：

1. 解压 `DIYVM-Local-Passkey-Chrome-0.3.0.zip`。
2. 打开 `chrome://extensions`。
3. 开启“开发者模式”。
4. 选择“加载已解压的扩展程序”，加载解压目录。
5. 点击插件图标，创建至少 12 个 UTF-8 字节的主密码。
6. 在 `https://webauthn.io` 注册并登录测试。

只使用可恢复的测试账户，并保留密码、OTP 或其他安全密钥。Amazon 真实账户流程
需要单独人工验证，本仓库自动测试不把 Amazon 兼容性标记为已通过。

## 加密备份

插件页面中的“导出备份”会生成：

```text
DIYVM-LocalPasskey-backup-<时间>.diyvmpasskey.json
```

备份包含 IndexedDB 中的加密信封、KDF 参数和包装后的 Vault Key，不包含明文
RP ID、账户名或私钥。导入会先验证文件大小、版本、结构和 SHA-256，再用一个
IndexedDB 事务完整替换凭据库；校验失败时不会覆盖现有数据。

备份文件可以被离线猜测主密码，因此必须使用高强度主密码并妥善保管。

## 开发和验证

```text
npm install
npm run check
npm test
npm run build
```

需要复测 webauthn.io 当前服务端时，可单独运行：

```text
npm run test:webauthn-io
```

该命令会用一次性用户名完成真实注册和登录验签，不会访问 Amazon，也不会在
GitHub Actions 中自动运行。

构建结果位于：

```text
extension/dist
```

当前自动测试覆盖：

- IndexedDB 加密记录读写和原子恢复。
- 主密码解锁、错误密码和 15 分钟空闲锁定。
- webauthn.io ES256 注册和登录。
- attestation、COSE 公钥、RP ID 哈希、UP/UV 标志。
- 登录签名的公钥验证和签名计数器递增。
- 真实加密凭据的导出、恢复和继续登录。
- 重复凭据、越界 RP ID、备份篡改和错误格式拒绝。
- 页面桥接的原生对象恢复、回退、错误映射和取消。
- Manifest 只申请 `storage` 权限，不含 `nativeMessaging` 或
  `webAuthenticationProxy`。

更多信息：

- [开发说明](docs/development.md)
- [页面桥接协议](docs/protocol.md)
- [安全边界](docs/security-boundary.md)

仓库只保留纯 Chrome 插件实现，不包含本机宿主、Native Messaging、Windows
安装器或其他历史版本源码。
