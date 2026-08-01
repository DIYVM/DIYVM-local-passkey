# 纯插件开发说明

本项目将 WebAuthn 软件验证器完整放入 Manifest V3 扩展，不依赖
Native Messaging、Windows 服务、安装器或本机可执行文件。

## 仓库结构

- `extension/src/software-authenticator.ts`：WebAuthn 注册、认证和 ES256 签名。
- `extension/src/pure-vault.ts`：主密码、Vault Key、AES-GCM 和凭据管理。
- `extension/src/indexeddb-vault.ts`：加密记录的 IndexedDB 事务层。
- `extension/src/vault-backup.ts`：加密备份导入、导出和完整性校验。
- `extension/src/background.ts`：来源校验、确认窗口和 WebAuthn 页面桥接。
- `extension/src/confirmation.*`：独立的扩展确认窗口。
- `extension/src/popup.*`：解锁、锁定、凭据管理和备份页面。
- `extension/src/types.ts`：页面桥接使用的序列化 WebAuthn 类型。

仓库不包含本机宿主、Native Messaging 或 Windows 安装器源码。

## 本地验证

在仓库根目录运行：

```text
npm install
npm run check
npm test
npm run build
```

测试会实际执行以下流程：

1. 创建 PBKDF2/AES-GCM 加密凭据库。
2. 为 webauthn.io 生成可发现的 ES256 凭据。
3. 解析并检查 attestation、COSE 公钥、RP ID 哈希和标志位。
4. 生成登录 assertion，并用注册公钥验证 DER 格式签名。
5. 验证签名计数器从 0 递增到 1、2。
6. 手动锁定、错误密码拒绝、正确密码恢复和长会话保持解锁。
7. 导出真实加密凭据，恢复到新 IndexedDB 后继续登录。
8. 拒绝重复凭据、越界 RP ID 和被篡改的备份。

## 手动加载

1. 运行 `npm run build`。
2. 在 Chrome 打开 `chrome://extensions`。
3. 开启开发者模式。
4. 加载 `extension/dist`。
5. 点击插件图标创建或解锁本地凭据库。

不需要安装或注册 Native Messaging Host。

## 测试站点

允许的顶层 HTTPS 站点：

- `https://webauthn.io`
- `https://amazon.com`
- `https://*.amazon.com`

不在白名单内的网站和条件式 WebAuthn 请求继续使用 Chrome 原生实现。

webauthn.io 是当前自动化验证目标。Amazon 使用同一套页面桥接和序列化
`PublicKeyCredential` 返回路径，真实账户已人工验证通行密钥创建和登录，但尚未
纳入自动化测试。
