# DIYVM Local Passkey 隐私政策

生效日期：2026 年 8 月 2 日  
最近更新：2026 年 8 月 2 日

## 适用范围

本政策适用于 DIYVM Local Passkey Chrome 扩展。该扩展为独立开发工具，与
Amazon.com, Inc. 及其关联公司不存在隶属、授权或背书关系。

## 扩展处理的数据

为在 `amazon.com` 及其 HTTPS 子域提供本地通行密钥功能，扩展会处理：

- Amazon 页面通过 WebAuthn 请求提供的账户标识，例如用户名、显示名称和
  userHandle；
- 通行密钥身份验证信息，包括凭据 ID、公钥、私钥、RP ID、签名计数器和创建、
  最近使用时间；
- 发起 WebAuthn 请求的 Amazon Origin 和 RP ID；
- 用户输入的主密码。

扩展不会读取普通网页正文、Cookie、完整浏览历史、键盘输入记录、付款信息、健康
信息、位置或个人通讯。

## 数据用途

上述数据仅用于：

- 创建和使用本地通行密钥；
- 在用户确认后生成标准 WebAuthn 注册或登录响应；
- 展示和管理本地加密凭据；
- 导出和恢复用户主动创建的加密备份。

扩展会把标准 WebAuthn 公共响应返回给发起请求的 Amazon 页面，以完成用户选择的
注册或登录流程。该响应可能包含凭据 ID、公钥、签名、authenticatorData、
clientDataJSON 和 userHandle，但不包含通行密钥私钥或主密码。

## 本地存储和安全

- 通行密钥私钥、账户标识、RP ID 和凭据元数据使用 AES-256-GCM 加密后保存在扩展
  的本地 IndexedDB 中。
- 主密码用于通过 PBKDF2-SHA-256 包装本地 Vault Key。主密码不会被保存。
- 解锁后的 Vault Key 仅临时保存在 `chrome.storage.session`。用户手动锁定、
  Chrome 重启或扩展更新、重载后，该会话数据会被清除。
- 加密备份由用户主动导出并自行保管；扩展不会自动上传备份。

## 数据传输、共享和出售

扩展不会把用户数据、主密码、通行密钥私钥、浏览活动或使用分析数据发送到 DIYVM
或开发者控制的服务器。

除把完成注册或登录所必需的标准 WebAuthn 公共响应返回给用户正在使用的 Amazon
页面外，扩展不会向第三方出售、出租、共享或传输用户数据。数据不会用于广告、
画像、信用评估、贷款决定或与本地通行密钥功能无关的用途。

扩展界面中的 DIYVM 官网链接只有在用户主动点击后才会打开普通网页，不会在后台
传输扩展数据。

## 数据保留和删除

本地凭据会一直保留到用户在扩展中删除凭据、清除扩展数据或卸载扩展。用户导出的
加密备份由用户自行控制，卸载扩展不会删除用户另行保存的备份文件。

## Chrome 权限

- `storage`：用于在当前 Chrome 会话中临时保存凭据库解锁状态和 Vault Key。
- `https://amazon.com/*` 与 `https://*.amazon.com/*`：用于在 Amazon 页面加载初期
  建立 WebAuthn 桥接，处理通行密钥创建和登录请求。

扩展不申请访问所有网站的权限。

## Chrome Web Store Limited Use

本扩展对通过 Chrome API 获得的信息的使用遵守 Chrome Web Store User Data
Policy，包括 Limited Use 要求。用户数据只用于提供或改进扩展明确展示的本地通行
密钥功能，不用于个性化广告，也不会允许人工读取。

## 联系方式

如对本政策或数据处理方式有疑问，可通过项目问题页面联系：

https://github.com/DIYVM/DIYVM-local-passkey/issues
