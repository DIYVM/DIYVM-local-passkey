# 页面桥接协议 v1

本协议只用于受支持 Amazon 站点的通行密钥流程。普通密码捕获和填充通过
`chrome.scripting.executeScript` 或用户授权的动态 Content Script 完成，不使用此协议。

## 通道与边界

- 页面消息通道：`local-passkey:webauthn:v1`。
- 只接受顶层、HTTPS、已启用 Amazon Origin。
- `requestId` 为 16–128 个 ASCII 字母、数字、`_` 或 `-`。
- 页面到扩展的 public-key 载荷上限为 512 KiB。
- 二进制数据统一使用无填充 Base64URL。
- Content Script 验证消息来源、Origin、类型、请求 ID、重复请求和负载大小。
- Background 只信任 Chrome 提供的 `sender.url` 和 `sender.tab`。

## 创建凭据

页面主世界脚本仅拦截非条件式 `navigator.credentials.create()`，序列化：

- RP 与用户实体；
- challenge；
- 算法列表；
- 排除凭据；
- 验证器选择和扩展参数。

后台验证保险库已经解锁、实际来源属于启用的 Amazon 市场、RP ID 与来源匹配且包含
ES256。用户在独立确认窗口批准后，软件验证器创建密钥并返回可恢复为
`PublicKeyCredential` 的 attestation 数据。

## 获取断言

页面脚本仅拦截非条件式 `navigator.credentials.get()`，序列化 challenge、RP ID、
允许凭据和用户验证要求。后台只解密 RP ID 与允许列表同时匹配的本地凭据。

返回内容包括：

- `clientDataJSON`；
- `authenticatorData`；
- DER 格式 ES256 签名；
- `userHandle`；
- 递增后的签名计数器。

## 确认、取消与回退

本地创建或签名会打开 `confirmation.html`：

- “使用本地通行密钥”：继续本地操作；
- “改用 Chrome / 系统”：调用扩展安装前保存的原生 WebAuthn 方法；
- “取消”：返回 `AbortError`。

页面取消、确认窗口关闭或 120 秒超时都会终止等待中的操作。条件式请求、不支持的
算法/参数、未启用网站或用户选择系统验证器时回退到 Chrome 原生实现。

## 兼容策略

商店版不申请 `webAuthenticationProxy`，而是在受支持页面加载初期桥接 WebAuthn。
恢复后的对象保留浏览器原型，并实现 `toJSON()`、`getClientExtensionResults()` 以及
注册响应所需的公钥与传输方式方法。

协议版本保持 `v1`，以兼容已发布版本。扩展的产品名称或保险库数据模型变化不改变
页面消息格式。
