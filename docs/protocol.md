# 页面桥接协议 v1

纯插件不再使用 Native Messaging。网页主世界、隔离 Content Script 和扩展后台通过
受限消息桥交换序列化的 WebAuthn 请求和响应。

## 边界

- 页面桥接通道：`local-passkey:webauthn:v1`。
- 页面到扩展的 public-key 负载最大 512 KiB。
- `requestId` 为 16–128 个 ASCII 字母、数字、`_` 或 `-`。
- 二进制统一使用无填充 Base64URL。
- 只接受顶层 HTTPS 页面。
- Content Script 校验 `event.source`、`event.origin`、消息类型、请求 ID、重复请求
  和负载大小。
- Background 只信任 Chrome 提供的 `sender.url` 和 `sender.tab`，不使用网页传入
  的 Origin。

## 注册请求

Page Script 拦截非条件式 `navigator.credentials.create()`，序列化：

- RP 与用户实体。
- challenge。
- 算法列表。
- 排除凭据。
- 验证器选择和扩展参数。

后台确认凭据库已解锁、RP ID 在产品白名单内且 ES256 可用，再打开独立确认窗口。
用户批准后，软件验证器返回可恢复为 `PublicKeyCredential` 的 attestation 数据。

## 登录请求

Page Script 拦截非条件式 `navigator.credentials.get()`，序列化 challenge、RP ID、
允许凭据和用户验证要求。后台只解密与 RP ID 和允许列表同时匹配的本地凭据。

登录响应包含：

- `clientDataJSON`。
- `authenticatorData`。
- DER 格式 ES256 签名。
- `userHandle`。
- 递增后的签名计数器。

## 确认和回退

每次操作都会打开 `confirmation.html`。该页面不是网站内容，也没有列入
`web_accessible_resources`。

- “使用本地通行密钥”：继续纯插件操作。
- “改用 Chrome / 系统”：调用插件安装前保存的原生 WebAuthn 方法。
- “取消”：返回 `AbortError`。

页面取消、确认窗口关闭或 120 秒超时都会终止等待中的操作。

## 商店版兼容路径

商店版不申请 `webAuthenticationProxy`。webauthn.io 和 Amazon 都通过同一页面桥接
返回恢复后的 `PublicKeyCredential` 对象；对象保留浏览器原型，并实现
`toJSON()`、`getClientExtensionResults()` 以及注册响应的公钥和传输方式方法。

webauthn.io 属于自动化验证范围。Amazon 的真实账户兼容性仍需人工测试；不支持的
参数、条件式请求或用户选择系统验证器时，会调用拦截前保存的 Chrome 原生方法。
