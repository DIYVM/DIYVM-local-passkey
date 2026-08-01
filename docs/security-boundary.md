# 纯插件安全边界

当前 `0.3.0` 使用 Chrome Web Store 架构，但仍未经过外部安全审计或商店审核。

## 来源与消息信任链

1. Manifest 只把页面代码注入 `webauthn.io`、`amazon.com` 及 Amazon HTTPS 子域。
2. Page Script 只拦截顶层页面的非条件式 WebAuthn 请求。
3. Content Script 校验消息来源、Origin、通道、请求 ID、重复请求和 512 KiB 上限。
4. Background 使用 Chrome 提供的 `sender.url` 推导 Origin，不信任网页字段。
5. 软件验证器再次校验 HTTPS Origin、产品白名单和 RP ID 范围。
6. 确认页面属于扩展自身，未暴露为网页可访问资源。

## 凭据和密钥

- 每枚通行密钥使用 Web Crypto 生成独立 ES256 / P-256 密钥。
- 私钥以 PKCS#8 形式进入凭据明文结构后，连同 RP ID、userHandle、账户名和计数器
  整体使用 AES-256-GCM 加密。
- 每条记录使用随机 96 位 IV，并把凭据 ID 作为 AAD 的一部分。
- Vault Key 是随机 256 位密钥。
- 主密码必须为 12–1024 个 UTF-8 字节。
- PBKDF2-SHA-256 使用随机 128 位 salt 和 600,000 次迭代，只用于包装 Vault Key。
- IndexedDB 不保存明文 RP ID、账户名、userHandle 或私钥。
- 解锁后的原始 Vault Key 保存到 Chrome `storage.session`，默认只允许扩展可信上下文
  访问；锁定、Chrome 关闭或 15 分钟空闲后清除。
- JavaScript 和浏览器内存不提供与硬件安全模块相同的不可提取或可靠清零保证。

## 备份

- 导出文件只包含 KDF 参数、包装后的 Vault Key 和 AES-GCM 加密记录。
- 导入先限制为 20 MiB，再验证格式、版本、字段边界、重复 ID 和 SHA-256。
- 所有检查通过后才在一个 IndexedDB 读写事务内替换当前库。
- SHA-256 用于检测文件损坏，不是带密钥的真实性证明；AES-GCM 在解锁和读取时继续
  检测加密字段篡改。
- 取得完整备份的攻击者可以离线猜测主密码，PBKDF2 只能提高猜测成本。

## 用户确认

每次创建或登录都会显示 DIYVM 扩展窗口，展示 RP ID 和账户：

- 使用本地通行密钥。
- 改用 Chrome、Windows Hello 或 USB 安全密钥。
- 取消请求。

主密码解锁建立本地用户验证会话，因此响应设置 UP 和 UV 标志。这里的 UV 是软件
主密码会话，不等同于 Windows Hello 生物识别或硬件验证。

## 已知限制

- 纯插件的安全边界弱于 TPM、Windows Hello 和 USB FIDO2 硬件。
- 扩展更新代码与解锁后的 Vault Key、解密能力位于同一 Chrome 扩展信任边界。
- PBKDF2 不具备 Argon2id 的内存硬特性。
- 页面桥接恢复的是带浏览器原型的 JavaScript `PublicKeyCredential` 对象，不是
  Chrome 内部验证器直接创建的对象，因此需要持续验证目标网站兼容性。
- 条件式 WebAuthn 不被拦截。
- 仅支持 ES256 和当前白名单站点。
- Amazon 真实账户尚未由自动化测试验证。
- 尚未完成 Chrome Web Store 审核、外部安全审计和 Windows 实机矩阵。

测试时必须使用可恢复账户，并保留密码、OTP 或其他安全密钥。
