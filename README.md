<div align="center">
  <img src="./extension/src/logo.png" width="112" height="112" alt="DIYVM Local Passkey">
  <h1>DIYVM Local Passkey</h1>
  <p>本地优先、可选用户自有 OSS 加密备份的密码与通行密钥管理器。</p>
  <p>
    <img src="https://img.shields.io/badge/version-1.1.1-2458d3?style=flat-square" alt="Version 1.1.1">
    <img src="https://img.shields.io/badge/Manifest-V3-34a853?style=flat-square" alt="Manifest V3">
    <img src="https://img.shields.io/badge/license-Apache--2.0-f59e0b?style=flat-square" alt="Apache-2.0">
  </p>
  <p>
    <a href="./README_EN.md">English</a> ·
    <a href="./CHANGELOG.md">更新记录</a> ·
    <a href="./docs/privacy-policy.md">隐私政策</a> ·
    <a href="./docs/security-boundary.md">安全边界</a> ·
    <a href="./docs/chrome-web-store-listing-zh.md">商店提交文案</a>
  </p>
</div>

## 这是什么

DIYVM Local Passkey `1.1.0` 把原来的 Amazon 本地通行密钥工具扩展为本地密码与
通行密钥保险库。扩展不需要 DIYVM 账户或开发者服务器；密码、通行密钥私钥和操作
记录均先加密，再保存到浏览器本地。用户也可以选择把完整加密备份手动上传到自己的
阿里云 OSS。

原 `0.4.x` 保险库会在首次成功解锁时自动迁移密钥派生元数据，已有通行密钥无需重建。

## 主要功能

- 在同一个加密保险库中管理密码和 ES256 通行密钥。
- 支持 Amazon 全球主要站点的通行密钥创建和登录。
- 当前页面可由用户点击后匹配并填充密码，不自动提交表单。
- 优先识别当前登录弹窗，并支持同源 iframe、开放式 Shadow DOM 和分步登录。
- 可为指定 HTTPS 网站单独授权持续自动填充；默认不获取任意网站的长期访问权限。
- 新建、编辑、搜索、收藏、标签、备注、别名、回收站与恢复。
- 可配置密码生成器，并在本地检查弱密码、重复密码和长期未更新密码。
- 5、15、30 或 60 分钟自动锁定；关闭浏览器会丢弃会话密钥。
- 加密备份、备份结构校验、完整恢复与主密码修改。
- 可选用户自有阿里云 OSS 手动加密备份，不经过 DIYVM 服务器。
- 加密的本地操作日志，不含明文密码。

## 安全设计

```mermaid
flowchart LR
    A["主密码"] --> B["Argon2id"]
    B --> C["包装随机 Vault Key"]
    C --> D["AES-256-GCM 加密记录"]
    D --> E["Chrome IndexedDB"]
    F["解锁会话"] --> G["chrome.storage.session"]
    H["用户点击填充"] --> I["activeTab + scripting"]
    J["指定网站自动填充"] --> K["逐站点可选授权"]
    D --> L["加密备份"]
    L --> M["可选：用户自有 OSS"]
```

- 新保险库使用 Argon2id（19 MiB、2 次迭代、并行度 1）派生包装密钥。
- 每条密码、通行密钥与审计记录使用 AES-256-GCM 独立加密。
- 主密码不保存；解锁后的 Vault Key 仅放在浏览器会话存储中，并受自动锁定限制。
- 密码只对完全相同的 HTTPS Origin 匹配；扩展不会点击登录按钮或自动提交。
- 通行密钥页面桥接仅用于受支持的 Amazon 顶层页面，并验证实际发送方 Origin 和 RP ID。
- 扩展不加载远程 JavaScript、Wasm 或配置代码。

详细威胁模型和限制见[安全边界](./docs/security-boundary.md)。

## 权限说明

| 权限 | 用途 |
| --- | --- |
| `storage` | 保存非敏感设置和临时解锁会话 |
| `activeTab` | 用户点击扩展后读取或填充当前标签页的登录表单 |
| `scripting` | 在当前标签页执行一次性捕获/填充，并注册用户授权站点的脚本 |
| `alarms` | 到达用户设置的时间后自动锁定保险库 |
| `amazon.com` 主机权限 | 保持原版 Amazon 美国站通行密钥功能 |
| 其他 Amazon 主机权限（可选） | 只在用户开启对应国家/地区站点时申请 |
| 其他 HTTPS 主机权限（可选） | 只在用户开启精确 Origin 自动填充，或连接自己的 OSS Bucket 时申请，可随时撤销 |

点击式填充不需要授予网站长期权限。清单中的 `https://*/*` 只是允许 Chrome 在用户主动
选择某个网站或 OSS Bucket 时显示精确主机授权提示；扩展不会一次请求全部网站。

## 支持的 Amazon 站点

美国站默认启用。设置中可按需开启加拿大、墨西哥、巴西、英国、德国、法国、意大利、
西班牙、荷兰、瑞典、波兰、比利时、爱尔兰、土耳其、日本、印度、澳大利亚、新加坡、
阿联酋、沙特、埃及和南非站及其 HTTPS 子域。

## 本地开发

要求 Node.js 20+ 和 Chrome 120+。

```bash
npm ci
npm run test:pure
```

开发构建输出到 `extension/dist/`。在 `chrome://extensions` 开启开发者模式，选择
“加载已解压的扩展程序”，然后选择该目录。

正式商店构建不包含 source map：

```bash
npm run build:store
```

## 使用流程

1. 打开扩展并设置主密码，或用原主密码解锁已有保险库。
2. 在“密码”中手动添加，或在目标网站打开登录表单后点击“读取当前表单”。
3. 默认通过“填充当前页面”完成一次性填充；如确有需要，可为当前 HTTPS 网站开启自动填充。
4. 在“设置”中开启需要的 Amazon 国家/地区站点。
5. 定期导出加密备份，并使用“验证备份”确认文件可读取。
6. 可选：在“设置”中连接用户自有阿里云 OSS，手动上传、检查或恢复加密备份。

## 1.1.0 的边界

- 不提供多设备双向实时同步、共享保险库、支付卡或身份资料自动填充。
- 软件通行密钥的隔离强度低于 TPM、Secure Enclave 或独立硬件安全密钥。
- 密码填入网页后，该网页自身的脚本可能读取输入框内容；只应在可信、域名正确的网站填充。
- 本项目完成了自动化测试和代码级安全检查，但不宣称已通过独立第三方安全审计。
- Chrome Web Store 中已经发布的旧版本与本仓库的 `1.1.0` 更新是不同审核批次；提交更新后
  仍需等待 Google 审核。

## 数据与隐私

扩展不收集遥测、不展示广告、不出售数据，也不向 DIYVM 服务器发送保险库。只有用户
明确启用 OSS 功能时，完整加密备份才会发送到用户配置的阿里云 OSS。卸载扩展会删除
Chrome 管理的本地扩展数据，但不会删除磁盘或 OSS 中的备份。完整说明见
[隐私政策](./docs/privacy-policy.md)。

## 开源许可

[Apache License 2.0](./LICENSE)
