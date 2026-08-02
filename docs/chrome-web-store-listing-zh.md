# Chrome Web Store 提交文案（DIYVM Local Passkey 0.4.1）

## 上传文件

上传 `DIYVM-Local-Passkey-Chrome-Web-Store-0.4.1.zip`。

## 商品详情

### 名称

DIYVM Local Passkey

### 简短说明

在 Chrome 内为 Amazon 创建、加密保存并使用本地通行密钥，无需云端凭据同步。

### 详细说明

DIYVM Local Passkey 是一款完全运行在 Chrome 扩展内的 Amazon 本地通行密钥工具。
扩展仅在 amazon.com 及其 HTTPS 子域运行，可在 Amazon 发起 WebAuthn 注册或登录
请求时创建和使用本地通行密钥。

通行密钥私钥、账户标识、RP ID 和凭据记录均经过 AES-256-GCM 加密后保存在用户
本地浏览器中，不会上传至 DIYVM 或开发者服务器。主密码不会保存，解锁后的会话
密钥会在用户手动锁定、Chrome 重启或扩展更新、重载后清除。

每次创建通行密钥或登录都会显示独立确认窗口。用户可以选择使用 DIYVM 本地通行
密钥、改用 Chrome、Windows Hello 或其他系统验证器，或者取消请求。

扩展支持加密凭据库的导出和恢复。导出文件只包含加密数据，恢复时仍需原主密码。

本项目为独立开发工具，与 Amazon.com, Inc. 及其关联公司不存在隶属、授权或背书
关系。建议仅在可恢复账户上使用，并始终保留密码、OTP 或其他安全密钥。

## 隐私权

### 单一用途说明

本扩展的单一用途是为 amazon.com 及其 HTTPS 子域提供完全在 Chrome 内运行的本地
通行密钥验证器。用户可以在 Amazon 发起 WebAuthn 请求时创建、加密保存并使用本地
通行密钥。主密码保护、凭据管理以及加密备份和恢复，均是实现本地通行密钥功能所
必需的辅助能力。本扩展不提供广告、数据分析、网页内容修改或其他无关功能。

### 请求 storage 权限的理由

storage 权限仅用于通过 chrome.storage.session 临时保存当前 Chrome 会话中的凭据库
解锁状态和本地 Vault Key，使扩展后台、管理弹窗和用户确认窗口能够在同一浏览器
会话内完成通行密钥创建与签名。该会话数据不会使用 storage.sync，也不会上传开发者
服务器；用户手动锁定、Chrome 重启或扩展更新、重载后会被清除。长期通行密钥记录
使用 AES-256-GCM 加密后保存在本地 IndexedDB 中。

### 请求主机权限的理由

本扩展仅请求 https://amazon.com/* 和 https://*.amazon.com/*，用于在 Amazon 页面
加载初期建立 WebAuthn 桥接，处理 navigator.credentials.create() 和
navigator.credentials.get() 请求。如果没有这些权限，扩展无法在 Amazon 页面原有
WebAuthn 代码运行前建立桥接。

扩展不会扫描网页正文，不读取 Cookie、普通表单内容或完整浏览历史。页面桥接只
处理 Amazon 发起的 WebAuthn 请求，并在每次创建或登录前显示独立确认窗口。用户
确认后，扩展仅把完成该次注册或登录所需的标准 WebAuthn 公共响应返回给发起请求的
Amazon 页面；通行密钥私钥和主密码不会离开本地设备。

### 远程代码

选择：不，我并未使用远程代码。

所有 JavaScript 和依赖均已包含在扩展安装包内。扩展不会下载或执行远程 JavaScript
或 WebAssembly，也不使用 eval()、new Function() 或远程脚本。DIYVM 官网链接仅在
用户主动点击后作为普通网页打开。

## 数据使用

勾选：

- 个人身份信息；
- 身份验证信息；
- 网络记录；
- 用户活动。

不勾选：

- 健康信息；
- 财务和付款信息；
- 个人通讯；
- 位置；
- 网站内容。

说明：

- 个人身份信息：Amazon WebAuthn 请求可能包含用户名、显示名称或电子邮箱；
- 身份验证信息：扩展处理主密码、通行密钥、凭据 ID、userHandle 和签名计数器；
- 网络记录：扩展加密保存通行密钥所属的 Amazon RP ID 和 Origin，不保存完整浏览
  历史；
- 用户活动：扩展在本地保存凭据创建时间和最近使用时间，只用于凭据展示和排序，
  不监控点击、鼠标、滚动或键盘输入。

下方三个 Limited Use 承诺全部勾选：

- 不会出于已获批准用途之外的用途出售或传输用户数据；
- 不会为与产品单一用途无关的目的使用或传输用户数据；
- 不会为确定信用度或贷款而使用或传输用户数据。

## 隐私政策网址

优先使用 DIYVM 官网的公开固定页面，例如：

https://www.diyvm.com/local-passkey/privacy

在官网页面上线前，可在推送仓库更新后暂时使用：

https://github.com/DIYVM/DIYVM-local-passkey/blob/main/docs/privacy-policy.md

商店提交前必须确认该网址无需登录、可以公开访问，并且内容与
`docs/privacy-policy.md` 一致。

## 测试说明

1. 安装扩展后，点击 Chrome 工具栏中的 DIYVM Local Passkey 图标。
2. 输入至少 12 个 UTF-8 字节的主密码，创建本地加密凭据库。
3. 使用可恢复的 Amazon 测试账户打开 amazon.com 或 sellercentral.amazon.com 的
   通行密钥注册/登录流程。Seller Central 可从 Login Settings 进入 Passkey 设置。
4. 当 DIYVM 确认窗口出现时，确认网站和账户，然后选择“使用本地通行密钥”。
5. 注册完成后退出 Amazon，再次选择通行密钥登录，验证本地凭据可完成签名。
6. 在确认窗口选择“改用 Chrome / 系统”，可验证请求会回退到 Chrome 原生验证器。
7. 测试结束后可在扩展弹窗中删除凭据或清除扩展数据。

请勿提供个人或生产 Amazon 账户。若审核团队要求账号，应提供专门创建、可恢复且不
包含真实订单、付款信息或业务数据的测试账户。

## 商店素材

- 屏幕截图：`01-vault-overview-1280x800.png`
- 屏幕截图：`02-login-confirmation-1280x800.png`
- 屏幕截图：`03-encrypted-backup-1280x800.png`
- 小型宣传图：`small-promo-tile-440x280.png`
- 顶部宣传图：`marquee-promo-tile-1400x560.png`

使用 `DIYVM-Chrome-Web-Store-Graphics-0.4.1.zip` 中的最新版素材，替换此前包含
example.com 或“所有 HTTPS 网站”描述的旧素材。
