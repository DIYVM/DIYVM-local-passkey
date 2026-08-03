# 开发与发布

## 环境

- Node.js 20+
- npm
- Chrome 120+

安装、检查、测试和开发构建：

```bash
npm ci
npm run test:pure
```

`test:pure` 依次执行 TypeScript 类型检查、Node 测试和扩展构建。开发构建输出到
`extension/dist/`，并包含 source map。

Chrome Web Store 构建：

```bash
npm run build:store
```

商店构建同样输出到 `extension/dist/`，但不生成 source map。

## 目录

```text
extension/
  manifest.json
  scripts/build.mjs
  src/
    background.ts             后台消息、自动锁定与 WebAuthn 调度
    pure-vault.ts             加密保险库与数据迁移
    indexeddb-vault.ts        IndexedDB 存储
    password-model.ts         密码校验、生成和风险检查
    page-password-actions.ts  当前页面一次性捕获/填充
    password-autofill.ts      用户授权 Origin 的持续自动填充
    amazon-sites.ts           Amazon 市场清单
    site-access.ts            可选权限和动态脚本
    page-bridge.ts            Amazon 页面主世界 WebAuthn 桥接
    content-script.ts         隔离世界消息验证
    popup.*                   保险库界面
  test/
docs/
artifacts/                   本地发布产物，Git 忽略
```

## 数据兼容性

IndexedDB 数据库 schema 保持版本 1，以避免破坏旧安装。加密记录在解密后按 `kind`
区分 `password`、`passkey` 和固定的 `audit-log`。旧通行密钥记录缺少的新 UI 字段会
在读取时使用安全默认值。

保险库元数据同时识别旧 `PBKDF2-SHA-256` 与新 `ARGON2ID`。旧保险库只有在主密码
成功验证后才会重新包装 Vault Key；迁移不会修改通行密钥私钥或凭据 ID。

备份格式版本为 2，但导入器继续接受版本 1。

## 手动测试清单

1. 新建保险库，锁定、错误密码解锁、正确密码解锁。
2. 新增、编辑、搜索、收藏、删除、恢复和永久删除密码。
3. 生成密码，确认弱/重复/长期未更新统计。
4. 在一个 HTTPS 测试页执行点击读取和点击填充，确认不自动提交。
5. 分别验证页面登录弹窗、开放式 Shadow DOM、同源 iframe 和先账号后密码的分步登录。
6. 开启某 Origin 自动填充，刷新测试；撤销后确认脚本不再运行。
7. 逐项开启和关闭至少一个非美国 Amazon 市场权限。
8. 创建加密备份、验证、导入并确认导入后锁定。
9. 修改主密码，确认旧密码失败、新密码成功。
10. 验证 Amazon 通行密钥创建、登录、取消、超时和“改用系统”路径。
11. 关闭/重启 Chrome 后确认保险库锁定。

## 发布检查

```bash
npm ci
npm audit
npm run test:pure
npm run build:store
```

压缩时必须让 `manifest.json` 位于 ZIP 根目录。不得打包 `node_modules`、源码、
source map、测试文件、本地数据库、环境文件或任何 `.key`/证书文件。上传前确认：

- `manifest.json` 版本与 `package.json` 一致；
- Manifest 不含 `key`；
- 文件仅来自 `extension/dist/`；
- ZIP 可以重新解压并解析 Manifest；
- 保存 ZIP 的 SHA-256。
