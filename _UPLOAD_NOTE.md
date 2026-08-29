# 上传前必读（上传完成后请删除本文件）

这是 EvoNIDS 项目的干净导出副本，git 历史已就绪（`main` 分支），远程未配置。

## 给执行上传的助手（Codex）的操作步骤

1. **替换占位符**：以下文件中的 `USERNAME/EvoNIDS` 需替换为真实 `用户名/EvoNIDS`（仓库创建后确定）：
   `README.md`、`README.zh-CN.md`、`CITATION.cff`、`CHANGELOG.md`、`.github/ISSUE_TEMPLATE/config.yml`
   （各文件内均有 `replace USERNAME` 注释标记）
2. **提交替换结果**：`git add -A && git commit -m "docs: point badges and citation to the published repository"`
3. **创建 GitHub 仓库**：名称建议 `EvoNIDS`，**公开**（Public），**不要**用 README/.gitignore/license 初始化
4. **推送**：
   ```bash
   git remote add origin https://github.com/<用户名>/EvoNIDS.git
   git push -u origin main
   ```
5. **删除本文件并再次推送**：`git rm _UPLOAD_NOTE.md && git commit -m "chore: remove upload note" && git push`

## 可选（不影响运行）

- 提交署名若需挂 GitHub 头像：`git config user.name "<用户名>" && git config user.email "<GitHub noreply 邮箱>" && git commit --amend --reset-author --no-edit`
- 完整复现材料（非必需）：`backend/datasets/CICIDS2017/*.csv.gz`（约 235MB）与已训练模型产物可作 Release 附件上传，校验值见 `DATA_CARD.md`
- 推送后在仓库 Settings → About 填写简介并添加 topics：`ids` `nids` `intrusion-detection` `deepseek` `suricata` `fastapi` `nuxt` `cicids2017`

## 本仓库内容自检基线

- 219 个跟踪文件；后端测试 11/11 通过；前端 typecheck/lint/vitest 30 项/build 全绿
- 不含 `.env`、数据库、数据集大文件、模型产物、临时目录、本机绝对路径、任何人名（演示角色已中性化为 Root / 分析师A / 分析师B）
