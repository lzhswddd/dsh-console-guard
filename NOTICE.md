# NOTICE / 归属说明

本仓库（dsh-console-guard）是以下项目的**加固源码派生分支**：

- 上游项目：**ChenJun25/dsh-console-plugin** — <https://github.com/ChenJun25/dsh-console-plugin>
- 上游版本基线：`0.5.64`（GitHub HEAD `58bffb2df9130b800203a92a3e0297c501abd621`，2026-11-04）
- 上游作者：CJ（ChenJun25）

## 许可

上游仓库**没有附带 LICENSE 文件**，但其 `package.json` 声明 `"license": "MIT"`。
本仓库据此按 MIT 许可保留上游版权与署名，并采用同一 MIT 许可（见 [`LICENSE`](LICENSE)）。

## 本分支改动

仅对上游源码做安全加固（路由白名单、配对端点收口、危险能力条件门控等），
未重新发布到 npm；具体改动见 [`docs/PATCH-PLAN.md`](docs/PATCH-PLAN.md)、
[`docs/host-hardening-notes.md`](docs/host-hardening-notes.md) 与
[`docs/verification.md`](docs/verification.md)。

## 与上游的关系

- 本仓库**不是**上游官方版本，也不代表上游作者立场；
- 上游后续更新不会自动合入本分支；
- 手机 App「DSH控制台」为上游作者的闭源应用，本仓库不包含、不修改、不逆向它。
