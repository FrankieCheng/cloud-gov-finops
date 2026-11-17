# Cloud Governance & FinOps Agent（GCP 云管与账单异常监控平台）

面向企业云管（CMP）与财务运营（FinOps）团队的独立智能治理工程，采用 **三大核心业务域目录（`msa/`、`quota/`、`billing/`）+ 专用新飞书机器人（`bot/`）** 架构，基于 **Google ADK (`gemini-2.5-flash`)** 实现服务变更生命周期纳管、项目与组织双层配额监控、以及 BigQuery Billing Export 每日账单异常下钻推送。

> **与工单系统关系**：本工程（`~/cloud-gov-finops`）与工单助手（`cloud-case-manage`）完全独立解耦，通过**新的专用飞书机器人**（`FEISHU_GOV_APP_ID` / `FEISHU_GOV_APP_SECRET`）与独立 Cloud Run 服务（`cloud-gov-finops-agent`）运行。

---

## 📂 三目录核心代码架构

```text
cloud-gov-finops/
├── msa/                        # 【目录 1：云管 — MSA 服务公告、爆炸半径映射与审计台账】
│   ├── models.py               # MSA 分类枚举、状态机与紧迫度模型
│   ├── parser.py               # Google Sheet TSV/CSV 解析、DDL 提取与历史 429 脏数据自愈
│   ├── impact_matcher.py       # 基于活跃账单自动关联受影响真实 GCP 项目 (爆炸半径识别)
│   └── service.py              # SQLite 台账、审计轨迹 (msa_audit_events)、告警静默、TSV 导出与交互按钮卡片
│
├── quota/                      # 【目录 2：云管 — Project/Org 配额 (含429回溯) + IAM/密钥/防火墙安全】
│   ├── models.py               # 项目/组织配额模型、429 历史限流模型与账号/防火墙安全审计模型
│   ├── scanner.py              # 6 线程并发采集 Compute + Monitoring + Org Cloud Quotas + 近7日 429 超限事件与提额命令
│   ├── hygiene.py              # 全组织静态 SA 密钥 (>90d)/泛滥、公共 IAM、高危默认 SA 与 VPC 公网高危防火墙 (0.0.0.0/0) 审计
│   └── service.py              # ≥90% 红线告警、429 限流回溯、TTL 缓存加速与飞书配额卡片
│
├── billing/                    # 【目录 3：FinOps — 异常归因、预算预测、僵尸浪费回收与云架构降本】
│   ├── models.py               # 每日支出、月末预测、ESR 节省率、无标签黑盒占比与闲置资源模型
│   ├── analyzer.py             # 分区裁剪安全 SQL、公共分摊归集 (_BILLING_ACCOUNT_LEVEL_)、Z-Score/盘中冲高检测与 SKU 下钻
│   ├── finops_governance.py    # 月末净支出预测 (EOM Run-Rate)、ESR/CUD 节省分析、标签合规率、单实例 Top 10 与闲置静态 IP/孤儿盘扫描
│   ├── architecture_advisor.py # 同组织 VPN 转免费 VPC Peering、Cloud/DNS Armor 冗余、LB 常驻开销与高消耗 BigQuery SQL 任务归因
│   └── service.py              # 每日账单、成本治理与架构优化飞书卡片渲染
│
├── bot/                        # 【统一调度层：新飞书「GCP 云管与账单雷达」Bot + 0-100 健康评分卡】
│   ├── config.py               # 多级配置、SQL 表名/日期正则白名单校验与 GCP 鉴权
│   ├── cache.py                # 线程安全 TTL 缓存层 (消除多工具重复跨项目 API 扫描，响应提速 >50%)
│   ├── state_sync.py           # 本地原子快照 + 可选 GCS 持久化同步 (防止无状态容器重启丢失人工闭环与静默记录)
│   ├── agent.py                # Google ADK 主智能体 (gemini-2.5-flash)、14 项专业治理工具与 0-100 五维健康分引擎
│   ├── feishu_bot.py           # 飞书长连接机器人 (支持按钮点击原地 PATCH 卡片、群聊上下文智能路由与上传 .tsv/.csv 导入)
│   ├── scheduler.py            # 每日北京时间 09:00 全景自动巡检与签名 Webhook 推送器
│   └── server.py               # 安全加固的 FastAPI 服务网关 (含 TSV 导出、架构分析与静默接口)
│
├── deployment/deploy_gov_prod.sh
├── docs/
│   ├── DEPLOYMENT_GUIDE_ZH.md  # 中文部署与权限配置指南
│   └── FINOPS_CMP_MANUAL_ZH.md # 中文云管与 FinOps 使用手册
└── tests/                      # 单元、安全及真实 GCP 数据端到端仿真套件
```

---

## 📚 中文文档导航

- 🚀 **[部署与权限配置指南 (`docs/DEPLOYMENT_GUIDE_ZH.md`)](./docs/DEPLOYMENT_GUIDE_ZH.md)**
- 📖 **[云管与 FinOps 操作手册 (`docs/FINOPS_CMP_MANUAL_ZH.md`)](./docs/FINOPS_CMP_MANUAL_ZH.md)**
