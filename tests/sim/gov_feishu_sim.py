"""End-to-End Live Verification & Feishu Bot Simulation for `cloud-gov-finops`.

Tests:
1. Real MSA TSV ingestion + 429 dirty-row self-healing + Gemini MSA governance turn
2. Real LIVE Project (`demo-core-prod`) + Organization (`123456789012`) Quota scan + Feishu card
3. Real LIVE BigQuery Billing Export (`demo-core-prod.billing.gcp_billing_export_resource_v1_01ABCD_EF0123_456789`)
   daily summary (latest settled day) + historical spike attribution (`2026-11-08`) + Feishu card
4. Real Gemini ADK Agent + GovFeishuBot end-to-end conversational turns
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

DATA_DIR = tempfile.mkdtemp(prefix="gov-finops-sim-")
os.environ.update(
    {
        "GOV_API_MODE": "LIVE",
        "CHAT_ENGINE": "llm",
        "GOV_DATA_DIR": DATA_DIR,
        "PREFER_GCLOUD_CLI_TOKEN": "1",
        "GOOGLE_GENAI_USE_VERTEXAI": "true",
        "GOOGLE_CLOUD_PROJECT": os.environ.get("GOOGLE_CLOUD_PROJECT", "demo-core-prod"),
        "GOOGLE_CLOUD_LOCATION": "global",
        "BILLING_BQ_PROJECT": "demo-core-prod",
        "BILLING_EXPORT_TABLES": "demo-core-prod.billing.gcp_billing_export_resource_v1_01ABCD_EF0123_456789",
        "GOV_ORG_ID": "123456789012",
        "GOV_PROJECTS": "demo-core-prod",
    }
)
sys.path.insert(0, os.getcwd())

from billing.service import get_billing_service  # noqa: E402
from bot.feishu_bot import GovFeishuBot  # noqa: E402
from bot.server import run_gov_agent_turn  # noqa: E402
from msa.service import get_msa_service  # noqa: E402
from quota.service import get_quota_service  # noqa: E402


class FakeGovApi:
    def __init__(self) -> None:
        self.sent: list[dict] = []

    def reply_text(self, mid: str, text: str) -> str:
        self.sent.append({"type": "text", "text": text})
        return "om_txt"

    def reply_markdown(self, mid: str, text: str) -> str:
        self.sent.append({"type": "md", "text": text})
        return "om_md"

    def reply_card(self, mid: str, card: dict) -> str:
        json.dumps(card, ensure_ascii=False)
        self.sent.append({"type": "card", "card": card})
        return "om_card"


class SyncExec:
    def submit(self, fn, *a, **k):
        fn(*a, **k)


CHECKS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    CHECKS.append((name, bool(ok), detail))
    print(f"  {'PASS' if ok else 'FAIL'}: {name}{(' -> ' + detail) if detail else ''}")


def main() -> int:
    print("=== 1. MSA Sheet Import & 429 Dirty-Row Healing ===")
    msa_svc = get_msa_service()
    tsv_path = Path(
        "./sample_msa_sheet.tsv"
    )
    if tsv_path.is_file():
        stats = msa_svc.import_from_tsv_file(tsv_path)
        check("MSA real Google Sheet TSV imported", stats["updated"] + stats["inserted"] >= 7, str(stats))
    radar = msa_svc.get_governance_radar()
    check("MSA 429 broken row healed cleanly", radar["healed_429_count"] >= 1, f"total={radar['total_records']}")

    print("\n=== 2. LIVE Project (demo-core-prod) + Org (123456789012) Quota Scan ===")
    q_rep = get_quota_service().scan_all(include_org=True)
    check(
        "LIVE Quota scan evaluated active metrics on demo-core-prod",
        "demo-core-prod" in q_rep.projects_scanned and q_rep.total_metrics_evaluated > 0,
        f"evaluated={q_rep.total_metrics_evaluated}, crit={len(q_rep.critical_over_90)}, warn={len(q_rep.warning_80_to_90)}",
    )
    for top_q in q_rep.top_utilized[:5]:
        print(f"    Top Quota: [{top_q.scope_id}|{top_q.region}] {top_q.display_name} = {top_q.usage:g}/{top_q.limit:g} ({top_q.utilization_pct:.1f}%)")

    print("\n=== 3. LIVE BigQuery Billing Export Analysis (Latest Settled + 2026-11-08 Spike) ===")
    b_svc = get_billing_service()
    latest_bill = b_svc.generate_daily_report()
    check(
        "LIVE Billing Export latest settled day queried",
        latest_bill.total_net_cost > 0 and len(latest_bill.projects_summary) >= 3,
        f"date={latest_bill.target_date}, total_net=${latest_bill.total_net_cost:.2f}, mtd=${latest_bill.mtd_total_net_cost:.2f}",
    )

    spike_bill = b_svc.generate_daily_report(target_date="2026-11-08", top_n=3)
    check(
        "LIVE Billing Export caught real 2026-11-08 $150+ spike with SKU root cause",
        len(spike_bill.suspected_anomalies) >= 1
        and spike_bill.suspected_anomalies[0].project_id == "demo-core-prod"
        and len(spike_bill.suspected_anomalies[0].top_sku_drivers) >= 1,
        f"top1={spike_bill.suspected_anomalies[0].project_id} ${spike_bill.suspected_anomalies[0].net_cost:.2f} "
        f"driver={spike_bill.suspected_anomalies[0].top_sku_drivers[0].service}/{spike_bill.suspected_anomalies[0].top_sku_drivers[0].sku}"
        if spike_bill.suspected_anomalies and spike_bill.suspected_anomalies[0].top_sku_drivers
        else "no driver",
    )
    for a in spike_bill.suspected_anomalies:
        print(f"    Anomaly #{a.rank}: {a.project_id} net=${a.net_cost:.2f} ({a.reason_summary})")
        for d in a.top_sku_drivers[:2]:
            print(f"      SKU Driver: {d.service} -> {d.sku} (${d.target_net_cost:.2f}, delta ${d.delta_net_cost:+.2f})")

    print("\n=== 4. Real Gemini + GovFeishuBot Conversational E2E ===")
    api = FakeGovApi()
    bot = GovFeishuBot(api, run_gov_agent_turn, executor=SyncExec(), bot_open_id="ou_gov_bot")

    def _dm(txt: str, mid: str) -> list[dict]:
        before = len(api.sent)
        ev = SimpleNamespace(
            event=SimpleNamespace(
                sender=SimpleNamespace(sender_id=SimpleNamespace(open_id="ou_user1"), sender_type="user"),
                message=SimpleNamespace(
                    message_id=mid,
                    chat_id="oc_dm_gov",
                    chat_type="p2p",
                    message_type="text",
                    content=json.dumps({"text": txt}),
                    mentions=[],
                    parent_id="",
                ),
            )
        )
        bot.handle_message_event(ev)
        return api.sent[before:]

    out1 = _dm("帮我盘点当前待处理的 MSA 服务公告，并把 Backup and DR 那条标记为已处理 MITIGATED，责任人 ops-lead", "om_g1")
    check(
        "Gemini queried & updated MSA status",
        any(x["type"] in ("md", "text") for x in out1) and msa_svc.get_msa("Backup and DR").status.value == "MITIGATED",
    )

    out2 = _dm("扫描一下项目和组织的 Quota 配额使用情况，看看有没有超过 90% 的配额风险", "om_g2")
    check(
        "Gemini ran Quota scan & attached Feishu Quota card",
        any(x["type"] == "card" for x in out2),
    )

    out3 = _dm("分析 2026-11-08 这一天各个项目的账单汇总和疑似异常波动的根因 SKU", "om_g3")
    md_txt = " ".join(x.get("text", "") for x in out3 if x["type"] in ("md", "text"))
    check(
        "Gemini analyzed 2026-11-08 Billing Export spike & attached FinOps card",
        "demo-core-prod" in md_txt and any(x["type"] == "card" for x in out3),
        md_txt[:180].replace("\n", " "),
    )

    passed = sum(1 for _, ok, _ in CHECKS if ok)
    print(f"\n===== RESULT: {passed}/{len(CHECKS)} checks passed =====")
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
