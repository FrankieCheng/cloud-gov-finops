# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

"""Cloud Account IAM & Service Account Key Hygiene Auditor across GCP Organization projects."""

from __future__ import annotations

import concurrent.futures
import datetime
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from bot import config
from quota.models import AccountHygieneReport, SecurityHygieneFinding
from quota.scanner import _gcp_get_json, discover_org_projects_live

logger = logging.getLogger(__name__)

SENSITIVE_PORTS: dict[int, str] = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    1433: "MSSQL",
}


def _extract_exposed_sensitive_ports(allowed_rules: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    """Return `(allows_all_protocols, matched_sensitive_port_labels)`."""
    exposed: list[str] = []
    for rule in allowed_rules:
        proto = str(rule.get("IPProtocol") or "").lower()
        if proto == "all":
            return True, ["ALL_PROTOCOLS_AND_PORTS"]
        if proto not in ("tcp", "udp"):
            continue
        ports_raw = rule.get("ports")
        if not ports_raw:
            return True, [f"{proto.upper()}:1-65535"]
        for p_spec in ports_raw:
            s = str(p_spec).strip()
            if "-" in s:
                try:
                    lo, hi = (int(x) for x in s.split("-", 1))
                    for sp, label in SENSITIVE_PORTS.items():
                        if lo <= sp <= hi:
                            tag = f"{sp}/{label}"
                            if tag not in exposed:
                                exposed.append(tag)
                except ValueError:
                    continue
            else:
                try:
                    p_num = int(s)
                    if p_num in SENSITIVE_PORTS:
                        tag = f"{p_num}/{SENSITIVE_PORTS[p_num]}"
                        if tag not in exposed:
                            exposed.append(tag)
                except ValueError:
                    continue
    return False, exposed


def _gcp_post_json(url: str, token: str, payload: dict[str, Any], timeout: int = 15) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        return json.loads(raw) if raw else {}


def _audit_single_project_hygiene(
    project_id: str, token: str, now_utc: datetime.datetime
) -> tuple[bool, int, list[SecurityHygieneFinding]]:
    """Audit user-managed SA keys (>60d / >90d / sprawl) and IAM primitive/public bindings for 1 project."""
    findings: list[SecurityHygieneFinding] = []
    user_key_count = 0
    audited_ok = False
    p_enc = urllib.parse.quote(project_id)

    # 1. Service Account User-Managed Keys Rotation & Sprawl
    try:
        sa_resp = _gcp_get_json(
            f"https://iam.googleapis.com/v1/projects/{p_enc}/serviceAccounts?pageSize=100",
            token,
            timeout=15,
        )
        audited_ok = True
        for sa in sa_resp.get("accounts") or []:
            if bool(sa.get("disabled")):
                continue
            email = str(sa.get("email") or "").strip()
            if not email:
                continue
            keys_resp = _gcp_get_json(
                f"https://iam.googleapis.com/v1/projects/{p_enc}/serviceAccounts/{urllib.parse.quote(email)}/keys?keyTypes=USER_MANAGED",
                token,
                timeout=12,
            )
            sa_keys = list(keys_resp.get("keys") or [])
            user_key_count += len(sa_keys)

            if len(sa_keys) >= 2:
                findings.append(
                    SecurityHygieneFinding(
                        severity="WARNING",
                        category="SA_KEY_SPRAWL",
                        project_id=project_id,
                        principal=email,
                        resource_id=f"{len(sa_keys)} keys",
                        summary=f"服务账号 `{email}` 同时存在 {len(sa_keys)} 把有效静态私钥，建议迁移至 Workload Identity 并清理旧密钥。",
                        remediation_cli=f"gcloud iam service-accounts keys list --iam-account={email} --managed-by=user --project={project_id}",
                    )
                )

            for k in sa_keys:
                key_full = str(k.get("name") or "")
                key_short = key_full.split("/")[-1][:12]
                valid_after = str(k.get("validAfterTime") or "")
                try:
                    created_dt = datetime.datetime.fromisoformat(valid_after.replace("Z", "+00:00"))
                    age_days = max(0, (now_utc - created_dt).days)
                except ValueError:
                    continue

                if age_days >= 90:
                    findings.append(
                        SecurityHygieneFinding(
                            severity="CRITICAL",
                            category="SA_KEY_EXPIRED_90D",
                            project_id=project_id,
                            principal=email,
                            resource_id=key_short,
                            age_days=age_days,
                            summary=(
                                f"静态服务账号密钥 `{key_short}...` 已使用 **{age_days} 天**（超过 CIS 90 天强制轮换红线），存在长期凭证泄露风险！"
                            ),
                            remediation_cli=(
                                f"gcloud iam service-accounts keys delete {key_full.split('/')[-1]} "
                                f"--iam-account={email} --project={project_id}"
                            ),
                        )
                    )
                elif age_days >= 60:
                    findings.append(
                        SecurityHygieneFinding(
                            severity="WARNING",
                            category="SA_KEY_AGING_60D",
                            project_id=project_id,
                            principal=email,
                            resource_id=key_short,
                            age_days=age_days,
                            summary=f"静态服务账号密钥 `{key_short}...` 已使用 {age_days} 天（临近 90 天轮换期限）。",
                            remediation_cli=f"gcloud iam service-accounts keys list --iam-account={email} --project={project_id}",
                        )
                    )
    except urllib.error.HTTPError as exc:
        if exc.code not in (403, 404):
            logger.debug("SA key audit HTTP %s on %s", exc.code, project_id)
    except Exception as exc:
        logger.debug("SA key audit skipped on %s: %s", project_id, type(exc).__name__)

    # 2. Project-level IAM Policy: Public Principals & Over-privileged Default SAs
    try:
        pol = _gcp_post_json(
            f"https://cloudresourcemanager.googleapis.com/v1/projects/{p_enc}:getIamPolicy",
            token,
            payload={},
            timeout=15,
        )
        audited_ok = True
        for b in pol.get("bindings") or []:
            role = str(b.get("role") or "")
            for m in b.get("members") or []:
                mem = str(m)
                if mem in ("allUsers", "allAuthenticatedUsers"):
                    findings.append(
                        SecurityHygieneFinding(
                            severity="CRITICAL",
                            category="PUBLIC_IAM_EXPOSURE",
                            project_id=project_id,
                            principal=mem,
                            resource_id=role,
                            summary=f"项目 `{project_id}` 顶层 IAM 将 `{role}` 直接授予了公共主体 `{mem}`！",
                            remediation_cli=(
                                f"gcloud projects remove-iam-policy-binding {project_id} "
                                f"--member='{mem}' --role='{role}'"
                            ),
                        )
                    )
                elif role in ("roles/owner", "roles/editor") and (
                    "-compute@developer.gserviceaccount.com" in mem
                    or "@appspot.gserviceaccount.com" in mem
                ):
                    sa_mail = mem.split(":", 1)[-1]
                    findings.append(
                        SecurityHygieneFinding(
                            severity="HIGH",
                            category="DEFAULT_SA_OVERPRIVILEGED",
                            project_id=project_id,
                            principal=sa_mail,
                            resource_id=role,
                            summary=(
                                f"默认计算/应用服务账号 `{sa_mail}` 持有高危原始角色 `{role}`，"
                                "一旦工作负载被 SSRF 利用可横向接管整个项目。"
                            ),
                            remediation_cli=(
                                f"gcloud projects remove-iam-policy-binding {project_id} "
                                f"--member='{mem}' --role='{role}'"
                            ),
                        )
                    )
    except Exception as exc:
        logger.debug("Project IAM audit skipped on %s: %s", project_id, type(exc).__name__)

    # 3. VPC Firewall Perimeter Exposure (`0.0.0.0/0` or `::/0` to all ports or SSH/RDP/DB ports)
    try:
        fw_resp = _gcp_get_json(
            f"https://compute.googleapis.com/compute/v1/projects/{p_enc}/global/firewalls?maxResults=150",
            token,
            timeout=12,
        )
        for fw in fw_resp.get("items") or []:
            if bool(fw.get("disabled")) or str(fw.get("direction") or "INGRESS") != "INGRESS":
                continue
            src_ranges = set(fw.get("sourceRanges") or [])
            if not ("0.0.0.0/0" in src_ranges or "::/0" in src_ranges):
                continue
            fw_name = str(fw.get("name") or "unnamed-fw")
            net_name = str(fw.get("network") or "").split("/")[-1] or "default"
            allows_all, sens_ports = _extract_exposed_sensitive_ports(list(fw.get("allowed") or []))
            if allows_all:
                findings.append(
                    SecurityHygieneFinding(
                        severity="CRITICAL",
                        category="FIREWALL_OPEN_ALL_PORTS",
                        project_id=project_id,
                        principal="0.0.0.0/0",
                        resource_id=fw_name,
                        summary=(
                            f"VPC 防火墙规则 `{fw_name}`（网络 `{net_name}`）对公网 `0.0.0.0/0` 放行了 **全部协议与端口 (`all`)**，任何绑定公网 IP 的实例将完全暴露！"
                        ),
                        remediation_cli=(
                            f"gcloud compute firewall-rules update {fw_name} "
                            f"--disabled --project={project_id}"
                        ),
                    )
                )
            elif sens_ports:
                ports_str = ", ".join(sens_ports)
                findings.append(
                    SecurityHygieneFinding(
                        severity="HIGH",
                        category="FIREWALL_OPEN_SENSITIVE_PORT",
                        project_id=project_id,
                        principal="0.0.0.0/0",
                        resource_id=fw_name,
                        summary=(
                            f"VPC 防火墙规则 `{fw_name}`（网络 `{net_name}`）对公网 `0.0.0.0/0` 直接暴露了高危管理/数据库端口（{ports_str}），建议收敛至 IAP 网段 `35.235.240.0/20`。"
                        ),
                        remediation_cli=(
                            f"gcloud compute firewall-rules update {fw_name} "
                            f"--source-ranges=35.235.240.0/20 --project={project_id}"
                        ),
                    )
                )
    except Exception as exc:
        logger.debug("VPC firewall audit skipped on %s: %s", project_id, type(exc).__name__)

    return audited_ok, user_key_count, findings


def audit_account_hygiene(org_id: str = "", projects: list[str] | None = None) -> AccountHygieneReport:
    """Run organization-wide SA key & IAM security posture audit (supports LIVE and MOCK modes)."""
    now_utc = datetime.datetime.now(datetime.UTC)
    now_iso = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    eff_org = org_id or config.get_org_id()
    mode = config.get_api_mode()

    if mode == "MOCK":
        mock_findings = [
            SecurityHygieneFinding(
                severity="CRITICAL",
                category="SA_KEY_EXPIRED_90D",
                project_id="demo-core-prod",
                principal="legacy-ci-deployer@demo-core-prod.iam.gserviceaccount.com",
                resource_id="a1b2c3d4e5f6",
                age_days=99,
                summary="静态服务账号密钥 `a1b2c3d4e5f6...` 已使用 **99 天**（超过 CIS 90 天强制轮换红线）！",
                remediation_cli="gcloud iam service-accounts keys delete a1b2c3d4e5f6 --iam-account=legacy-ci-deployer@demo-core-prod.iam.gserviceaccount.com --project=demo-core-prod",
            ),
            SecurityHygieneFinding(
                severity="HIGH",
                category="DEFAULT_SA_OVERPRIVILEGED",
                project_id="demo-edge-svc",
                principal="100000000001-compute@developer.gserviceaccount.com",
                resource_id="roles/editor",
                summary="默认计算服务账号 `100000000001-compute@developer.gserviceaccount.com` 持有高危原始角色 `roles/editor`。",
                remediation_cli="gcloud projects remove-iam-policy-binding demo-edge-svc --member='serviceAccount:100000000001-compute@developer.gserviceaccount.com' --role='roles/editor'",
            ),
            SecurityHygieneFinding(
                severity="CRITICAL",
                category="FIREWALL_OPEN_ALL_PORTS",
                project_id="demo-core-prod",
                principal="0.0.0.0/0",
                resource_id="allow-internet-access-ingress",
                summary="VPC 防火墙规则 `allow-internet-access-ingress` 对公网 `0.0.0.0/0` 放行了 **全部协议与端口 (`all`)**！",
                remediation_cli="gcloud compute firewall-rules update allow-internet-access-ingress --disabled --project=demo-core-prod",
            ),
        ]
        try:
            from msa.service import get_msa_service

            snoozer = get_msa_service()
            visible_mock = [
                f
                for f in mock_findings
                if not snoozer.is_finding_snoozed(f.resource_id, f.principal, f"{f.project_id}:{f.category}")
            ]
            snoozed_cnt = len(mock_findings) - len(visible_mock)
        except Exception:
            visible_mock = mock_findings
            snoozed_cnt = 0

        return AccountHygieneReport(
            generated_at=now_iso,
            mode="MOCK",
            org_id=eff_org,
            projects_audited=["demo-core-prod", "demo-edge-svc"],
            total_user_managed_keys=2,
            keys_over_90_days=sum(1 for f in visible_mock if f.category == "SA_KEY_EXPIRED_90D"),
            keys_60_to_90_days=0,
            public_iam_bindings_count=0,
            overprivileged_sa_bindings_count=sum(
                1 for f in visible_mock if f.category == "DEFAULT_SA_OVERPRIVILEGED"
            ),
            open_firewall_rules_count=sum(
                1 for f in visible_mock if f.category.startswith("FIREWALL_OPEN_")
            ),
            snoozed_findings_count=snoozed_cnt,
            findings=visible_mock,
        )

    token = config.get_gcp_access_token()
    target_projects = list(projects or config.get_monitored_projects())
    if eff_org:
        for dp in discover_org_projects_live(eff_org, token):
            if dp not in target_projects:
                target_projects.append(dp)

    audited_projects: list[str] = []
    total_keys = 0
    raw_findings: list[SecurityHygieneFinding] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futs = {
            pool.submit(_audit_single_project_hygiene, pid, token, now_utc): pid
            for pid in target_projects
        }
        for fut in concurrent.futures.as_completed(futs):
            pid = futs[fut]
            try:
                ok, k_cnt, f_list = fut.result()
                if ok:
                    audited_projects.append(pid)
                total_keys += k_cnt
                raw_findings.extend(f_list)
            except Exception as exc:
                logger.debug("Hygiene worker failed on %s: %s", pid, type(exc).__name__)

    try:
        from msa.service import get_msa_service

        snoozer = get_msa_service()
        all_findings = [
            f
            for f in raw_findings
            if not snoozer.is_finding_snoozed(f.resource_id, f.principal, f"{f.project_id}:{f.category}")
        ]
        snoozed_cnt = len(raw_findings) - len(all_findings)
    except Exception:
        all_findings = raw_findings
        snoozed_cnt = 0

    sev_rank = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2}
    all_findings.sort(key=lambda f: (sev_rank.get(f.severity, 9), -(f.age_days or 0), f.project_id))

    return AccountHygieneReport(
        generated_at=now_iso,
        mode=mode,
        org_id=eff_org,
        projects_audited=sorted(audited_projects),
        total_user_managed_keys=total_keys,
        keys_over_90_days=sum(1 for f in all_findings if f.category == "SA_KEY_EXPIRED_90D"),
        keys_60_to_90_days=sum(1 for f in all_findings if f.category == "SA_KEY_AGING_60D"),
        public_iam_bindings_count=sum(1 for f in all_findings if f.category == "PUBLIC_IAM_EXPOSURE"),
        overprivileged_sa_bindings_count=sum(
            1 for f in all_findings if f.category == "DEFAULT_SA_OVERPRIVILEGED"
        ),
        open_firewall_rules_count=sum(
            1 for f in all_findings if f.category.startswith("FIREWALL_OPEN_")
        ),
        snoozed_findings_count=snoozed_cnt,
        findings=all_findings,
    )


def build_account_hygiene_feishu_card(
    report: AccountHygieneReport | dict[str, Any],
) -> dict[str, Any]:
    """Build Feishu interactive card for Cloud Account Security, Firewall Perimeter & IAM Key Hygiene."""
    d = report.to_dict() if isinstance(report, AccountHygieneReport) else report
    findings = list(d.get("findings") or [])
    k90 = int(d.get("keys_over_90_days") or 0)
    pub = int(d.get("public_iam_bindings_count") or 0)
    overpriv = int(d.get("overprivileged_sa_bindings_count") or 0)
    open_fw = int(d.get("open_firewall_rules_count") or 0)
    snoozed = int(d.get("snoozed_findings_count") or 0)

    has_crit = any(f.get("severity") == "CRITICAL" for f in findings)
    if k90 > 0 or pub > 0 or has_crit:
        template = "red"
        title = f"🔐 云账户安全基线告警（超期密钥 {k90} 把 | 高危防火墙 {open_fw} 条 | 公共IAM {pub} 项）"
    elif overpriv > 0 or open_fw > 0 or findings:
        template = "orange"
        title = f"⚠️ 云账户 IAM、密钥与网络边界提醒（共 {len(findings)} 项待收敛）"
    else:
        template = "green"
        title = "✅ 云账户 IAM、静态密钥与 VPC 防火墙基线全部合规"

    snooze_note = f" | 🔕 已静默豁免: {snoozed} 项" if snoozed > 0 else ""
    overview = (
        f"组织 ID: {d.get('org_id')} | 审计项目数: {len(d.get('projects_audited') or [])} | "
        f"用户自管 SA 密钥总数: {d.get('total_user_managed_keys', 0)}{snooze_note}\n"
        f"🔴 >90天未轮换密钥: {k90} | 🔴 公网高危防火墙 (0.0.0.0/0): {open_fw} | "
        f"🔴 公共IAM暴露: {pub} | 🟠 高危默认SA: {overpriv}"
    )
    elements: list[dict[str, Any]] = [
        {"tag": "div", "text": {"tag": "plain_text", "content": overview}},
        {"tag": "hr"},
    ]

    if not findings:
        elements.append(
            {
                "tag": "div",
                "text": {
                    "tag": "plain_text",
                    "content": "✅ 未发现超期未轮换静态私钥、公共 IAM 暴露或高危默认服务账号授权。",
                },
            }
        )
    else:
        lines: list[str] = []
        for f in findings[:10]:
            badge = "🔴" if f.get("severity") == "CRITICAL" else ("🟠" if f.get("severity") == "HIGH" else "🟡")
            lines.append(
                f"{badge} [{f.get('project_id')} · {f.get('category')}] {f.get('principal')}\n"
                f"  • 风险详情: {f.get('summary')}\n"
                f"  • 处置参考: {f.get('remediation_cli')}"
            )
        elements.append(
            {"tag": "div", "text": {"tag": "plain_text", "content": "\n\n".join(lines)[:3800]}}
        )

    elements.append(
        {
            "tag": "note",
            "elements": [
                {
                    "tag": "plain_text",
                    "content": "云管安全规范：生产环境优先采用 Workload Identity Federation 替代静态 JSON 密钥；移除默认 Compute SA 的 Editor 角色前请先核对工作负载最小权限。",
                }
            ],
        }
    )
    return {
        "config": {"wide_screen_mode": True},
        "header": {
            "template": template,
            "title": {"tag": "plain_text", "content": title},
        },
        "elements": elements,
    }
