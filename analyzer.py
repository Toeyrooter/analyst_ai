import os
from typing import Dict, Tuple
import pandas as pd

# Optional: OpenAI (only used if OPENAI_API_KEY is set)
USE_OPENAI = bool(os.environ.get("OPENAI_API_KEY"))
if USE_OPENAI:
    try:
        from openai import OpenAI
        _client = OpenAI()
    except Exception:
        USE_OPENAI = False
        _client = None

# ---------- Field normalization ----------
FIELD_MAP = {
    # common core fields (extend as you like)
    "Summary": "summary",
    "Issue key": "issue_key",
    "Issue id": "issue_id",
    "Issue Type": "issue_type",
    "Status": "status",
    "Priority": "priority",
    "Created": "created_at",
    "Updated": "updated_at",
    "Resolution": "resolution",
    "Assignee": "assignee",
    "Reporter": "reporter",
    "Description": "description",

    # security-ish fields (map many variants to unified columns)
    "Custom field (A-Source IP)": "src_ip",
    "Custom field (Source IP)": "src_ip",
    "Source IP": "src_ip",
    "Custom field (A-Destination IP)": "dest_ip",
    "Custom field (Destination IP)": "dest_ip",
    "Destination IP": "dest_ip",
    "Custom field (A-Device Name)": "device_name",
    "Custom field (Device Name)": "device_name",
    "Device Name": "device_name",
    "Custom field (A-Event Severity)": "sev",
    "Custom field (Severity)": "sev",
    "Severity": "sev",
    "Custom field (A-Use Case Name)": "use_case",
    "Custom field (Use Case Name)": "use_case",
    "Use Case Name": "use_case",
    "Custom field (A-Signature Name)": "signature_name",
    "Signature Name": "signature_name",
    "Custom field (A-Action)": "action",
    "Action": "action",
    "Custom field (A-Hash)": "hash",
    "Custom field (File Hash)": "hash",
    "File Hash": "hash",
    "Custom field (A-File Path)": "file_path",
    "File Path": "file_path",
}

UNIFIED_COLUMNS = [
    "issue_key","issue_id","issue_type","status","priority","resolution",
    "assignee","reporter","created_at","updated_at",
    "summary","description",
    "device_name","use_case","sev","action","signature_name","file_path","hash",
    "src_ip","dest_ip"
]

def normalize_fields(df: pd.DataFrame) -> pd.DataFrame:
    """Rename known columns to unified names and keep originals."""
    renamed = {}
    for col in df.columns:
        unified = FIELD_MAP.get(col)
        if unified:
            renamed[col] = unified
    df = df.rename(columns=renamed)
    # ensure all unified columns exist
    for c in UNIFIED_COLUMNS:
        if c not in df.columns:
            df[c] = pd.NA
    return df

# ---------- Heuristic analysis (rule-based fallback) ----------
def heuristic_analysis(row: pd.Series) -> Tuple[str, str, str]:
    summary = (row.get("summary") or "")[:3000]
    desc = str(row.get("description") or "")
    sev = (str(row.get("sev") or row.get("priority") or "")).lower()
    use_case = (row.get("use_case") or "").lower()
    signature = (row.get("signature_name") or "").lower()
    action = (row.get("action") or "").lower()

    # classify coarse incident type
    incident_type = "General Security Event"
    if "malware" in summary.lower() or "edr" in summary.lower() or "malware" in desc.lower() or "heu_" in signature:
        incident_type = "Malware Detection"
    elif "brute" in summary.lower() or "4625" in desc or "failed login" in summary.lower() or "vpn" in summary.lower():
        incident_type = "Brute Force / Auth Abuse"
    elif "waf" in summary.lower() or "sql injection" in summary.lower() or "xss" in summary.lower():
        incident_type = "Web Attack / WAF"
    elif "ips" in summary.lower() or "signature" in summary.lower():
        incident_type = "Intrusion Prevention Alert"

    # derive severity
    sev_map = {"critical":"Critical","high":"High","medium":"Medium","low":"Low"}
    severity = next((sev_map[k] for k in sev_map if k in sev), "Medium")

    # analysis text
    analysis = (
        f"ประเภทเหตุการณ์: {incident_type}. "
        f"สรุป: {summary[:400]}"
    ).strip()

    # short-term
    short_fix = []
    if incident_type == "Malware Detection":
        short_fix += [
            "Isolate เครื่องที่เกี่ยวข้องออกจากเครือข่าย",
            "IOC Hunting: ตรวจ Hash / File Path บนเครื่องอื่น",
            "รัน Full Scan ด้วย EDR/AV และลบไฟล์ต้องสงสัย",
        ]
        if "terminate" in action:
            short_fix.append("ยืนยันผลการ Terminate ว่ากระบวนการหยุดจริง")
    elif incident_type == "Brute Force / Auth Abuse":
        short_fix += [
            "บังคับ Reset Password และบังคับ MFA",
            "บล็อก IP/ประเทศต้นทางชั่วคราวบน VPN/Firewall",
            "ตรวจสอบบัญชีที่พยายามล็อกอินผิดปกติ"
        ]
    elif incident_type == "Web Attack / WAF":
        short_fix += [
            "บล็อก Signature/URL ที่โจมตีบน WAF ทันที",
            "ตรวจสอบ Log App/DB หา Injection หรือ Data Exfiltration",
            "เผยแพร่ Hotfix/Rule เสริมระบบ"
        ]
    else:
        short_fix += [
            "รวบรวม Log เพิ่มเติมจากอุปกรณ์ที่เกี่ยวข้อง",
            "ตั้ง Alert ชั่วคราวเพื่อเฝ้าระวังเหตุซ้ำ"
        ]

    # long-term
    long_fix = [
        "ปรับจูน Policy/SIEM Rule ให้ลด False Positive",
        "ทำ Security Awareness และ Phishing Drill รายไตรมาส",
        "เสริม Zero Trust / Least Privilege"
    ]
    if incident_type == "Malware Detection":
        long_fix += [
            "ทำ Application Whitelisting/Blocklist",
            "เพิ่ม Telemetry EDR และ Deploy Latest Signature อย่างสม่ำเสมอ"
        ]
    if incident_type == "Brute Force / Auth Abuse":
        long_fix += [
            "บังคับใช้ MFA ทุกระบบที่สำคัญ",
            "ปรับ Password Policy และ Account Lockout Policy",
        ]
    if incident_type == "Web Attack / WAF":
        long_fix += [
            "ทำ Secure Coding Review/DAST",
            "ปรับ Tuning Rule ของ WAF และเพิ่ม Ratelimit"
        ]

    return (
        analysis,
        " • " + " | ".join(short_fix),
        " • " + " | ".join(long_fix),
    )

# ---------- LLM analysis (enhanced, optional) ----------
LLM_SYSTEM = """คุณคือนักวิเคราะห์เหตุการณ์ความปลอดภัยไซเบอร์ของ SOC
ตอบเป็นภาษาไทยแบบกระชับ ชัดเจน แบ่งเป็น 3 ส่วน: 
1) สรุปเหตุการณ์/ความเสี่ยง 
2) แนวทางแก้ไขระยะสั้น 
3) แนวทางแก้ไขระยะยาว
"""

def llm_analysis(row: pd.Series) -> Tuple[str, str, str]:
    if not USE_OPENAI or _client is None:
        return heuristic_analysis(row)

    content = (
        f"Summary: {row.get('summary','')}\n"
        f"Description: {row.get('description','')}\n"
        f"Severity: {row.get('sev') or row.get('priority')}\n"
        f"Device: {row.get('device_name')}\n"
        f"Use Case: {row.get('use_case')}\n"
        f"Action: {row.get('action')}\n"
        f"Signature: {row.get('signature_name')}\n"
        f"File Path: {row.get('file_path')}\n"
        f"Hash: {row.get('hash')}\n"
        f"Source IP: {row.get('src_ip')}  Destination IP: {row.get('dest_ip')}\n"
    )

    try:
        resp = _client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role":"system","content": LLM_SYSTEM},
                {"role":"user","content": content}
            ],
            temperature=0.2,
        )
        text = resp.choices[0].message.content.strip()
    except Exception:
        # fail safe
        return heuristic_analysis(row)

    # naive split
    lines = [l.strip("-• ").strip() for l in text.splitlines() if l.strip()]
    analysis, short_fix, long_fix = "", "", ""
    bucket = 1
    acc = []
    for l in lines:
        if l.startswith("1") or "สรุป" in l and not analysis:
            if acc: analysis = " ".join(acc); acc=[]
            bucket = 1
            continue
        if l.startswith("2") or "ระยะสั้น" in l and not short_fix:
            if acc: analysis = " ".join(acc); acc=[]
            bucket = 2
            continue
        if l.startswith("3") or "ระยะยาว" in l and not long_fix:
            if bucket==1 and acc: analysis = " ".join(acc); acc=[]
            if bucket==2 and acc: short_fix = " • " + " | ".join(acc); acc=[]
            bucket = 3
            continue
        acc.append(l)

    if bucket==1 and acc: analysis = " ".join(acc)
    elif bucket==2 and acc: short_fix = " • " + " | ".join(acc)
    elif bucket==3 and acc: long_fix = " • " + " | ".join(acc)

    if not analysis or not short_fix or not long_fix:
        # mix with heuristic when parsing uncertain
        h1,h2,h3 = heuristic_analysis(row)
        analysis = analysis or h1
        short_fix = short_fix or h2
        long_fix = long_fix or h3

    return analysis, short_fix, long_fix