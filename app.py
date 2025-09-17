import os
import io
from io import BytesIO
import pandas as pd
import streamlit as st
from analyzer import normalize_fields, llm_analysis, heuristic_analysis, UNIFIED_COLUMNS, USE_OPENAI

st.set_page_config(page_title="Cyber Incident AI Report", page_icon="🛡️", layout="wide")

st.title("🛡️ Cyber Incident AI Report (Web App)")
st.caption("อัปโหลดไฟล์ Incident (CSV/XLSX) → วิเคราะห์ด้วย AI → ดาวน์โหลดไฟล์ Excel ที่สรุปผล")

with st.expander("วิธีใช้", expanded=False):
    st.markdown("""
1) กด **Browse files** เพื่ออัปโหลดไฟล์ Incident (CSV หรือ XLSX)\n
2) เลือกว่าจะใช้ **AI (OpenAI)** หรือ **Heuristic (ไม่ใช้ AI)**\n
3) กด **Run Analysis** เพื่อสร้างผลสรุป\n
4) กด **Download XLSX** เพื่อดาวน์โหลดรายงาน
""")

left, right = st.columns([2,1])

with left:
    file = st.file_uploader("อัปโหลดไฟล์ CSV/XLSX", type=["csv","xlsx"])

with right:
    use_ai = st.checkbox("ใช้ AI (OpenAI)", value=bool(os.environ.get("OPENAI_API_KEY")))
    if use_ai and not os.environ.get("OPENAI_API_KEY"):
        st.warning("ไม่ได้ตั้งค่า OPENAI_API_KEY ใน environment → จะใช้ Heuristic แทน")

run = st.button("▶️ Run Analysis")

if run:
    if not file:
        st.error("กรุณาอัปโหลดไฟล์ก่อน")
        st.stop()

    # read input
    if file.name.lower().endswith(".csv"):
        df = pd.read_csv(file)
    else:
        df = pd.read_excel(file)

    # normalize fields
    df = normalize_fields(df)

    st.write("ตัวอย่างข้อมูลก่อนวิเคราะห์:", df.head(5))

    # analyze rows
    results = []
    for _, row in df.iterrows():
        if use_ai and USE_OPENAI:
            analysis, short_fix, long_fix = llm_analysis(row)
        else:
            analysis, short_fix, long_fix = heuristic_analysis(row)
        results.append({
            "Incident ID": row.get("issue_key") or row.get("issue_id"),
            "Use Case": row.get("use_case"),
            "Device": row.get("device_name"),
            "Severity": row.get("sev") or row.get("priority"),
            "Analysis (สรุปเหตุการณ์)": analysis,
            "Short Term Fix": short_fix,
            "Long Term Fix": long_fix,
            "Source IP": row.get("src_ip"),
            "Destination IP": row.get("dest_ip"),
            "Action": row.get("action"),
            "Signature": row.get("signature_name"),
            "File Path": row.get("file_path"),
            "Hash": row.get("hash"),
        })

    out_df = pd.DataFrame(results)

    st.success("วิเคราะห์เสร็จแล้ว ✅")

    # show preview
    st.dataframe(out_df.head(20), use_container_width=True)

    # to excel bytes
    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        out_df.to_excel(writer, index=False, sheet_name="AI Report")
    data = output.getvalue()

    st.download_button(
        label="⬇️ Download XLSX",
        data=data,
        file_name="cyber_incident_ai_report.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )