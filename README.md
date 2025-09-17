# 🛡️ Cyber Incident AI Report (Web App)

อัปโหลดไฟล์ Incident (CSV/XLSX) → วิเคราะห์ด้วย AI/Heuristic → ดาวน์โหลดเป็น Excel

## คุณสมบัติ
- รองรับไฟล์ CSV/XLSX ที่ export จาก Jira/Service Desk (มี field จำนวนมาก)
- Normalize ฟิลด์สำคัญ (เช่น Summary, Severity, Device, Source/Destination IP, Hash, File Path ฯลฯ)
- วิเคราะห์แบบ **AI (OpenAI)** ถ้ามี `OPENAI_API_KEY` หรือ **Heuristic** ถ้าไม่มี
- สร้างรายงานผลลัพธ์เป็น **Excel** พร้อมสรุป: วิเคราะห์เหตุการณ์ / แนวทางแก้ไขระยะสั้น / ระยะยาว

## วิธีติดตั้งและใช้งาน (Local)
```bash
# 1) สร้างและเข้าโฟลเดอร์
unzip cyber_incident_ai_report_app.zip
cd cyber_incident_ai_report_app

# 2) สร้าง env และติดตั้ง lib
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# (ตัวเลือก) ใช้ AI ของ OpenAI
export OPENAI_API_KEY=YOUR_KEY   # Windows PowerShell: $env:OPENAI_API_KEY="YOUR_KEY"

# 3) รันเว็บแอป
streamlit run app.py
```

เปิดเบราว์เซอร์: http://localhost:8501

## โครงสร้างโปรเจกต์
```
.
├── app.py                # Streamlit UI
├── analyzer.py           # Field normalization + AI/Heuristic analysis
├── requirements.txt
├── sample_data.csv       # ตัวอย่างข้อมูล (แก้ให้ตรงกับฟิลด์ที่คุณมี)
└── README.md
```

## การปรับแต่ง
- เพิ่ม/แก้ `FIELD_MAP` ใน `analyzer.py` เพื่อ map คอลัมน์อื่นที่คุณมี
- ปรับกฎใน `heuristic_analysis()` ให้เข้ากับ Use Case/Environment ของคุณ
- เปลี่ยนโมเดล OpenAI ใน `llm_analysis()` ได้ตามต้องการ

## หมายเหตุ
- หากไม่ได้ตั้งค่า `OPENAI_API_KEY` ระบบจะใช้ Heuristic อัตโนมัติ
- ข้อมูลที่อ่อนไหว: กรุณาดูแลการตั้งค่า key/logs ตามนโยบายองค์กร