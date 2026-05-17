# Other BOTSv1 Write-ups

แหล่งอ้างอิงเพิ่มเติมสำหรับ BOTSv1 — ใช้เทียบคำตอบหรือดูเป็น hint
เวลาที่ติด

หลักให้ใช้ของ chan2git ใน folder นี้ก่อน (`botsv1/`) — รายการข้างล่าง
เป็น **แหล่งสำรอง** มุมมองอื่น และสำหรับ ransomware track โดยเฉพาะ

---

## Main scenario (ครอบคลุมทั้งโจทย์ 60 ข้อ)

### Sabina Aliyeva — Splunk BOTSv1 Writeup

<https://medium.com/@sabinaaliy3va/splunk-botsv1-writeup-47b73a2eadac>

- เขียน step-by-step ตอบทุกข้อ พร้อม SPL
- เริ่มต้นง่าย เหมาะคนที่ยังไม่ชินกับ SPL
- ภาษาอังกฤษเข้าใจง่าย

### Micah S0day — BOTSv1 Walkthrough

<https://micahs0day.github.io/Splunk_BOTSv1(Boss-of-the-SOC)/>

- มี screenshots ทุกขั้นตอน
- เน้นวิธี "think like a SOC analyst" — ทำไมถึงค้นแบบนี้
- จัดทำเป็น static site ดูง่าย ไม่ติด paywall

---

## Ransomware track (โฟกัสเฉพาะส่วน ransomware)

### JBXSec — BOTS Ransomware Challenge

<https://medium.com/@JBXSec/splunk-bots-ransomware-challenge-992ea6a62fc9>

- ลำดับการสืบสวนแบบ analyst จริง
- อธิบายเหตุผลของแต่ละ query
- กระชับ อ่านจบใน 15-20 นาที

### HackerHermanos — BOTSv1 Ransomware

<https://hackerhermanos.com/posts/splunk-bots-v1-ransomware/>

- Deep dive — มี IoCs ครบ (file hashes, IPs, domains)
- ครอบคลุม network + host artifacts ที่เจอ
- มี screenshots + diagram

---

## IoC reference (ใช้ตรวจ hash / IP / domain ที่เจอใน lab)

### SophosLabs — IoCs

<https://github.com/sophoslabs/IoCs>

- คลัง IoCs จากงานวิจัยมัลแวร์ของ SophosLabs (hashes, IPs, domains, YARA)
- ไม่ใช่ write-up — ใช้เทียบ artefact ที่เจอใน BOTS ว่าตรงกับแคมเปญที่
  มีคนรายงานไว้แล้วหรือไม่
- ค้นได้ตรง ๆ ด้วย GitHub search ภายใน repo

---

## วิธีใช้ที่แนะนำ

| สถานการณ์ | เปิดอันไหน |
|---|---|
| เริ่มจากศูนย์ | ลองตอบเองใน Splunk Web ก่อน |
| ติดเกิน 15 นาที | `botsv1/` ของ chan2git (folder นี้) |
| อยากดู approach อื่น | Sabina / Micah |
| โจทย์เกี่ยวกับ ransomware | JBXSec / HackerHermanos |
| เจอ hash / IP / domain แปลก ๆ | SophosLabs IoCs |

> ฝึกแบบทำเองก่อนเปิดเฉลย — ได้ผลมากกว่าการอ่านอย่างเดียวเยอะ
