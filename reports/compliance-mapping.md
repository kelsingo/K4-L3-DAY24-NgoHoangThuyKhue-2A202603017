# Compliance mapping — điền trong checkpoint 5

| Nguồn / yêu cầu | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| Luật 91/2025/QH15, Điều 7 khoản 7: nghiêm cấm chiếm đoạt, cố ý làm lộ hoặc làm mất dữ liệu cá nhân | PII detect/redact; phân loại `restricted`; deny `restricted + egress`; prove sink rỗng | `agent/pii.py:72`, `agent/pii.py:88`, `agent/policy.py:60`, `agent/runner.py:226`, `reports/attack-after.log` (0 byte) | Dữ liệu lab là synthetic; control kỹ thuật này không tự chứng minh căn cứ xử lý, sự đồng ý hoặc tuân thủ pháp lý production. |
| NĐ 356/2025/NĐ-CP, Điều 19 khoản 1-4: lập/lưu hồ sơ đánh giá tác động xử lý, mô tả mục đích, loại dữ liệu, luồng xử lý, biện pháp an toàn và rủi ro | DPIA-lite mô tả dữ liệu, purpose/principal, luồng Run A/Run B, endpoint, deny/allow và giới hạn | `reports/dpia-lite.md:3`, `agent/runner.py:147`, `agent/runner.py:184`, `agent/runner.py:193` | `dpia-lite.md` chỉ là bài tập rút gọn, không phải Hồ sơ/Mẫu số 10, không được nộp cho cơ quan chuyên trách và không thay thế nghĩa vụ pháp lý thực tế. |
| Luật AI 134/2025/QH15, Điều 4 khoản 3: minh bạch và trách nhiệm giải trình về quyết định/hệ quả của hệ thống AI | Mọi tool decision có reason, identity/run/TTL và hash chain; policy được kiểm trước tool | `agent/runner.py:86`, `agent/runner.py:108`, `agent/ledger.py:53`, `agent/ledger.py:76` | Chưa phân loại mức rủi ro pháp lý cho một hệ thống production; `--mock` và ledger cục bộ chỉ tạo evidence kỹ thuật trong lab. |
| OWASP Agentic Top 10: ASI01 Agent Goal Hijack, ASI03 Identity & Privilege Abuse, ASI04 Agentic Supply Chain Vulnerabilities | ASI01: 4 lure + split/PEP; ASI03: principal/scope/parent-scope/TTL; ASI04: lock có hash, hook Gitleaks pin và incident note | `tests/test_injection.py:69`, `tests/test_split.py:75`, `tests/test_obo.py:29`, `.pre-commit-config.yaml:1`, `reports/secrets-incident.md:3` | Mapping theo threat category, không phải chứng nhận OWASP; mock không bao phủ model/tool/supply chain production. |

Chỉ ghi điều khoản cụ thể khi đã đối chiếu văn bản gốc. Mô phỏng kỹ thuật không tự chứng minh tuân thủ pháp luật.

## Nguồn chính thức đã đối chiếu

- [Luật Bảo vệ dữ liệu cá nhân 91/2025/QH15](https://congbao.chinhphu.vn/van-ban/luat-so-91-2025-qh15-45578.htm), Công báo điện tử Chính phủ.
- [Nghị định 356/2025/NĐ-CP](https://congbao.chinhphu.vn/van-ban/nghi-dinh-so-356-2025-nd-cp-468371.htm), Công báo điện tử Chính phủ.
- [Luật Trí tuệ nhân tạo 134/2025/QH15](https://congbao.chinhphu.vn/van-ban/luat-so-134-2025-qh15-468694.htm), Công báo điện tử Chính phủ.
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/download/52117/), OWASP GenAI Security Project.
