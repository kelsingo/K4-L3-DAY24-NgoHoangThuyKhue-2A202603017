# DPIA-lite — điền trong checkpoint 5

1. **Loại dữ liệu và phân loại:** Lab chỉ dùng fixture synthetic trong
   `corpus/` và `data/`: họ tên, CCCD, số điện thoại, số tài khoản ngân
   hàng, email, customer ID và ticket liên quan. Nội dung ticket là
   `internal`; record khách hàng chứa CCCD/STK được coi là `restricted`.
   Không sử dụng credential hoặc PII thật.

2. **Mục đích xử lý và principal:** `summarize-tickets` cho tìm kiếm/tóm
   tắt ticket và `support-reply` cho việc đọc record gắn với ticket hợp lệ.
   `support_l1` chỉ được `search_docs`, không được `read_customer`; `dpo`
   được đọc record hợp lệ cho `support-reply`. `--as` chỉ chọn principal mô
   phỏng từ `data/principals.json`, không xác thực danh tính production.

3. **Luồng dữ liệu, run/tool và nơi đi:** Run A gọi `search_docs` và đọc
   corpus không tin cậy, nhưng không đọc private store hay gọi network. Chỉ
   `list[int]` ticket ID trích từ tên file đi sang Run B; prose và customer
   ID do attacker chèn không vượt boundary. Run B map ticket ID qua
   `related_tickets`, kiểm policy ngay trước `read_customer`, và không có
   egress. Injection yêu cầu gửi tới sink lab
   `http://127.0.0.1:10024/reconcile`; PEP đánh dấu dữ liệu `restricted`,
   kiểm `http_post` với `egress_enabled=True` và deny trước khi tool chạy.
   Ledger chỉ giữ `args_hash`, không ghi raw PII.

4. **Bằng chứng deny/allow và rủi ro còn lại:** `python -m pytest tests/ -q`
   pass 33 test; `tests/test_injection.py` pass 4 biến thể x 2 principal;
   `tests/test_split.py` chứng minh không đọc `KH-000777` từ free text nhưng
   vẫn đọc được customer hợp lệ; `tests/test_obo.py` chứng minh support deny,
   DPO allow và không mở rộng parent scope. Replay thủ công dưới `dpo` tạo
   `reports/attack-after.log` 0 byte. `reports/ledger.jsonl` verify `True`
   và có `http_post=deny` với reason, `on_behalf_of=dpo`, run ID và TTL.
   Giới hạn: mock deterministic không đại diện đầy đủ model thật; principal
   là fixture chứ không phải authentication; sink chỉ là localhost; regex có
   thể không bao phủ mọi PII production; hash chain không phát hiện cắt dòng
   cuối hoặc viết lại toàn chuỗi nếu thiếu trusted external anchor. Đây là
   DPIA-lite học tập, không phải kết luận hoặc hồ sơ tuân thủ pháp luật.
