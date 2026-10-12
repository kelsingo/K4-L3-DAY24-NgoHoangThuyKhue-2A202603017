# Baseline — điền trong checkpoint 1

1. **Agent chưa có identity riêng cho mỗi run.** `agent/loop.py:27-54`, hàm
   `_naive_loop()`, không tạo `agent_id` hay `run_id` và cũng không nhận
   `principal_id`. Dù `run_once()` nhận `principal_id`, khi runner còn là scaffold
   thì nhánh fallback ở `agent/loop.py:70-74` gọi `_naive_loop(message, llm)` mà
   không chuyển identity vào baseline.

2. **Không có policy hay principal nào cho phép `http_post`.** Sau khi nội dung
   không tin cậy được `llm.find_injection()` nhận diện, `_naive_loop()` đọc customer
   rồi gọi thẳng `tools.http_post(...)` tại `agent/loop.py:34-44`; quyết định gửi
   thực tế đến từ chỉ thị injection. `agent/tools.py:68-85`, hàm `http_post()`, chỉ
   kiểm tra đích là `127.0.0.1:10024`; allowlist localhost này là giới hạn an toàn
   của lab, không phải kiểm tra authorization hay purpose.

3. **Bằng chứng là request được sink ghi vào `reports/sink.log`.**
   `sink/sink.py:40-47`, `make_handler().Handler.do_POST()`, đọc request body rồi
   append một dòng JSON gồm `path` và `body` vào log. Sau khi replay baseline, bản
   evidence cần nộp là `reports/attack-before.log`, được copy từ `reports/sink.log`;
   nó phải chứa record synthetic của `KH-000999`.
