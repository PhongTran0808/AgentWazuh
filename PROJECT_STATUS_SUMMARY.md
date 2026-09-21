# AgentWazuh Project Status Summary

## Mục đích tài liệu

Tài liệu này tóm tắt đề cương ban đầu và hiện trạng codebase AgentWazuh tại ngày 20/09/2026. Nó được lập từ việc đọc file đề cương `.docx`, rà soát mã nguồn, test, giao diện và tài liệu trong repository. Đây là bản ghi hiện trạng để nhóm dùng làm mốc chung; các nhận định về Wazuh thật, LLM thật hoặc hiệu năng production vẫn cần được xác nhận bằng một Lab SOC đang chạy.

## 1. Ý tưởng ban đầu

Đề cương đặt mục tiêu xây dựng một SOC co-pilot cho Wazuh, tập trung vào:

- lấy alert/log thật từ Wazuh;
- deduplication và tương quan chuỗi sự kiện thành incident có ngữ cảnh;
- tính Risk Score, ánh xạ MITRE ATT&CK và hỗ trợ điều tra bằng ngôn ngữ tự nhiên;
- cung cấp Web UI gồm Dashboard, Triage Chat, Inventory, Topology và Log Drilldown;
- mở rộng bằng MCP, AI Agent và LangGraph HITL để đề xuất rule/case/response nhưng phải có người phê duyệt;
- đánh giá bằng các kịch bản tấn công, alert fatigue, độ chính xác tương quan, MTTR và mức an toàn của HITL.

Theo lịch trong đề cương, ngày 20/09/2026 đang nằm trong Tuần 5–7: hoàn thiện Correlation Engine và Risk Score. Tuy nhiên code hiện tại đã có nhiều thành phần thuộc các tuần sau, nên trạng thái thực tế không còn khớp hoàn toàn với kế hoạch tuần.

## 2. Kiến trúc hiện có

Luồng chính hiện thấy trong repository là:

```text
Web UI
  -> FastAPI core/server.py
  -> WazuhClient / SoLPi evidence / Correlation Engine
  -> MCP tools, LangGraph form workflow, Incident Assistant
  -> Wazuh REST API hoặc Dashboard/OpenSearch proxy
```

Các khối chính:

| Khối | Thành phần | Nhận xét hiện trạng |
|---|---|---|
| Backend | `core/server.py` | Nhiều route đã tích hợp, có session auth, cache, settings, chat, investigation, rule workflow. Đây là file rất lớn và đang gánh quá nhiều trách nhiệm. |
| Wazuh connector | `services/wazuh_client.py` | Có JWT cache, retry khi 401, fallback Dashboard/OpenSearch và ghi nhật ký API đã che JWT. Chưa có kiểm thử integration với Wazuh thật trong lần rà soát này. |
| Correlation | `services/correlation_engine.py` | Có dedup, gom nhóm theo entity/time window, NetworkX graph, TF-IDF similarity, risk/priority và dry-run rule. Cần bộ dữ liệu chuẩn để chứng minh chất lượng, không chỉ chứng minh code chạy. |
| AI investigation | `services/incident_assistant.py` | Có thể gọi provider/PI CLI và tạo context điều tra. Cần kiểm soát quota, timeout, prompt size và kiểm chứng grounding với dữ liệu thật. |
| MCP | `mcp_layer/wazuh_mcp.py`, `mcp_layer/correlation_mcp.py` | Có các tool lấy agent, alert, manager status, correlated events, tạo case và sinh grid UI. Một số tool vẫn mặc định credential/yếu tố TLS theo hướng phù hợp Lab hơn production. |
| HITL | `langgraph_engine/graphs/config_form_graph.py`, các route rule trong `core/server.py` | Có form/draft/dry-run/pending rule. Việc “apply” hiện chủ yếu ghi vào `config/pending_rules/`; chưa phải cơ chế triển khai rule an toàn lên Wazuh Manager thật. |
| Frontend | `web/*.html`, `web/*.js`, `web/*.css` | Có dashboard, chat, drilldown, inventory, topology, API inspector và settings drawer. UI có design token và empty state; cần kiểm thử browser với backend/Wazuh online để xác nhận các luồng tương tác. |

## 3. Ma trận tính năng so với đề cương

| Tính năng | Trạng thái | Bằng chứng / khoảng trống |
|---|---|---|
| Kết nối Wazuh API | 🟡 Có nhưng chưa chứng minh integration | Connector, auth JWT, fallback đã có; chưa có test hợp đồng với phiên bản Wazuh mục tiêu. |
| Lấy alert thật | 🟡 Có | Có polling, webhook và import; import từ client vẫn là nguồn dữ liệu có thể làm bẩn cache nếu không siết schema/provenance. |
| Deduplication | 🟢 Có ở mức prototype | Có fingerprint theo rule/src/dst/device và occurrence/evidence IDs; cần test collision, timezone, dữ liệu thiếu field và tải lớn. |
| Correlation incident | 🟡 Có nhưng cần hiệu chỉnh | Có graph/entity/time/TF-IDF; tiêu chí similarity còn khá thô, có nguy cơ nối các alert không cùng incident hoặc tách chuỗi attack thực sự. |
| Risk Score / priority | 🟡 Có | Có hàm score và badge thiết bị; cần tài liệu hóa công thức, calibration với ground truth và chứng minh giảm alert fatigue. |
| MITRE ATT&CK | 🟡 Một phần | Có `config/mitre_mapping.json` và context giải thích; chưa thấy quy trình đánh giá độ đúng của mapping trên dataset. |
| AI Incident Assistant | 🟡 Có nhưng phụ thuộc môi trường | Có provider/PI subprocess và SoLPi evidence receipt; cần giới hạn token, rate limit, timeout, retry và test khi provider lỗi. |
| MCP tools | 🟡 Có | Có tool truy xuất và tạo case; cần chuẩn hóa schema lỗi, auth, TLS và quyền read/write. |
| LangGraph HITL | 🟡 Prototype | Có state graph và trạng thái awaiting approval; graph chưa thể hiện checkpoint/resume đầy đủ cho quy trình production. |
| Dry-run rule | 🟡 Có nhưng phạm vi hạn chế | `dry_run_rule()` chạy trên alert lịch sử cục bộ; đây không thay thế Wazuh `wazuh-logtest`/kiểm thử rule chính thức. |
| Apply rule an toàn | 🔴 Chưa đạt mục tiêu production | Route ghi pending rule và trả trạng thái thành công ở UI; chưa deploy/reload Manager thật. UI còn hiển thị “đã áp dụng vào Wazuh Manager”, dễ gây hiểu nhầm. |
| Case TheHive/Jira/Webhook | 🟡 Có khung tích hợp | Có `case_manager.py`, nhưng cần test với endpoint thật, retry/idempotency và audit approval. |
| E2E và đánh giá khoa học | 🔴 Chưa đủ bằng chứng | Có test code, nhưng chưa có kết quả hiện tại đáng tin cậy cho Wazuh online, attack scenarios, precision/recall, MTTR hoặc alert-fatigue reduction. |

## 4. Kết quả kiểm tra hiện tại

- `compileall` cho các package Python chính: **PASS**.
- `tests/test_correlation_engine.py`: **2 passed**.
- Bộ test tích hợp dùng `TestClient` bị treo quá 20 giây tại bước login/kết nối tới IP Lab hard-code `172.16.175.145`; vì vậy không thể xác nhận tuyên bố cũ “21/21 passed” trong `baocaoquet.md` bằng môi trường hiện tại.
- `git status` đang có thay đổi ở `config/sessions.json`; đây là dữ liệu runtime không nên đưa vào commit.
- Repository lớn khoảng 599 MB, chủ yếu do `node_modules`, cache và virtual environment. Với một project nộp/bàn giao, cần tách runtime khỏi source hoặc loại khỏi Git.

## 5. Vấn đề cần ưu tiên

### Mức nghiêm trọng cao

1. **Dữ liệu nhạy cảm vẫn đang tracked trong Git.** `git ls-files` hiện còn thấy `config/vault_master.key`, `config/device_vault.enc`, `config/sessions.json`, `config/system_settings.json`, `config/admin_auth.json`, các file chat session và pending rules. `.gitignore` không có tác dụng với file đã tracked. Cần rotate credential/key trước khi public hoặc gửi repository, sau đó untrack dữ liệu runtime bằng một quy trình Git có kiểm soát.
2. **Credential mặc định/yếu còn xuất hiện trong code/UI path.** Ví dụ `uptime_kuma_push_token` có giá trị mặc định cố định; nhiều fallback là `wazuh/wazuh` hoặc `admin/admin`. Đây chỉ nên tồn tại trong fixture Lab rõ ràng, không nên là fallback runtime.
3. **TLS verification mặc định đang tắt cho Lab.** `WAZUH_VERIFY_SSL` và các connector liên quan cho phép `false`. Nếu dùng ngoài Lab, đây là rủi ro MITM và lộ credential.
4. **Đường đi “apply rule” dễ gây hiểu sai.** Backend có thể chỉ ghi file pending, trong khi UI nói đã áp dụng/thậm chí khởi động lại Wazuh. Phải đổi wording thành “đã tạo bản nháp/chờ áp dụng thủ công” hoặc triển khai một pipeline deploy có xác nhận và rollback thật.

### Mức trung bình

1. `core/server.py` quá lớn, trộn route, persistence, auth, background polling, scoring và business logic; khó test và khó chứng minh boundary an toàn.
2. `GLOBAL_ALERTS_CACHE` là bộ nhớ tiến trình: restart mất dữ liệu, chạy nhiều worker sẽ không đồng bộ. Nên dùng SQLite/PostgreSQL hoặc ít nhất một repository layer có schema.
3. Correlation hiện dùng connected components và TF-IDF threshold cố định `0.65`; cần benchmark trên dữ liệu có nhãn, tránh biến “gần giống câu chữ” thành cùng incident.
4. Chưa có rate limit/quota rõ ràng cho endpoint correlation/investigation gọi LLM hoặc OpenSearch.
5. Test phụ thuộc mạng/IP cụ thể và login thật ngay khi import module, khiến test treo khi Wazuh offline. Cần dependency injection, mock connector ở unit test và test integration riêng có marker.
6. Environment được đọc ở nhiều nơi và settings có thể đồng bộ ngược ra `pass.env`; nên gom cấu hình vào một module, không ghi password plaintext ra file.

### Giao diện và trải nghiệm

- Bố cục nhìn từ HTML/CSS có hệ thống khá rõ: dark SOC shell, dashboard/chat, drilldown, inventory, topology và API inspector.
- Empty state có thông báo “0 Real Alerts” và “log giả lập đã được gỡ bỏ”, phù hợp nguyên tắc không bịa dữ liệu.
- Có điểm không nhất quán: nút UI nói “Phê duyệt & Áp dụng lên Wazuh Manager” và sau đó “đã áp dụng thành công”, trong khi backend chỉ tạo pending rule. Đây là lỗi nghiệp vụ/UI quan trọng hơn lỗi thẩm mỹ.
- Dashboard poll 3 giây cho status và các polling khác 5–15 giây có thể tạo nhiều request khi nhiều tab mở. Nên có backoff khi offline, pause khi tab ẩn và hiển thị thời điểm dữ liệu cuối cùng.
- Frontend tải Google Fonts, Font Awesome và nhiều thư viện CDN. Trong Lab offline hoặc môi trường bảo vệ, giao diện có thể mất icon/font; nên pin hoặc bundle dependency quan trọng.
- Chưa thực hiện visual browser QA trong lần rà soát này; cần chạy các màn hình với backend mock/Wazuh online để kiểm tra responsive, lỗi 401, loading và empty state thật.

## 6. Tối ưu kiến trúc đề xuất

Ưu tiên làm một “vertical slice” có thể đo được:

1. Wazuh alert thật → normalize schema → dedup → correlation → risk score → dashboard/drilldown.
2. Chỉ đưa incident summary, evidence IDs, top alerts và số liệu đã tính vào LLM; không đưa hàng trăm raw alert nếu Python đã lọc được.
3. Lưu incident/evidence bằng schema ổn định, có `source`, `ingested_at`, `event_id`, `first_seen`, `last_seen`, `confidence`, `correlation_reasons` và hash evidence.
4. Tách 3 loại test: unit không mạng, contract test connector, E2E có Wazuh Lab. Không để unit test gọi IP thật.
5. Tách `core/server.py` thành router/auth/config/background/jobs/repository; giữ route mỏng.
6. Chỉ triển khai HITL sau khi có trạng thái bền vững: draft → dry-run result → approval identity/time → pending artifact → explicit deploy → verification → rollback.

## 7. Kế hoạch ngắn hạn đề xuất

| Ưu tiên | Việc cần làm | Tiêu chí hoàn thành |
|---|---|---|
| P0 | Gỡ/rotate secret và dữ liệu runtime khỏi Git | `git ls-files` không còn key/session/password/chat runtime; secret mới đã được rotate. |
| P0 | Sửa wording và semantics của apply rule | UI/backend phân biệt rõ draft, approved, deployed, verified; không báo thành công giả. |
| P0 | Làm test chạy offline | Không test nào gọi IP thật khi chạy mặc định; full unit suite hoàn thành trong thời gian hữu hạn. |
| P1 | Chuẩn hóa config và TLS | Một nguồn config, không ghi password ra `pass.env`, TLS production mặc định bật. |
| P1 | Chốt schema và benchmark correlation | Có dataset mẫu, expected incidents, precision/recall và phân tích false merge/false split. |
| P1 | Đo hiệu năng/alert fatigue | So sánh trước/sau dedup-correlation: số alert, số incident, tỷ lệ giảm, latency, MTTR proxy. |
| P2 | Browser QA và polish UI | Có checklist cho 5 màn hình, offline/online/401/empty/loading/responsive. |
| P2 | Tách module backend | Route/business/persistence/background tách riêng, test dễ và ít side effect import. |

## Kết luận

Chủ đề phù hợp cho một tiểu luận/prototype An toàn thông tin vì có bài toán thực tế, có dữ liệu Wazuh, có pipeline tương quan và có điểm nhấn HITL. Codebase hiện đã vượt qua giai đoạn ý tưởng: có backend, connector, correlation, MCP, AI assistant và UI tương đối đầy đủ. Tuy nhiên chưa nên mô tả là hệ thống SOC tự động vận hành hoàn chỉnh. Trọng tâm cần thu hẹp và chứng minh được là **correlation + prioritization trên alert thật**, sau đó mới trình bày AI/HITL như lớp hỗ trợ có kiểm soát. Ba rủi ro phải xử lý trước khi demo hoặc nộp báo cáo là secret trong Git, semantics “apply rule” không đúng thực tế và bộ test tích hợp phụ thuộc Wazuh/IP thật.

## 8. Nâng cấp đã thực hiện sau đợt rà soát

- Thêm `ai/gemini_analyzer.py` làm adapter Gemini riêng, chỉ nhận incident group đã được Python xử lý.
- Tái sử dụng pipeline `deduplication → correlation → risk scoring` trong `core/server.py` qua `build_correlated_groups()`.
- Thêm `POST /api/wazuh/incidents/analyze` để Analyst chọn một incident và yêu cầu Gemini phân tích có kiểm soát.
- Thêm nút `Phân tích Gemini` trên danh sách Incident Group; không tự gọi Gemini theo chu kỳ polling của Dashboard.
- Khi thiếu API key hoặc Gemini lỗi, hệ thống trả trạng thái `unavailable/error` rõ ràng, không tự bịa kết quả AI.
- Thêm 3 test offline cho việc parse JSON từ Gemini và xử lý trường hợp thiếu key. Tổng kiểm tra offline liên quan: **5 passed**; compile Python: **PASS**.

Luồng mục tiêu hiện tại là:

```text
Wazuh → Python dedup/correlation/risk → Incident Group → Gemini → Dashboard/SOC Analyst
```

## 9. Nâng cấp chat AI

- Thêm `services/chat_intent.py` để phân loại câu hỏi thành greeting, how-to, metrics, investigation, rule configuration, Wazuh explanation hoặc general.
- Thêm `.pi/knowledge/wazuh_domain.md` làm knowledge pack cho các khái niệm Wazuh, alert schema, correlation và cách hướng dẫn thao tác.
- Prompt yêu cầu chọn format theo câu hỏi: giải thích khái niệm, quy trình từng bước, SOC briefing, bảng/chart, Mermaid hoặc HITL form.
- Fallback local không còn dùng IP/agent/alert minh họa như dữ liệu thật; khi thiếu evidence, chat nói rõ giới hạn và yêu cầu dữ liệu bổ sung.
- Không thể cam kết AI “hiểu 100% Wazuh”. Kiến thức nền có thể mở rộng, nhưng trạng thái thực tế và thao tác phải dựa trên API/tool tương ứng.
