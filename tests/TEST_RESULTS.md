# WVA 테스트 결과보고서

### 수행 환경과 검증 범위

- 보고서 갱신 시각: 2026-11-03T17:34:20+09:00
- 운영체제: Windows-10-10.0.19045-SP0
- Python: 3.12.14
- 기능 테스트: **99/99 PASS**
- 외부 운영 사이트 진단은 수행하지 않았습니다. 로컬 실습 환경에 대한 검증입니다.

### 기능 테스트 상세 결과

| 실제 테스트 | 결과 | 소요 |
| --- | --- | ---: |
| `test_compute_score_and_grade` | PASS | 0.001초 |
| `test_build_ai_prompt` | PASS | 0.000초 |
| `test_audit_js_secrets_detection` | PASS | 0.002초 |
| `test_consent_validation_in_start_scan` | PASS | 0.012초 |
| `test_surface_measured_metadata_and_openapi` | PASS | 0.542초 |
| `test_persistent_utf8_scan_log_and_rotation` | PASS | 0.830초 |
| `test_selected_export_formats_and_detailed_remediation[json]` | PASS | 0.458초 |
| `test_selected_export_formats_and_detailed_remediation[md]` | PASS | 0.419초 |
| `test_selected_export_formats_and_detailed_remediation[csv]` | PASS | 0.411초 |
| `test_header_remediation_does_not_mix_unrelated_policies[CSP]` | PASS | 0.001초 |
| `test_header_remediation_does_not_mix_unrelated_policies[HSTS]` | PASS | 0.000초 |
| `test_export_selection_validation[sections0-json]` | PASS | 0.005초 |
| `test_export_selection_validation[sections1-json]` | PASS | 0.005초 |
| `test_export_selection_validation[sections2-md]` | PASS | 0.005초 |
| `test_export_selection_validation[sections3-xlsx]` | PASS | 0.005초 |
| `test_export_requires_completed_current_scan_and_full_disk_logs` | PASS | 0.447초 |
| `test_csv_preserves_rows_and_blocks_formulas` | PASS | 0.001초 |
| `test_openapi_discovery_never_executes_declared_operations` | PASS | 0.005초 |
| `test_unfinished_scan_has_no_grade_or_comparison[idle]` | PASS | 0.008초 |
| `test_unfinished_scan_has_no_grade_or_comparison[running]` | PASS | 0.007초 |
| `test_unfinished_scan_has_no_grade_or_comparison[stopped]` | PASS | 0.007초 |
| `test_unfinished_scan_has_no_grade_or_comparison[error]` | PASS | 0.008초 |
| `test_added_rules_preserve_specific_limits_and_ai_context[VULN-SECRET-LEAK-1-INFO_DISCLOSURE-\ubb38\uc790\uc5f4]` | PASS | 0.001초 |
| `test_added_rules_preserve_specific_limits_and_ai_context[VULN-TLS-EXPIRING-1-MISSING_SECURITY_HEADER-\uc778\uc99d\uc11c]` | PASS | 0.001초 |
| `test_baseline_excludes_incomplete_other_scope_and_current_copy` | PASS | 0.014초 |
| `test_actual_repeat_scan_compares_only_same_profile` | PASS | 0.804초 |
| `test_tls_expiry_uses_validated_async_connection_and_closes_writer[14-1]` | PASS | 0.039초 |
| `test_tls_expiry_uses_validated_async_connection_and_closes_writer[60-0]` | PASS | 0.034초 |
| `test_tls_cancel_propagates_instead_of_becoming_success` | PASS | 0.034초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[VULN-CSP-1-MISSING_SECURITY_HEADER]` | PASS | 0.001초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[VULN-HSTS-1-MISSING_SECURITY_HEADER]` | PASS | 0.004초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[debug-EXPOSED_DEBUG_ENDPOINT]` | PASS | 0.001초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[object-BOLA_IDOR]` | PASS | 0.001초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[admin-PRIVILEGE_ESCALATION]` | PASS | 0.001초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[cors-CORS_MISCONFIGURATION]` | PASS | 0.001초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[cookie-COOKIE_SECURITY_FLAG]` | PASS | 0.001초 |
| `test_unknown_type_does_not_invent_an_attack` | PASS | 0.000초 |
| `test_profile_lists_are_not_shared_between_findings` | PASS | 0.000초 |
| `test_security_header_explanations_remain_specific[VULN-CSP-1-\ub124\ud2b8\uc6cc\ud06c \uac00\ub85c\ucc44\uae30]` | PASS | 0.001초 |
| `test_security_header_explanations_remain_specific[VULN-HSTS-1-\uc2a4\ud06c\ub9bd\ud2b8 \uc0bd\uc785]` | PASS | 0.001초 |
| `test_risk_explanation_does_not_change_observed_evidence_or_severity` | PASS | 0.000초 |
| `test_risk_context_survives_selected_and_automatic_reports[json]` | PASS | 0.419초 |
| `test_risk_context_survives_selected_and_automatic_reports[md]` | PASS | 0.423초 |
| `test_risk_context_survives_selected_and_automatic_reports[csv]` | PASS | 0.420초 |
| `test_entry_path_and_query_are_preserved[https://example.com/app/]` | PASS | 0.001초 |
| `test_entry_path_and_query_are_preserved[https://example.com/app/login?next=%2Fapp%2F&lang=ko]` | PASS | 0.000초 |
| `test_entry_path_and_query_are_preserved[http://127.0.0.1:8990?empty=&tag=a&tag=b]` | PASS | 0.000초 |
| `test_entry_path_and_query_are_preserved[https://example.com/api/item?value=tail/]` | PASS | 0.000초 |
| `test_ambiguous_entry_path_cannot_expand_the_scope_to_root[/app/..]` | PASS | 0.000초 |
| `test_ambiguous_entry_path_cannot_expand_the_scope_to_root[/app/%2e%2e/]` | PASS | 0.000초 |
| `test_ambiguous_entry_path_cannot_expand_the_scope_to_root[/app/%252e%252e/]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://example.com/application]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://example.com/private]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://example.com/app/../private]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://example.com/app/%2e%2e/private]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://example.com/app/%252e%252e/private]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://example.com/app/%255c..%255cprivate]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://other.test/app/item]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[http://example.com/app/item]` | PASS | 0.000초 |
| `test_scope_choice_is_explicit_and_query_not_copied_to_other_paths` | PASS | 0.000초 |
| `test_query_variants_are_distinct_but_root_slash_is_not` | PASS | 0.000초 |
| `test_mounted_app_follows_relative_links_and_keeps_actual_boundary` | PASS | 0.402초 |
| `test_direct_query_endpoint_preserves_other_parameters_during_id_check` | PASS | 0.312초 |
| `test_origin_choice_can_probe_root_but_still_requests_the_entry` | PASS | 0.409초 |
| `test_dashboard_accepts_path_query_and_reports_selected_scope` | PASS | 0.409초 |
| `test_same_origin_allowed[https://example.com/]` | PASS | 0.001초 |
| `test_same_origin_allowed[https://example.com:443]` | PASS | 0.000초 |
| `test_outside_origin_blocked[https://sub.example.com]` | PASS | 0.000초 |
| `test_outside_origin_blocked[https://example.com.evil.test]` | PASS | 0.000초 |
| `test_outside_origin_blocked[http://example.com]` | PASS | 0.000초 |
| `test_outside_origin_blocked[https://example.com:444]` | PASS | 0.000초 |
| `test_outside_origin_blocked[https://other.test]` | PASS | 0.000초 |
| `test_outside_origin_blocked[file:///etc/hosts]` | PASS | 0.000초 |
| `test_outside_origin_blocked[https://a:b@example.com]` | PASS | 0.000초 |
| `test_destructive_paths_blocked[/delete-user]` | PASS | 0.000초 |
| `test_destructive_paths_blocked[/%64elete]` | PASS | 0.000초 |
| `test_destructive_paths_blocked[/%2564elete]` | PASS | 0.000초 |
| `test_destructive_paths_blocked[/reset-db]` | PASS | 0.000초 |
| `test_destructive_paths_blocked[/purchase]` | PASS | 0.000초 |
| `test_invalid_target_rejected[example.com]` | PASS | 0.000초 |
| `test_invalid_target_rejected[ftp://example.com]` | PASS | 0.000초 |
| `test_invalid_target_rejected[https://a:b@example.com]` | PASS | 0.000초 |
| `test_invalid_target_rejected[http://localhost:99999]` | PASS | 0.000초 |
| `test_invalid_target_rejected[http://localhost:0]` | PASS | 0.000초 |
| `test_invalid_target_rejected[http://localhost/#section]` | PASS | 0.000초 |
| `test_invalid_target_rejected[http://localhost/%0Aprivate]` | PASS | 0.000초 |
| `test_invalid_target_rejected[http://local host]` | PASS | 0.000초 |
| `test_empty_state_and_report_gate` | PASS | 0.007초 |
| `test_cross_origin_and_form_blocked` | PASS | 0.006초 |
| `test_secure_cookie_is_not_false_positive` | PASS | 0.001초 |
| `test_cors_requires_credentialed_reflection[*-true-0]` | PASS | 0.002초 |
| `test_cors_requires_credentialed_reflection[https://evil-attacker.com-false-0]` | PASS | 0.001초 |
| `test_cors_requires_credentialed_reflection[https://evil-attacker.com-true-1]` | PASS | 0.001초 |
| `test_vulnerable_demo_and_reports` | PASS | 0.461초 |
| `test_direct_target_hardened_profile` | PASS | 0.407초 |
| `test_unreachable_target_is_error` | PASS | 2.060초 |
| `test_duplicate_start_cancel_and_reset` | PASS | 0.013초 |
| `test_events_broadcast_and_replay` | PASS | 0.003초 |
| `test_redirects_do_not_escape_scope` | PASS | 0.543초 |

### 실행파일 독립 실행 결과

- 결과: **PASS**
- 수행 시각: 2026-11-03T17:31:04.984764+09:00
- 실행파일 SHA-256: `5ceba009a5bac69ef3bc0df41e6e999b29fde46d02e9c436fed5269b6b926279`
- 실행파일 크기: 26,160,304 bytes

| 검증 항목 | 결과 | 실제 결과 |
| --- | --- | --- |
| standalone_health | PASS | Copied exe starts from Korean path, no project sources |
| bundled_asset:/ | PASS | {"status": 200, "bytes": 13063} |
| bundled_asset:/static/app.css | PASS | {"status": 200, "bytes": 26659} |
| bundled_asset:/static/app.js | PASS | {"status": 200, "bytes": 28375} |
| bundled_asset:/static/fonts/NotoSansKR.ttf | PASS | {"status": 200, "bytes": 10414588} |
| bundled_asset:/static/fonts/IBMPlexMono-Regular.ttf | PASS | {"status": 200, "bytes": 135580} |
| start_demo | PASS | Embedded lab starts without Python subprocess |
| demo_result | PASS | {"status": "completed", "target_url": "http://127.0.0.1:2869", "endpoints_count": 8, "findings_count": 5, "chains_count": 1, "severity": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 2, "INFO": 0}, "score": 46, "grade": "F", "error": "", "scan_id": "4fb6cee97879", "started_at": "2026-11-03T08:31:07.122406+00:00", "finished_at": "2026-11-03T08:31:07.443353+00:00", "demo": true, "report_paths": ["<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\reports\\20261103_173107_4fb6cee97879.md", "<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\reports\\20261103_173107_4fb6cee97879.json"], "phase": 4, "scope_mode": "path", "log_path": "<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\logs\\scans\\20261103_173107_4fb6cee97879.jsonl", "log_error": "", "app_log_path": "<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\logs\\WVA.log"} |
| report_download | PASS | 5 findings in downloaded JSON |
| report_persistence | PASS | ["<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\reports\\20261103_173107_4fb6cee97879.md", "<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\reports\\20261103_173107_4fb6cee97879.json"] |
| detailed_remediation | PASS | 5 findings include ordered actions, completion criteria and verification |
| integrated_version | PASS | Integrated executable identifies as WVA 2.4.0 |
| risk_and_ai_context | PASS | Conditional risk limits and local AI prompt coexist in all five findings |
| reference_grade | PASS | {"score": 46, "grade": "F"} |
| comparison_metadata | PASS | Completed report records scope and rule version |
| surface_metadata | PASS | {"target_url": "http://127.0.0.1:2869", "methods": {"GET": 8}, "status_codes": {"200": 5, "unmeasured": 1, "422": 1, "403": 1}, "measured_count": 7, "schema_only_count": 1, "auth_response_count": 1, "tech_stack": ["Server: uvicorn"]} |
| persistent_scan_log | PASS | <프로젝트>\tests\artifacts\독립 실행 한글 경로\logs\scans\20261103_173107_4fb6cee97879.jsonl |
| selected_json_export | PASS | Only selected findings/logs plus provenance |
| selected_csv_export | PASS | UTF-8 BOM CSV includes enriched endpoint metadata |
| two_sse_clients | PASS | Independent clients receive identical first event |
| sse_resume | PASS | Last-Event-ID resumes after acknowledged event |
| second_launch_reuses_server | PASS | Second launcher exits; original service stays healthy |
| shutdown_request | PASS | Graceful shutdown accepted with an active SSE subscriber |
| graceful_exit | PASS | 0 |
| port_released | PASS | Service port closed after exit |

### 브라우저 작업 흐름 결과

- 결과: **PASS**
- 수행 시각: 2026-11-03T08:32:10.186Z

| 검증 항목 | 결과 | 실제 결과 |
| --- | --- | --- |
| minimal_copy | PASS | No screen slogan, priority panel, or explanatory count captions |
| consent_validation | PASS | Unchecked permission confirmation prevents diagnosis; checked confirmation allows it |
| running_motion | PASS | Spinner, scanning line and real stages activate; scope is locked |
| completed_reference_grade | PASS | Reference score appears for a completed scan |
| direct_target_scan | PASS | 5 findings, 1 chain, 8 endpoints |
| completion_motion | PASS | Completion check appears and stage labels disappear after completion |
| charts_reconcile | PASS | Pie slices sum to 5; severity 1/1/1/2/0 and CVSS bins 1/1/2/1 |
| expanded_finding_table | PASS | Severity, finding/CWE, method/path, CVSS, evidence, remediation summary |
| finding_filters | PASS | Search empty state and HIGH-only filter |
| risk_detail_readability | PASS | Korean explanation and limits precede conditional attacks; raw evidence folds; six actions expand together |
| ai_prompt_with_risk_details | PASS | Collapsed AI prompt copies locally; observation, conditional attacks and ordered actions remain available |
| shared_detail_dialog | PASS | 75% workspace width, 75vh height, six ordered actions with completion criteria, native focus and Escape |
| attack_conditions_not_exploit_claims | PASS | CSP displays the separate XSS prerequisite and no execution claim; raw evidence remains available |
| chain_dialog_stays_on_route | PASS | Three steps, three related findings, detail opens without route change |
| surface_metadata | PASS | 7 measured, 1 unmeasured; parameters, HTTP, timing, bytes, headers and source |
| log_storage_paths | PASS | Per-scan JSONL and app error-log locations are visible |
| save_selection_gate | PASS | Five information descriptions; empty selection disables save |
| selected_json_download | PASS | Only selected findings and full disk logs plus provenance |
| selected_markdown_download | PASS | Selected summary and findings, detailed remediation included |
| selected_csv_download | PASS | UTF-8 BOM CSV with response metadata and selected endpoints |
| responsive_1440 | PASS | Charts, contained table scrolling, and dialog stay within viewport |
| responsive_768 | PASS | Charts, contained table scrolling, and dialog stay within viewport |
| mobile_risk_readability | PASS | 390px explanation, attack conditions and action controls fit the dialog at readable sizes |
| responsive_390 | PASS | Charts, contained table scrolling, and dialog stay within viewport |
| mobile_save_layout | PASS | Choices and save controls remain visible without page overflow |
| reload_restores_results | PASS | Counts and charts restore after refresh |
| reduced_motion | PASS | System motion preference disables scan/check animations |
| path_scope_network_boundary | PASS | Entry query preserved; every actual target request remains under /app/ |
| relative_links_and_query_variants | PASS | Nested relative links are measured; query variants remain separate |
| scoped_finding_request_url | PASS | Detail shows the actual request URL, without duplicated base path or query |
| scope_mobile_layout | PASS | URL and scope controls fit 390px without document overflow |
| direct_query_and_reload | PASS | Direct query is diagnosed, unrelated repeated parameters and restored input are preserved |
| origin_scope_choice | PASS | Same-server choice includes root probes while retaining entry URL |
| repeat_scan_comparison | PASS | Same target and scope show persistent findings; missing findings are not claimed as remediated |
| stage_labels_terminal_states | PASS | Stage labels disappear on stopped and failed scans as well as completed scans |
| offline_assets | PASS | Zero external requests and zero JavaScript exceptions |

### 디자인 보조 검사

- 테이스트스킬 브라우저 검사: 0 FAIL, 2 WARN.
- 1440px: 페이지 가로 넘침 0px, JavaScript 예외 0개.
- 768px: 페이지 가로 넘침 0px, JavaScript 예외 0개.
- 390px: 페이지 가로 넘침 0px, JavaScript 예외 0개.
- WARN `rainbow-chart`: The charts use 5 different hues.
- WARN `tiny-text`: 78% of the text is under 13px.
- 소스 lint: 0 FAIL, 2 WARN. 숫자·URL의 고정폭 글꼴과 미측정 값의 대시 표시는 데이터 표현에 사용합니다.
- Impeccable detect: 보조 발견 2건. 진단 중 진행선 모션은 요청된 기능이며 완료 후 멈춥니다.
  - warning: Auto-scrolling marquee
  - advisory: Em-dash overuse
- 실제 데스크톱·모바일 화면과 큰 상세 창, 저장 화면의 스크린샷을 직접 확인했습니다.

### 화면 및 산출물

- [데스크톱 화면](../docs/images/dashboard.png)
- 태블릿 화면: `artifacts/browser/results-768.png` (로컬 검증 산출물)
- 모바일 화면: `artifacts/browser/results-390.png` (로컬 검증 산출물)
- 경로 화면: `artifacts/browser/chains-desktop.png` (로컬 검증 산출물)
- [순서별 조치 화면](../docs/images/actions.png)
- 공격 표면: `artifacts/browser/surface-desktop.png` (로컬 검증 산출물)
- 로그 위치: `artifacts/browser/logs-desktop.png` (로컬 검증 산출물)
- 저장 화면: `artifacts/browser/save-desktop.png` (로컬 검증 산출물)
- 기능 검증 원본: `artifacts/pytest.xml`, `artifacts/pytest-output.txt`
- 실행파일 검증 원본: `artifacts/executable-smoke.json`
- 브라우저 검증 원본: `artifacts/browser/result.json`

### 제한과 미실행 항목

- Windows 10 x64 한 대에서 확인했습니다. 별도 Windows 11 PC·백신 제품별 실행은 NOT_RUN입니다.
- 실제 외부 사이트, 로그인 세션을 가진 다중 사용자 권한 대조, 전체 URL 크롤링, 모든 OWASP 항목은 NOT_RUN입니다.
- 진단 데이터는 세션 메모리에 있으며 완료 보고서와 개별 JSONL 진단 로그는 파일로 보존됩니다. 앱 재실행 시 화면 히스토리를 복원하지 않습니다.
- 수집한 API 키와 식별자가 보고서에 포함될 수 있습니다. 테스트 값과 실제 진단 증거를 구분하여 관리합니다.
