# WVA 테스트 결과보고서

### 수행 환경과 검증 범위

- 보고서 갱신 시각: 2026-11-04T09:06:11+09:00
- 운영체제: Windows-10-10.0.19045-SP0
- Python: 3.12.14
- 기능 테스트: **123/123 PASS**
- 외부 운영 사이트 진단은 수행하지 않았습니다. 로컬 실습 환경에 대한 검증입니다.

### 기능 테스트 상세 결과

| 실제 테스트 | 결과 | 소요 |
| --- | --- | ---: |
| `test_sql_actual_sqlite_and_negative_conditions[sql-True-FINDING]` | PASS | 1.710초 |
| `test_sql_actual_sqlite_and_negative_conditions[safe-sql-False-PASS]` | PASS | 1.577초 |
| `test_sql_actual_sqlite_and_negative_conditions[unstable-False-SIGNAL]` | PASS | 1.351초 |
| `test_sql_actual_sqlite_and_negative_conditions[waf-False-ERROR]` | PASS | 1.137초 |
| `test_sql_actual_sqlite_and_negative_conditions[db-error-False-SIGNAL]` | PASS | 1.961초 |
| `test_browser_execution_encoding_csp_and_dom[reflected-True]` | PASS | 3.406초 |
| `test_browser_execution_encoding_csp_and_dom[safe-reflected-False]` | PASS | 4.798초 |
| `test_browser_execution_encoding_csp_and_dom[csp-reflected-False]` | PASS | 4.650초 |
| `test_browser_execution_encoding_csp_and_dom[spa/#/search?q=baseline-True]` | PASS | 3.680초 |
| `test_browser_enforces_external_path_post_and_websocket_boundaries` | PASS | 3.340초 |
| `test_response_and_request_caps_are_actual_boundaries` | PASS | 0.236초 |
| `test_csrf_get_refresh_preserves_unrelated_repeated_query` | PASS | 0.237초 |
| `test_real_login_csrf_and_private_object_role_policy` | PASS | 1.912초 |
| `test_stored_xss_separate_read_and_verified_cleanup[False]` | PASS | 2.609초 |
| `test_stored_xss_separate_read_and_verified_cleanup[True]` | PASS | 2.556초 |
| `test_timing_uses_real_sqlite_conditional_delay` | PASS | 2.366초 |
| `test_partial_check_does_not_receive_a_grade[R11-NOT_RUN]` | PASS | 0.012초 |
| `test_partial_check_does_not_receive_a_grade[R09-ERROR]` | PASS | 0.005초 |
| `test_extended_probes_reject_external_targets_without_post` | PASS | 1.078초 |
| `test_missing_browser_is_not_run_instead_of_a_pass` | PASS | 1.225초 |
| `test_cancel_stored_check_still_removes_owned_record` | PASS | 1.589초 |
| `test_primary_session_is_used_for_normal_scan` | PASS | 0.994초 |
| `test_validation_does_not_echo_profile_secrets` | PASS | 0.005초 |
| `test_session_rescan_uses_the_same_redacted_comparison_profile` | PASS | 2.283초 |
| `test_compute_score_and_grade` | PASS | 0.000초 |
| `test_build_ai_prompt` | PASS | 0.000초 |
| `test_audit_js_secrets_detection` | PASS | 0.001초 |
| `test_consent_validation_in_start_scan` | PASS | 0.004초 |
| `test_surface_measured_metadata_and_openapi` | PASS | 1.485초 |
| `test_persistent_utf8_scan_log_and_rotation` | PASS | 3.014초 |
| `test_selected_export_formats_and_detailed_remediation[json]` | PASS | 1.631초 |
| `test_selected_export_formats_and_detailed_remediation[md]` | PASS | 1.631초 |
| `test_selected_export_formats_and_detailed_remediation[csv]` | PASS | 2.025초 |
| `test_header_remediation_does_not_mix_unrelated_policies[CSP]` | PASS | 0.001초 |
| `test_header_remediation_does_not_mix_unrelated_policies[HSTS]` | PASS | 0.001초 |
| `test_export_selection_validation[sections0-json]` | PASS | 0.005초 |
| `test_export_selection_validation[sections1-json]` | PASS | 0.005초 |
| `test_export_selection_validation[sections2-md]` | PASS | 0.008초 |
| `test_export_selection_validation[sections3-xlsx]` | PASS | 0.005초 |
| `test_export_requires_completed_current_scan_and_full_disk_logs` | PASS | 1.683초 |
| `test_csv_preserves_rows_and_blocks_formulas` | PASS | 0.001초 |
| `test_openapi_discovery_never_executes_declared_operations` | PASS | 0.005초 |
| `test_unfinished_scan_has_no_grade_or_comparison[idle]` | PASS | 0.009초 |
| `test_unfinished_scan_has_no_grade_or_comparison[running]` | PASS | 0.008초 |
| `test_unfinished_scan_has_no_grade_or_comparison[stopped]` | PASS | 0.008초 |
| `test_unfinished_scan_has_no_grade_or_comparison[error]` | PASS | 0.009초 |
| `test_added_rules_preserve_specific_limits_and_ai_context[VULN-SECRET-LEAK-1-INFO_DISCLOSURE-\ubb38\uc790\uc5f4]` | PASS | 0.001초 |
| `test_added_rules_preserve_specific_limits_and_ai_context[VULN-TLS-EXPIRING-1-MISSING_SECURITY_HEADER-\uc778\uc99d\uc11c]` | PASS | 0.001초 |
| `test_baseline_excludes_incomplete_other_scope_and_current_copy` | PASS | 0.033초 |
| `test_actual_repeat_scan_compares_only_same_profile` | PASS | 10.933초 |
| `test_tls_expiry_uses_validated_async_connection_and_closes_writer[14-1]` | PASS | 0.040초 |
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
| `test_risk_context_survives_selected_and_automatic_reports[json]` | PASS | 1.561초 |
| `test_risk_context_survives_selected_and_automatic_reports[md]` | PASS | 1.387초 |
| `test_risk_context_survives_selected_and_automatic_reports[csv]` | PASS | 1.290초 |
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
| `test_mounted_app_follows_relative_links_and_keeps_actual_boundary` | PASS | 3.470초 |
| `test_direct_query_endpoint_preserves_other_parameters_during_id_check` | PASS | 1.369초 |
| `test_origin_choice_can_probe_root_but_still_requests_the_entry` | PASS | 3.899초 |
| `test_dashboard_accepts_path_query_and_reports_selected_scope` | PASS | 3.476초 |
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
| `test_destructive_paths_blocked[/purchase]` | PASS | 0.001초 |
| `test_invalid_target_rejected[example.com]` | PASS | 0.001초 |
| `test_invalid_target_rejected[ftp://example.com]` | PASS | 0.001초 |
| `test_invalid_target_rejected[https://a:b@example.com]` | PASS | 0.000초 |
| `test_invalid_target_rejected[http://localhost:99999]` | PASS | 0.000초 |
| `test_invalid_target_rejected[http://localhost:0]` | PASS | 0.000초 |
| `test_invalid_target_rejected[http://localhost/#section]` | PASS | 0.000초 |
| `test_invalid_target_rejected[http://localhost/%0Aprivate]` | PASS | 0.000초 |
| `test_invalid_target_rejected[http://local host]` | PASS | 0.000초 |
| `test_empty_state_and_report_gate` | PASS | 0.008초 |
| `test_cross_origin_and_form_blocked` | PASS | 0.005초 |
| `test_secure_cookie_is_not_false_positive` | PASS | 0.001초 |
| `test_cors_requires_credentialed_reflection[*-true-0]` | PASS | 0.002초 |
| `test_cors_requires_credentialed_reflection[https://evil-attacker.com-false-0]` | PASS | 0.002초 |
| `test_cors_requires_credentialed_reflection[https://evil-attacker.com-true-1]` | PASS | 0.001초 |
| `test_vulnerable_demo_and_reports` | PASS | 1.809초 |
| `test_direct_target_hardened_profile` | PASS | 1.238초 |
| `test_unreachable_target_is_error` | PASS | 2.092초 |
| `test_duplicate_start_cancel_and_reset` | PASS | 0.013초 |
| `test_events_broadcast_and_replay` | PASS | 0.003초 |
| `test_redirects_do_not_escape_scope` | PASS | 1.430초 |

### 실행파일 독립 실행 결과

- 결과: **PASS**
- 수행 시각: 2026-11-04T09:00:00.299680+09:00
- 실행파일 SHA-256: `9b664f6138c34aa39350cc953ce53c4437febb526d7cae932038ed4c6a8eeb1c`
- 실행파일 크기: 65,658,315 bytes

| 검증 항목 | 결과 | 실제 결과 |
| --- | --- | --- |
| standalone_health | PASS | Copied exe starts from Korean path, no project sources |
| bundled_asset:/ | PASS | {"status": 200, "bytes": 14368} |
| bundled_asset:/static/app.css | PASS | {"status": 200, "bytes": 27732} |
| bundled_asset:/static/app.js | PASS | {"status": 200, "bytes": 30025} |
| bundled_asset:/static/fonts/NotoSansKR.ttf | PASS | {"status": 200, "bytes": 10414588} |
| bundled_asset:/static/fonts/IBMPlexMono-Regular.ttf | PASS | {"status": 200, "bytes": 135580} |
| start_demo | PASS | Embedded lab starts without Python subprocess |
| demo_result | PASS | {"status": "completed", "target_url": "http://127.0.0.1:2149", "endpoints_count": 8, "findings_count": 5, "chains_count": 1, "severity": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 2, "INFO": 0}, "score": 46, "grade": "F", "checks": [{"rule_id": "BASE", "title": "헤더·쿠키·CORS·정보 노출", "status": "FINDING", "reason": "실제로 측정한 응답에 대한 기존 규칙 결과입니다.", "tested": 8, "findings": 3, "errors": 0, "version": "1.0"}, {"rule_id": "R11", "title": "SQL Injection 조건 대조", "status": "SIGNAL", "reason": "매개변수 2개 대조, 조건 쌍 2회 반복. 읽기 응답만 비교했습니다. 판정 보류: 정상 기준 응답 없음; 정상 기준 응답 없음", "tested": 2, "findings": 0, "errors": 0, "version": "1.0"}, {"rule_id": "R06", "title": "입력값 반사와 출력 문맥", "status": "PASS", "reason": "HTML 원시 반사 0개. 반사만으로 XSS를 확정하지 않습니다.", "tested": 2, "findings": 0, "errors": 0, "version": "1.0"}, {"rule_id": "R12", "title": "브라우저 XSS 실행 확인", "status": "NOT_RUN", "reason": "범위 안에서 HTML 반사 또는 JavaScript 라우트 후보가 없습니다.", "tested": 0, "findings": 0, "errors": 0, "version": "1.0"}, {"rule_id": "R09", "title": "계정 간 객체 권한 대조", "status": "NOT_RUN", "reason": "소유권·역할 정책과 테스트 세션을 지정하지 않았습니다.", "tested": 0, "findings": 0, "errors": 0, "version": "1.0"}, {"rule_id": "R10", "title": "역할별 관리 응답 대조", "status": "NOT_RUN", "reason": "소유권·역할 정책과 테스트 세션을 지정하지 않았습니다.", "tested": 0, "findings": 0, "errors": 0, "version": "1.0"}, {"rule_id": "R11-T", "title": "시간 기반 SQL 조건 대조", "status": "NOT_RUN", "reason": "로컬 시간 대조 시나리오를 지정하지 않았습니다.", "tested": 0, "findings": 0, "errors": 0, "version": "1.0"}, {"rule_id": "R12-S", "title": "저장형 XSS 실행 대조", "status": "NOT_RUN", "reason": "저장·조회·정리 URL을 가진 로컬 시나리오를 지정하지 않았습니다.", "tested": 0, "findings": 0, "errors": 0, "version": "1.0"}], "assessment_complete": false, "assessment_note": "판정 보류: SQL Injection 조건 대조, 브라우저 XSS 실행 확인", "error": "", "scan_id": "b273e3d111e7", "started_at": "2026-11-04T00:00:05.751177+00:00", "finished_at": "2026-11-04T00:00:07.180630+00:00", "demo": true, "report_paths": ["<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\reports\\20261104_090006_b273e3d111e7.md", "<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\reports\\20261104_090006_b273e3d111e7.json"], "phase": 4, "scope_mode": "path", "log_path": "<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\logs\\scans\\20261104_090005_b273e3d111e7.jsonl", "log_error": "", "app_log_path": "<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\logs\\WVA.log"} |
| report_download | PASS | 5 findings in downloaded JSON |
| report_persistence | PASS | ["<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\reports\\20261104_090006_b273e3d111e7.md", "<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\reports\\20261104_090006_b273e3d111e7.json"] |
| detailed_remediation | PASS | 5 findings include ordered actions, completion criteria and verification |
| integrated_version | PASS | Integrated executable identifies as WVA 2.5.0 |
| risk_and_ai_context | PASS | Conditional risk limits and local AI prompt coexist in all five findings |
| reference_grade | PASS | {"score": 46, "grade": "F"} |
| comparison_metadata | PASS | Completed report records scope and rule version |
| surface_metadata | PASS | {"target_url": "http://127.0.0.1:2149", "methods": {"GET": 8}, "status_codes": {"200": 5, "unmeasured": 1, "422": 1, "403": 1}, "measured_count": 7, "schema_only_count": 1, "auth_response_count": 1, "tech_stack": ["Server: uvicorn"]} |
| persistent_scan_log | PASS | <프로젝트>\tests\artifacts\독립 실행 한글 경로\logs\scans\20261104_090005_b273e3d111e7.jsonl |
| selected_json_export | PASS | Only selected findings/logs plus provenance |
| check_coverage | PASS | Versioned check statuses and unmet prerequisites are returned |
| coverage_in_exports | PASS | Selected export preserves check scope and NOT_RUN reasons |
| selected_csv_export | PASS | UTF-8 BOM CSV includes enriched endpoint metadata |
| two_sse_clients | PASS | Independent clients receive identical first event |
| sse_resume | PASS | Last-Event-ID resumes after acknowledged event |
| second_launch_reuses_server | PASS | Second launcher exits; original service stays healthy |
| shutdown_request | PASS | Graceful shutdown accepted with an active SSE subscriber |
| graceful_exit | PASS | 0 |
| port_released | PASS | Service port closed after exit |

### 브라우저 작업 흐름 결과

- 결과: **PASS**
- 수행 시각: 2026-11-04T00:01:00.279Z

| 검증 항목 | 결과 | 실제 결과 |
| --- | --- | --- |
| minimal_copy | PASS | No screen slogan, priority panel, or explanatory count captions |
| consent_validation | PASS | Unchecked permission confirmation prevents diagnosis; checked confirmation allows it |
| running_motion | PASS | Spinner, scanning line and real stages activate; scope is locked |
| completed_reference_grade | PASS | Reference score appears for a completed scan |
| direct_target_scan | PASS | 5 findings, 1 chain, 8 endpoints |
| check_coverage_and_scope | PASS | Eight check outcomes, unmet prerequisites and limited assessment are visible |
| advanced_scan_controls | PASS | SQL, browser, parameter selection and local session/scenario profile are available in a collapsed section |
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
| actual_sql_finding_dialog | PASS | Installed DVWA SQLi is detected and has dedicated risks and ordered parameterization actions |
| hash_route_xss_and_partial_grade | PASS | Installed Juice Shop DOM XSS is detected; absent server query coverage prevents an A grade and the detail fits mobile |
| offline_assets | PASS | Zero external requests and zero JavaScript exceptions |

### 독립 취약 웹앱 벤치마크 (별도 수행 기록)

- 수행 시각: 2026-11-04T09:00:01+09:00
- 상태: **PASS**. 환경·재현·결과 수집 상태이며 SQLi·XSS 탐지 통과가 아닙니다.
- 독립 취약점·방어 대조 확인 6건, 소스/실행파일 진단 12건.
- SQLi·XSS 양성 4개와 방어 대조 2개를 소스·실행파일에서 비교했습니다. 전체 사이트 정확도로 일반화하지 않습니다.
- 설치·재실행: [독립 실습 절차](benchmarks/README.md). 상세 결과·한계: [벤치마크 결과](benchmarks/RESULTS.md).

### 계정·저장형·시간 기반 source/exe 검증

- 수행 시각: 2026-11-04T09:01:36+09:00
- 결과: **PASS**, 검증 10건.
- 원본: `artifacts/benchmark/extended-result.json`. 자체 SQLite 실습 앱의 결과이며 제3자 앱 측정과 구분합니다.

### 디자인 보조 검사

- 테이스트스킬 브라우저 검사: 0 FAIL, 2 WARN.
- 1440px: 페이지 가로 넘침 0px, JavaScript 예외 0개.
- 768px: 페이지 가로 넘침 0px, JavaScript 예외 0개.
- 390px: 페이지 가로 넘침 0px, JavaScript 예외 0개.
- WARN `rainbow-chart`: The charts use 5 different hues.
- WARN `tiny-text`: 67% of the text is under 13px.
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
- 운영 사이트·운영 계정의 권한 대조, 포괄적인 전체 URL 탐색, 모든 OWASP 항목은 NOT_RUN입니다. 로컬 테스트 계정의 대조는 별도 확장 검증 기록을 따릅니다.
- 진단 데이터는 세션 메모리에 있으며 완료 보고서와 개별 JSONL 진단 로그는 파일로 보존됩니다. 앱 재실행 시 화면 히스토리를 복원하지 않습니다.
- 비밀 값은 가리지만 경로·식별자·관찰 증거는 남습니다. 공개된 실습 값과 운영 진단의 증거를 구분합니다.
