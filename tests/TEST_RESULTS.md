# WVA 테스트 결과보고서

### 수행 환경과 검증 범위

- 보고서 갱신 시각: 2026-11-04T16:28:38+09:00
- 운영체제: Windows-10-10.0.19045-SP0
- Python: 3.12.14
- 기능 테스트: **172/172 PASS**
- 외부 운영 사이트 진단은 수행하지 않았습니다. 로컬 실습 환경에 대한 검증입니다.

### 기능 테스트 상세 결과

| 실제 테스트 | 결과 | 소요 |
| --- | --- | ---: |
| `test_sql_actual_sqlite_and_negative_conditions[sql-True-FINDING]` | PASS | 1.455초 |
| `test_sql_actual_sqlite_and_negative_conditions[safe-sql-False-PASS]` | PASS | 2.114초 |
| `test_sql_actual_sqlite_and_negative_conditions[unstable-False-SIGNAL]` | PASS | 1.077초 |
| `test_sql_actual_sqlite_and_negative_conditions[waf-False-ERROR]` | PASS | 1.298초 |
| `test_sql_actual_sqlite_and_negative_conditions[db-error-False-SIGNAL]` | PASS | 2.121초 |
| `test_browser_execution_encoding_csp_and_dom[reflected-True]` | PASS | 3.791초 |
| `test_browser_execution_encoding_csp_and_dom[safe-reflected-False]` | PASS | 4.805초 |
| `test_browser_execution_encoding_csp_and_dom[csp-reflected-False]` | PASS | 5.179초 |
| `test_browser_execution_encoding_csp_and_dom[spa/#/search?q=baseline-True]` | PASS | 3.825초 |
| `test_browser_enforces_external_path_post_and_websocket_boundaries` | PASS | 2.471초 |
| `test_response_and_request_caps_are_actual_boundaries` | PASS | 5.087초 |
| `test_csrf_get_refresh_preserves_unrelated_repeated_query` | PASS | 0.221초 |
| `test_real_login_csrf_and_private_object_role_policy` | PASS | 2.271초 |
| `test_stored_xss_separate_read_and_verified_cleanup[False]` | PASS | 2.703초 |
| `test_stored_xss_separate_read_and_verified_cleanup[True]` | PASS | 2.412초 |
| `test_timing_uses_real_sqlite_conditional_delay` | PASS | 2.405초 |
| `test_partial_check_does_not_receive_a_grade[R11-NOT_RUN]` | PASS | 0.010초 |
| `test_partial_check_does_not_receive_a_grade[R09-ERROR]` | PASS | 0.004초 |
| `test_extended_probes_reject_external_targets_without_post` | PASS | 1.305초 |
| `test_missing_browser_is_not_run_instead_of_a_pass` | PASS | 1.634초 |
| `test_cancel_stored_check_still_removes_owned_record` | PASS | 1.671초 |
| `test_primary_session_is_used_for_normal_scan` | PASS | 1.307초 |
| `test_validation_does_not_echo_profile_secrets` | PASS | 0.006초 |
| `test_session_rescan_uses_the_same_redacted_comparison_profile` | PASS | 2.117초 |
| `test_request_budget_safe_and_deep_modes` | PASS | 0.002초 |
| `test_policy_auditor_safe_mode_skips_deep_tests` | PASS | 0.001초 |
| `test_policy_auditor_deep_mode_concurrency_and_teardown` | PASS | 0.002초 |
| `test_audit_consent_api_and_deep_mode` | PASS | 0.042초 |
| `test_scan_options_are_respected` | PASS | 0.029초 |
| `test_legacy_lfi_cmdi_keywords_without_contract_do_not_confirm` | PASS | 0.001초 |
| `test_legacy_ssrf_upload_keywords_without_contract_do_not_confirm` | PASS | 0.001초 |
| `test_sql_success_banner_is_only_a_signal` | PASS | 0.003초 |
| `test_build_verification_binds_source_and_binary[none]` | PASS | 0.005초 |
| `test_build_verification_binds_source_and_binary[source]` | PASS | 0.005초 |
| `test_build_verification_binds_source_and_binary[binary]` | PASS | 0.005초 |
| `test_compute_score_and_grade` | PASS | 0.000초 |
| `test_build_ai_prompt` | PASS | 0.001초 |
| `test_audit_js_secrets_detection` | PASS | 0.001초 |
| `test_consent_validation_in_start_scan` | PASS | 0.004초 |
| `test_surface_measured_metadata_and_openapi` | PASS | 1.734초 |
| `test_persistent_utf8_scan_log_and_rotation` | PASS | 4.393초 |
| `test_selected_export_formats_and_detailed_remediation[json]` | PASS | 1.850초 |
| `test_selected_export_formats_and_detailed_remediation[md]` | PASS | 1.958초 |
| `test_selected_export_formats_and_detailed_remediation[csv]` | PASS | 1.569초 |
| `test_header_remediation_does_not_mix_unrelated_policies[CSP]` | PASS | 0.001초 |
| `test_header_remediation_does_not_mix_unrelated_policies[HSTS]` | PASS | 0.001초 |
| `test_export_selection_validation[sections0-json]` | PASS | 0.005초 |
| `test_export_selection_validation[sections1-json]` | PASS | 0.005초 |
| `test_export_selection_validation[sections2-md]` | PASS | 0.005초 |
| `test_export_selection_validation[sections3-xlsx]` | PASS | 0.004초 |
| `test_export_requires_completed_current_scan_and_full_disk_logs` | PASS | 2.262초 |
| `test_csv_preserves_rows_and_blocks_formulas` | PASS | 0.000초 |
| `test_openapi_discovery_never_executes_declared_operations` | PASS | 0.004초 |
| `test_unfinished_scan_has_no_grade_or_comparison[idle]` | PASS | 0.008초 |
| `test_unfinished_scan_has_no_grade_or_comparison[running]` | PASS | 0.007초 |
| `test_unfinished_scan_has_no_grade_or_comparison[stopped]` | PASS | 0.007초 |
| `test_unfinished_scan_has_no_grade_or_comparison[error]` | PASS | 0.007초 |
| `test_added_rules_preserve_specific_limits_and_ai_context[VULN-SECRET-LEAK-1-INFO_DISCLOSURE-\ubb38\uc790\uc5f4]` | PASS | 0.001초 |
| `test_added_rules_preserve_specific_limits_and_ai_context[VULN-TLS-EXPIRING-1-MISSING_SECURITY_HEADER-\uc778\uc99d\uc11c]` | PASS | 0.001초 |
| `test_baseline_excludes_incomplete_other_scope_and_current_copy` | PASS | 0.013초 |
| `test_actual_repeat_scan_compares_only_same_profile` | PASS | 11.998초 |
| `test_tls_expiry_uses_validated_async_connection_and_closes_writer[14-1]` | PASS | 0.039초 |
| `test_tls_expiry_uses_validated_async_connection_and_closes_writer[60-0]` | PASS | 0.034초 |
| `test_tls_cancel_propagates_instead_of_becoming_success` | PASS | 0.036초 |
| `test_constant_sql_documentation_never_confirms[SQL Injection Vulnerability Detected]` | PASS | 0.007초 |
| `test_constant_sql_documentation_never_confirms[SQL_INJECTION_PWNED]` | PASS | 0.006초 |
| `test_constant_sql_documentation_never_confirms[Normal documentation]` | PASS | 0.007초 |
| `test_default_system_checks_do_not_write_or_claim_safe` | PASS | 0.001초 |
| `test_real_system_contracts_positive_and_defended[file-vulnerable-True]` | PASS | 0.352초 |
| `test_real_system_contracts_positive_and_defended[file-safe-False]` | PASS | 0.339초 |
| `test_real_system_contracts_positive_and_defended[command-vulnerable-True]` | PASS | 0.405초 |
| `test_real_system_contracts_positive_and_defended[command-reflection-False]` | PASS | 0.308초 |
| `test_real_system_contracts_positive_and_defended[ssrf-vulnerable-True]` | PASS | 0.529초 |
| `test_real_system_contracts_positive_and_defended[ssrf-reflection-False]` | PASS | 0.417초 |
| `test_real_system_contracts_positive_and_defended[ssrf-safe-False]` | PASS | 0.421초 |
| `test_real_system_contracts_positive_and_defended[upload-vulnerable-True]` | PASS | 0.453초 |
| `test_real_system_contracts_positive_and_defended[upload-reject-False]` | PASS | 0.420초 |
| `test_real_system_contracts_positive_and_defended[upload-safe-False]` | PASS | 0.420초 |
| `test_upload_cleanup_failure_is_error` | PASS | 0.451초 |
| `test_authenticated_owner_is_not_unauthenticated_bola` | PASS | 0.001초 |
| `test_concurrency_errors_are_not_pass[1]` | PASS | 0.002초 |
| `test_concurrency_errors_are_not_pass[3]` | PASS | 0.002초 |
| `test_concurrency_errors_are_not_pass[5]` | PASS | 0.002초 |
| `test_teardown_requires_real_receipts` | PASS | 0.001초 |
| `test_explicit_system_contract_rejects_unsafe_context_without_requests[safe-http://127.0.0.1]` | PASS | 0.001초 |
| `test_explicit_system_contract_rejects_unsafe_context_without_requests[deep-https://example.invalid]` | PASS | 0.001초 |
| `test_failed_stored_cleanup_cannot_be_reported_as_pass` | PASS | 0.001초 |
| `test_selected_options_and_lower_budget_preserved` | PASS | 0.030초 |
| `test_http_500_is_not_a_confirmed_race_condition` | PASS | 0.003초 |
| `test_check_invariants[PASS-0-0-NOT_RUN]` | PASS | 0.001초 |
| `test_check_invariants[PASS-1-1-ERROR]` | PASS | 0.001초 |
| `test_consent_omission_and_remote_deep_rejected` | PASS | 0.007초 |
| `test_graph_does_not_join_unrelated_credentials[value]` | PASS | 0.001초 |
| `test_graph_does_not_join_unrelated_credentials[session]` | PASS | 0.001초 |
| `test_graph_target_privilege_and_idempotence` | PASS | 0.001초 |
| `test_unverified_privilege_never_creates_chain` | PASS | 0.000초 |
| `test_large_graph_has_a_bounded_search` | PASS | 0.006초 |
| `test_authenticated_debug_response_not_claimed_public` | PASS | 0.001초 |
| `test_required_incomplete_checks_withhold_all_grades[NOT_RUN]` | PASS | 0.004초 |
| `test_required_incomplete_checks_withhold_all_grades[SIGNAL]` | PASS | 0.004초 |
| `test_required_incomplete_checks_withhold_all_grades[ERROR]` | PASS | 0.004초 |
| `test_mixed_confirmed_and_inconclusive_withholds_grade` | PASS | 0.004초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[VULN-CSP-1-MISSING_SECURITY_HEADER]` | PASS | 0.001초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[VULN-HSTS-1-MISSING_SECURITY_HEADER]` | PASS | 0.001초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[debug-EXPOSED_DEBUG_ENDPOINT]` | PASS | 0.001초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[object-BOLA_IDOR]` | PASS | 0.001초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[admin-PRIVILEGE_ESCALATION]` | PASS | 0.001초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[cors-CORS_MISCONFIGURATION]` | PASS | 0.001초 |
| `test_known_risk_explains_attack_conditions_and_observation_limits[cookie-COOKIE_SECURITY_FLAG]` | PASS | 0.000초 |
| `test_unknown_type_does_not_invent_an_attack` | PASS | 0.000초 |
| `test_profile_lists_are_not_shared_between_findings` | PASS | 0.000초 |
| `test_security_header_explanations_remain_specific[VULN-CSP-1-\ub124\ud2b8\uc6cc\ud06c \uac00\ub85c\ucc44\uae30]` | PASS | 0.001초 |
| `test_security_header_explanations_remain_specific[VULN-HSTS-1-\uc2a4\ud06c\ub9bd\ud2b8 \uc0bd\uc785]` | PASS | 0.001초 |
| `test_risk_explanation_does_not_change_observed_evidence_or_severity` | PASS | 0.000초 |
| `test_risk_context_survives_selected_and_automatic_reports[json]` | PASS | 2.236초 |
| `test_risk_context_survives_selected_and_automatic_reports[md]` | PASS | 1.904초 |
| `test_risk_context_survives_selected_and_automatic_reports[csv]` | PASS | 2.251초 |
| `test_entry_path_and_query_are_preserved[https://example.com/app/]` | PASS | 0.001초 |
| `test_entry_path_and_query_are_preserved[https://example.com/app/login?next=%2Fapp%2F&lang=ko]` | PASS | 0.000초 |
| `test_entry_path_and_query_are_preserved[http://127.0.0.1:8990?empty=&tag=a&tag=b]` | PASS | 0.000초 |
| `test_entry_path_and_query_are_preserved[https://example.com/api/item?value=tail/]` | PASS | 0.000초 |
| `test_ambiguous_entry_path_cannot_expand_the_scope_to_root[/app/..]` | PASS | 0.000초 |
| `test_ambiguous_entry_path_cannot_expand_the_scope_to_root[/app/%2e%2e/]` | PASS | 0.000초 |
| `test_ambiguous_entry_path_cannot_expand_the_scope_to_root[/app/%252e%252e/]` | PASS | 0.001초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://example.com/application]` | PASS | 0.001초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://example.com/private]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://example.com/app/../private]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://example.com/app/%2e%2e/private]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://example.com/app/%252e%252e/private]` | PASS | 0.001초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://example.com/app/%255c..%255cprivate]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[https://other.test/app/item]` | PASS | 0.000초 |
| `test_path_boundary_rejects_siblings_traversal_and_other_origins[http://example.com/app/item]` | PASS | 0.000초 |
| `test_scope_choice_is_explicit_and_query_not_copied_to_other_paths` | PASS | 0.000초 |
| `test_query_variants_are_distinct_but_root_slash_is_not` | PASS | 0.000초 |
| `test_mounted_app_follows_relative_links_and_keeps_actual_boundary` | PASS | 3.336초 |
| `test_direct_query_endpoint_preserves_other_parameters_during_id_check` | PASS | 2.307초 |
| `test_origin_choice_can_probe_root_but_still_requests_the_entry` | PASS | 3.645초 |
| `test_dashboard_accepts_path_query_and_reports_selected_scope` | PASS | 4.322초 |
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
| `test_cross_origin_and_form_blocked` | PASS | 0.005초 |
| `test_secure_cookie_is_not_false_positive` | PASS | 0.001초 |
| `test_cors_requires_credentialed_reflection[*-true-0]` | PASS | 0.002초 |
| `test_cors_requires_credentialed_reflection[https://evil-attacker.com-false-0]` | PASS | 0.002초 |
| `test_cors_requires_credentialed_reflection[https://evil-attacker.com-true-1]` | PASS | 0.002초 |
| `test_vulnerable_demo_and_reports` | PASS | 1.873초 |
| `test_direct_target_hardened_profile` | PASS | 1.769초 |
| `test_unreachable_target_is_error` | PASS | 2.109초 |
| `test_duplicate_start_cancel_and_reset` | PASS | 0.015초 |
| `test_events_broadcast_and_replay` | PASS | 0.003초 |
| `test_redirects_do_not_escape_scope` | PASS | 1.654초 |

### 실행파일 독립 실행 결과

- 결과: **PASS**
- 수행 시각: 2026-11-04T16:25:16.303811+09:00
- 실행파일 SHA-256: `f94a3af53b1eec57d4060aecfd4003b14b99f4fc25cab362245f6d10417b09e7`
- 실행파일 크기: 65,687,717 bytes

| 검증 항목 | 결과 | 실제 결과 |
| --- | --- | --- |
| standalone_health | PASS | Copied exe starts from Korean path, no project sources |
| bundled_asset:/ | PASS | {"status": 200, "bytes": 14901} |
| bundled_asset:/static/app.css | PASS | {"status": 200, "bytes": 27881} |
| bundled_asset:/static/app.js | PASS | {"status": 200, "bytes": 31984} |
| bundled_asset:/static/fonts/NotoSansKR.ttf | PASS | {"status": 200, "bytes": 10414588} |
| bundled_asset:/static/fonts/IBMPlexMono-Regular.ttf | PASS | {"status": 200, "bytes": 135580} |
| start_demo | PASS | Embedded lab starts without Python subprocess |
| demo_result | PASS | {"status": "completed", "target_url": "http://127.0.0.1:13292", "mode": "safe", "endpoints_count": 8, "findings_count": 5, "chains_count": 1, "severity": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 2, "INFO": 0}, "score": 46, "grade": null, "checks": [{"rule_id": "BASE", "title": "헤더·쿠키·CORS·정보 노출", "status": "FINDING", "reason": "실제로 측정한 응답에 대한 기존 규칙 결과입니다.", "tested": 8, "findings": 3, "errors": 0, "inconclusive": 0, "required": true, "version": "2.6.0"}, {"rule_id": "IDOR", "title": "미인증 자격증명 응답 대조", "status": "FINDING", "reason": "미인증 자격증명 반복 대조 1개, 노출 1개. 소유권 정책은 별도 검사합니다.", "tested": 1, "findings": 1, "errors": 0, "inconclusive": 0, "required": false, "version": "2.6.0"}, {"rule_id": "R11", "title": "SQL Injection 조건 대조", "status": "SIGNAL", "reason": "매개변수 2개 대조, 조건 쌍 2회 반복. 읽기 응답만 비교했습니다. 판정 보류: 정상 기준 응답 없음; 정상 기준 응답 없음", "tested": 2, "findings": 0, "errors": 0, "inconclusive": 2, "required": true, "version": "2.6.0"}, {"rule_id": "R06", "title": "입력값 반사와 출력 문맥", "status": "PASS", "reason": "HTML 원시 반사 0개. 반사만으로 XSS를 확정하지 않습니다.", "tested": 2, "findings": 0, "errors": 0, "inconclusive": 0, "required": false, "version": "2.6.0"}, {"rule_id": "R12", "title": "브라우저 XSS 실행 확인", "status": "NOT_RUN", "reason": "범위 안에서 HTML 반사 또는 JavaScript 라우트 후보가 없습니다.", "tested": 0, "findings": 0, "errors": 0, "inconclusive": 0, "required": true, "version": "2.6.0"}, {"rule_id": "R16", "title": "경로 순회 표식 파일 대조", "status": "NOT_RUN", "reason": "독립 증거를 확인할 로컬 실습 시나리오를 지정하지 않았습니다.", "tested": 0, "findings": 0, "errors": 0, "inconclusive": 0, "required": false, "version": "2.6.0"}, {"rule_id": "R17", "title": "명령어 실행 표식 대조", "status": "NOT_RUN", "reason": "독립 증거를 확인할 로컬 실습 시나리오를 지정하지 않았습니다.", "tested": 0, "findings": 0, "errors": 0, "inconclusive": 0, "required": false, "version": "2.6.0"}, {"rule_id": "R18", "title": "서버 요청 수신 기록 대조", "status": "NOT_RUN", "reason": "독립 증거를 확인할 로컬 실습 시나리오를 지정하지 않았습니다.", "tested": 0, "findings": 0, "errors": 0, "inconclusive": 0, "required": false, "version": "2.6.0"}, {"rule_id": "R19", "title": "파일 저장·조회·정리 대조", "status": "NOT_RUN", "reason": "독립 증거를 확인할 로컬 실습 시나리오를 지정하지 않았습니다.", "tested": 0, "findings": 0, "errors": 0, "inconclusive": 0, "required": false, "version": "2.6.0"}, {"rule_id": "R09", "title": "계정 간 객체 권한 대조", "status": "NOT_RUN", "reason": "소유권·역할 정책과 테스트 세션을 지정하지 않았습니다.", "tested": 0, "findings": 0, "errors": 0, "inconclusive": 0, "required": false, "version": "2.6.0"}, {"rule_id": "R10", "title": "역할별 관리 응답 대조", "status": "NOT_RUN", "reason": "소유권·역할 정책과 테스트 세션을 지정하지 않았습니다.", "tested": 0, "findings": 0, "errors": 0, "inconclusive": 0, "required": false, "version": "2.6.0"}, {"rule_id": "R11-T", "title": "시간 기반 SQL 조건 대조", "status": "NOT_RUN", "reason": "로컬 시간 대조 시나리오를 지정하지 않았습니다.", "tested": 0, "findings": 0, "errors": 0, "inconclusive": 0, "required": false, "version": "2.6.0"}, {"rule_id": "R12-S", "title": "저장형 XSS 실행 대조", "status": "NOT_RUN", "reason": "저장·조회·정리 URL을 가진 로컬 시나리오를 지정하지 않았습니다.", "tested": 0, "findings": 0, "errors": 0, "inconclusive": 0, "required": false, "version": "2.6.0"}, {"rule_id": "R15", "title": "동시성 및 상태 일관성 대조", "status": "NOT_RUN", "reason": "운영 안전 모드에서는 동시성 부하 검사를 수행하지 않습니다. 샌드박스 모드를 선택하세요.", "tested": 0, "findings": 0, "errors": 0, "inconclusive": 0, "required": false, "version": "2.6.0"}, {"rule_id": "R14", "title": "테스트 데이터 생성 및 정리 생명주기", "status": "NOT_RUN", "reason": "실제 작업 0개, 정리·부재 확인 0개, 미확인 0개. 실행하지 않은 작업은 성공으로 표시하지 않습니다.", "tested": 0, "findings": 0, "errors": 0, "inconclusive": 0, "required": false, "version": "2.6.0"}, {"rule_id": "CHAIN", "title": "유출 키의 관리자 응답 접근 대조", "status": "FINDING", "reason": "미인증·잘못된 키 거부와 실제 키 응답을 대조했습니다. 확인 1개.", "tested": 1, "findings": 1, "errors": 0, "inconclusive": 0, "required": true, "version": "2.6.0"}, {"rule_id": "IO", "title": "요청 경계·응답 수신 완료", "status": "PASS", "reason": "요청 56회, 수신·한도·경계 오류 0회.", "tested": 56, "findings": 0, "errors": 0, "inconclusive": 0, "required": true, "version": "2.6.0"}], "assessment_complete": false, "assessment_note": "판정 보류: SQL Injection 조건 대조, 브라우저 XSS 실행 확인", "error": "", "scan_id": "fa8d2502f8fa", "started_at": "2026-11-04T07:25:20.355601+00:00", "finished_at": "2026-11-04T07:25:22.225551+00:00", "demo": true, "report_paths": ["<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\reports\\20261104_162522_fa8d2502f8fa.md", "<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\reports\\20261104_162522_fa8d2502f8fa.json"], "phase": 4, "scope_mode": "path", "log_path": "<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\logs\\scans\\20261104_162520_fa8d2502f8fa.jsonl", "log_error": "", "app_log_path": "<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\logs\\WVA.log"} |
| report_download | PASS | 5 findings in downloaded JSON |
| report_persistence | PASS | ["<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\reports\\20261104_162522_fa8d2502f8fa.md", "<프로젝트>\\tests\\artifacts\\독립 실행 한글 경로\\reports\\20261104_162522_fa8d2502f8fa.json"] |
| detailed_remediation | PASS | 5 findings include ordered actions, completion criteria and verification |
| integrated_version | PASS | Integrated executable identifies as WVA 2.6.0 |
| risk_and_ai_context | PASS | Conditional risk limits and local AI prompt coexist in all five findings |
| reference_grade | PASS | {"score": 46, "grade": null, "reason": "Default demo lacks required SQL/browser evidence; all aggregate grades are withheld"} |
| comparison_metadata | PASS | Completed report records scope and rule version |
| surface_metadata | PASS | {"target_url": "http://127.0.0.1:13292", "methods": {"GET": 8}, "status_codes": {"200": 5, "unmeasured": 1, "422": 1, "403": 1}, "measured_count": 7, "schema_only_count": 1, "auth_response_count": 1, "tech_stack": ["Server: uvicorn"]} |
| persistent_scan_log | PASS | <프로젝트>\tests\artifacts\독립 실행 한글 경로\logs\scans\20261104_162520_fa8d2502f8fa.jsonl |
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
- 수행 시각: 2026-11-04T07:25:59.185Z

| 검증 항목 | 결과 | 실제 결과 |
| --- | --- | --- |
| minimal_copy | PASS | No screen slogan, priority panel, or explanatory count captions |
| consent_validation | PASS | Unchecked permission confirmation prevents diagnosis; checked confirmation allows it |
| running_motion | PASS | Spinner, scanning line and real stages activate; scope is locked |
| completed_reference_grade | PASS | Reference score appears for a completed scan |
| direct_target_scan | PASS | 5 findings, 1 chain, 8 endpoints |
| check_coverage_and_scope | PASS | Every actual check outcome and unmet prerequisite is visible |
| scan_mode_controls | PASS | Scan mode and scope mode dropdowns are available adjacent to each other |
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
| selected_checks_respected | PASS | Disabled SQL/browser checks remain NOT_RUN and optional |
| profile_validation_and_clear | PASS | Invalid profile has a readable error without echoing file contents; clear works |
| offline_assets | PASS | Zero external requests and zero JavaScript exceptions |

### 계정·저장형·시간 기반 source/exe 검증

- 수행 시각: 2026-11-04T16:25:29+09:00
- 결과: **PASS**, 검증 10건.
- 원본: `artifacts/benchmark/extended-result.json`. 자체 SQLite 실습 앱의 결과이며 제3자 앱 측정과 구분합니다.

### 최신 서버 규칙 source/exe 대조

- 상태: **PASS**, 실측 대조 20건.
- 실제 파일·표식 명령·HTTP 수신·업로드를 사용하는 로컬 취약/방어 쌍. 운영 사이트 정확도로 일반화하지 않습니다.

이전 버전의 제3자 앱·확장 검증은 해당 기록의 해시와 수행 시각으로 구분합니다. 최신 실행파일과 일치하지 않으면 이번 검증 수에 합치지 않습니다.

### 디자인 보조 검사

- 테이스트스킬 브라우저 검사: 0 FAIL, 2 WARN.
- 1440px: 페이지 가로 넘침 0px, JavaScript 예외 0개.
- 768px: 페이지 가로 넘침 0px, JavaScript 예외 0개.
- 390px: 페이지 가로 넘침 0px, JavaScript 예외 0개.
- WARN `rainbow-chart`: The charts use 5 different hues.
- WARN `tiny-text`: 63% of the text is under 13px.
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
