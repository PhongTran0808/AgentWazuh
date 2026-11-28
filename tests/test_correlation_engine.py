import unittest

import services.correlation_engine as engine


def alert(alert_id, timestamp, source_ip):
    return {
        "id": alert_id,
        "timestamp": timestamp,
        "rule": {"id": "5710", "level": 10, "description": "SSH authentication failed"},
        "agent": {"name": "web-01"},
        "data": {"srcip": source_ip},
    }


def detailed_alert(alert_id, timestamp, rule_id, agent_name, source_ip="", destination_ip="", **rule_fields):
    rule = {"id": rule_id, "level": rule_fields.pop("level", 10), "description": rule_fields.pop("description", rule_id)}
    rule.update(rule_fields)
    return {
        "id": alert_id,
        "timestamp": timestamp,
        "rule": rule,
        "agent": {"id": agent_name, "name": agent_name},
        "data": {"srcip": source_ip, "dstip": destination_ip},
    }


class CorrelationFallbackTests(unittest.TestCase):
    def test_fallback_groups_same_entity_and_preserves_audit_fields(self):
        original_nx = engine.nx
        engine.nx = None
        try:
            groups = engine.correlate_alerts([
                alert("one", "2026-09-15T00:00:00Z", "10.0.0.5"),
                alert("two", "2026-09-15T00:02:00Z", "10.0.0.5"),
                alert("three", "2026-09-15T00:02:00Z", "10.0.0.6"),
            ], time_window_minutes=5)
        finally:
            engine.nx = original_nx

        self.assertEqual(len(groups), 2)
        grouped = next(group for group in groups if group["entity"] == "10.0.0.5")
        self.assertEqual(grouped["alert_count"], 2)
        self.assertEqual(grouped["correlation_reason"], "shared_entity_temporal_fallback")
        self.assertTrue(grouped["incident_id"].startswith("INC-"))

    def test_empty_alerts_returns_empty_group_list(self):
        self.assertEqual(engine.correlate_alerts([]), [])

    def test_deduplication_does_not_merge_same_rule_across_agents(self):
        alerts = [
            detailed_alert("one", "2026-09-15T00:00:00Z", "5710", "web-01"),
            detailed_alert("two", "2026-09-15T00:00:10Z", "5710", "db-01"),
        ]
        deduped = engine.deduplicate_alerts(alerts)
        self.assertEqual(len(deduped), 2)
        self.assertEqual([item["occurrence_count"] for item in deduped], [1, 1])

    def test_deduplication_does_not_merge_distinct_file_events(self):
        first = detailed_alert("one", "2026-09-15T00:00:00Z", "550", "web-01")
        second = detailed_alert("two", "2026-09-15T00:00:10Z", "550", "web-01")
        first["data"]["path"] = "/etc/passwd"
        second["data"]["path"] = "/etc/shadow"
        self.assertEqual(len(engine.deduplicate_alerts([first, second])), 2)

    def test_repeated_burst_is_actionable_but_singleton_is_not(self):
        first = detailed_alert("one", "2026-09-15T00:00:00Z", "5710", "web-01")
        second = detailed_alert("two", "2026-09-15T00:00:10Z", "5710", "web-01")
        first["full_log"] = "authentication failure"
        second["full_log"] = "[WEB_SCAN_DETECTED] Directory enumeration probe detected"
        repeated = engine.deduplicate_alerts([first, second])
        self.assertEqual(
            [event["full_log"] for event in repeated[0]["evidence_events"]],
            ["authentication failure", "[WEB_SCAN_DETECTED] Directory enumeration probe detected"],
        )
        repeated_group = engine.correlate_alerts(repeated)[0]
        self.assertTrue(repeated_group["is_correlated"])
        self.assertIn("repeated_activity", repeated_group["correlation_reasons"])
        self.assertEqual(repeated_group["alert_ids"], ["one", "two"])
        self.assertEqual(repeated_group["last_seen"], "2026-09-15T00:00:10+00:00")

        singleton = engine.correlate_alerts([
            detailed_alert("three", "2026-09-15T00:10:00Z", "5501", "db-01")
        ])[0]
        self.assertFalse(singleton["is_correlated"])
        self.assertEqual(singleton["correlation_reason"], "singleton")

    def test_shared_ip_correlates_cross_device_rule_sequence(self):
        groups = engine.correlate_alerts([
            detailed_alert("scan", "2026-09-15T00:00:00Z", "100010", "firewall", "203.0.113.8", "10.0.0.10"),
            detailed_alert("login", "2026-09-15T00:03:00Z", "100015", "web-01", "203.0.113.8", "10.0.0.20"),
        ], time_window_minutes=5)
        self.assertEqual(len(groups), 1)
        self.assertTrue(groups[0]["is_correlated"])
        self.assertIn("shared_ip", groups[0]["correlation_reasons"])
        self.assertIn("rule_sequence", groups[0]["correlation_reasons"])
        self.assertGreaterEqual(groups[0]["correlation_confidence"], 50)

    def test_same_text_without_shared_entity_does_not_correlate(self):
        groups = engine.correlate_alerts([
            detailed_alert("one", "2026-09-15T00:00:00Z", "5710", "web-01", "198.51.100.1"),
            detailed_alert("two", "2026-09-15T00:01:00Z", "5710", "db-01", "198.51.100.2"),
        ])
        self.assertEqual(len(groups), 2)
        self.assertTrue(all(not group["is_correlated"] for group in groups))

    def test_low_level_temporal_noise_on_same_agent_does_not_correlate(self):
        groups = engine.correlate_alerts([
            detailed_alert("one", "2026-09-15T00:00:00Z", "100", "web-01", level=3),
            detailed_alert("two", "2026-09-15T00:01:00Z", "101", "web-01", level=4),
        ])
        self.assertEqual(len(groups), 2)
        self.assertTrue(all(not group["is_correlated"] for group in groups))

    def test_native_mitre_is_exposed_and_scored(self):
        alert_item = detailed_alert(
            "one", "2026-09-15T00:00:00Z", "999001", "web-01",
            mitre={"id": ["T1110"], "tactic": ["Credential Access"]},
        )
        group = engine.correlate_alerts([alert_item])[0]
        self.assertEqual(group["mitre_techniques"], ["T1110"])
        score = engine.score_priority(group, {}, {})
        self.assertEqual(score["breakdown"]["mitre_techniques_found"], ["T1110"])
        self.assertIn("Credential Access", score["breakdown"]["mitre_tactics_found"])

    def test_connected_chain_is_split_at_max_incident_span(self):
        alerts = [
            detailed_alert(f"a-{minute}", f"2026-09-15T00:{minute:02d}:00Z", str(6000 + minute), "web-01")
            for minute in (0, 4, 8, 12)
        ]
        groups = engine.correlate_alerts(alerts, time_window_minutes=5, max_incident_span_minutes=10)
        self.assertEqual(len(groups), 2)
        self.assertTrue(all(group["time_span"]["end"] - group["time_span"]["start"] <= 600 for group in groups))


class MultiEntityAndGraphUpgradeTests(unittest.TestCase):
    def test_extract_alert_entities(self):
        sample = {
            "id": "alert-101",
            "timestamp": "2026-09-28T08:00:00Z",
            "rule": {"id": "100104", "level": 12, "description": "Privilege escalation detected"},
            "agent": {"id": "002", "name": "ubuntu-dmz"},
            "data": {
                "srcip": "192.168.1.50",
                "dstip": "10.0.0.10",
                "srcuser": "www-data",
                "dstuser": "root",
                "devname": "FGT-Branch-01"
            }
        }
        entities = engine.extract_alert_entities(sample)
        self.assertIn("192.168.1.50", entities["src_ips"])
        self.assertIn("10.0.0.10", entities["dst_ips"])
        self.assertIn("ubuntu-dmz", entities["agents"])
        self.assertIn("root", entities["users"])
        self.assertIn("FGT-Branch-01", entities["devnames"])
        self.assertEqual(entities["rule_id"], "100104")
        self.assertEqual(entities["rule_level"], 12)

    def test_weighted_graph_correlation_links_multi_stage_attack(self):
        # Alert 1: External brute force from 192.168.1.100 to 10.0.0.50
        a1 = {
            "id": "stage-1",
            "timestamp": "2026-09-28T09:00:00Z",
            "rule": {"id": "5710", "level": 10, "description": "SSH Authentication failed"},
            "agent": {"name": "dmz-server"},
            "data": {"srcip": "192.168.1.100", "dstip": "10.0.0.50", "dstuser": "admin"}
        }
        # Alert 2: Lateral movement - dmz-server (10.0.0.50) connects to internal db (10.0.0.99)
        a2 = {
            "id": "stage-2",
            "timestamp": "2026-09-28T09:02:00Z",
            "rule": {"id": "100104", "level": 12, "description": "Lateral movement connection via SSH"},
            "agent": {"name": "dmz-server"},
            "data": {"srcip": "10.0.0.50", "dstip": "10.0.0.99", "dstuser": "root"}
        }

        groups = engine.correlate_alerts([a1, a2], time_window_minutes=15)
        self.assertEqual(len(groups), 1, "Multi-stage lateral attack should be correlated into 1 group")
        group = groups[0]
        self.assertEqual(group["involved_alerts"], 2)
        self.assertIn("confidence_score", group)
        self.assertGreaterEqual(group["confidence_score"], 40)
        self.assertLessEqual(group["confidence_score"], 98)
        self.assertIn("attack_graph_mermaid", group)
        self.assertIn("graph TD", group["attack_graph_mermaid"])

    def test_generate_incident_attack_graph_mermaid_structure(self):
        group = {
            "incident_id": "INC-TEST123",
            "entity": "192.168.1.100",
            "source_ips": ["192.168.1.100"],
            "destination_ips": ["10.0.0.50"],
            "devices": ["dmz-server"],
            "alerts": [
                {
                    "id": "a1",
                    "timestamp": "2026-09-28T09:00:00Z",
                    "rule": {"id": "5710", "level": 10, "description": "SSH Brute Force"}
                },
                {
                    "id": "a2",
                    "timestamp": "2026-09-28T09:03:00Z",
                    "rule": {"id": "100104", "level": 12, "description": "Privilege Escalation root"}
                }
            ]
        }
        mermaid = engine.generate_incident_attack_graph_mermaid(group)
        self.assertTrue(mermaid.startswith("graph TD"))
        self.assertIn("classDef attacker", mermaid)
        self.assertIn("classDef target", mermaid)
        self.assertIn("Nguồn:", mermaid)
        self.assertIn("Mục Tiêu:", mermaid)
        self.assertIn("Bước 1: Rule 5710", mermaid)
        self.assertIn("Bước 2: Rule 100104", mermaid)

    def test_generate_incident_attack_graph_groups_consecutive_repeated_rules(self):
        group = {
            "entity": "WEB-01",
            "alerts": [
                {"timestamp": f"2026-09-28T09:0{i}:00Z", "rule": {"id": "40704", "level": 5, "description": "Service exited"}}
                for i in range(6)
            ]
        }
        mermaid = engine.generate_incident_attack_graph_mermaid(group)
        self.assertIn("graph TD", mermaid)
        self.assertIn("Rule 40704 ×6", mermaid)
        self.assertIn("6 cảnh báo tương tự được gom", mermaid)
        self.assertNotIn('step_1["Bước 2:', mermaid)

    def test_web_scan_full_log_overrides_generic_authentication_description(self):
        scan = detailed_alert(
            "scan-1", "2026-09-30T17:16:37.469+0700", "2501", "WEB-01",
            level=5, description="syslog: User authentication failure.",
        )
        scan["full_log"] = (
            "[WEB_SCAN_DETECTED] User authentication failure from 127.0.0.1 "
            "- Directory enumeration probe detected (10 reqs)"
        )
        scan["occurrence_count"] = 6
        scan["evidence_ids"] = [f"scan-{index}" for index in range(1, 7)]
        group = {
            "entity": "agent-WEB-01", "devices": ["WEB-01"], "alerts": [scan],
            "alert_ids": scan["evidence_ids"], "priority_score": 24, "confidence_score": 49,
        }

        semantics = engine.derive_alert_semantics(scan)
        analysis = engine.build_deterministic_incident_analysis(group)
        mermaid = engine.generate_incident_attack_graph_mermaid(group)

        self.assertEqual(semantics["category"], "web_scan")
        self.assertEqual(semantics["source_ip"], "127.0.0.1")
        self.assertIn("dò quét thư mục", analysis["summary"])
        self.assertEqual(analysis["mitre_techniques"], ["T1595"])
        self.assertIn("Web scan: dò quét thư mục", mermaid)
        self.assertIn("Nguồn: 127.0.0.1", mermaid)
        self.assertIn("Rule 2501 ×6", mermaid)
        self.assertNotIn("<small>", mermaid)


class WazuhFactualQueryTests(unittest.TestCase):
    def setUp(self):
        from services.incident_assistant import IncidentAssistant
        self.assistant = IncidentAssistant()
        self.mock_context = {
            "status": "online",
            "version": "Wazuh v4.14.7",
            "wazuh_host": "172.16.175.145",
            "agents": [
                {
                    "id": "001",
                    "name": "ubuntu-dmz",
                    "ip": "10.0.0.50",
                    "status": "active",
                    "os": {"name": "Ubuntu", "version": "22.04"},
                    "lastKeepAlive": "2026-09-28T09:00:00Z"
                },
                {
                    "id": "002",
                    "name": "windows-ad",
                    "ip": "10.0.0.60",
                    "status": "disconnected",
                    "os": {"name": "Windows Server", "version": "2022"},
                    "lastKeepAlive": "2026-09-27T10:00:00Z"
                }
            ],
            "total_agents": 2,
            "active_agents": 1,
            "disconnected_agents": 1,
            "alert_stats": {
                "total_24h": 150,
                "critical": 5,
                "high": 15,
                "medium": 30,
                "low": 100
            },
            "error": None
        }

    def test_query_agent_count_and_list(self):
        res = self.assistant.resolve_wazuh_server_factual_query(
            "Wazuh server có bao nhiêu agent?",
            self.mock_context
        )
        self.assertIsNotNone(res)
        self.assertIn("172.16.175.145", res)
        self.assertIn("2", res)
        self.assertIn("ubuntu-dmz", res)
        self.assertIn("windows-ad", res)
        self.assertIn("🟢 ACTIVE", res)
        self.assertIn("🔴 DISCONNECTED", res)
        self.assertNotIn("/ /", res)

    def test_query_server_version_and_status(self):
        res = self.assistant.resolve_wazuh_server_factual_query(
            "Wazuh server đang chạy phiên bản bao nhiêu?",
            self.mock_context
        )
        self.assertIsNotNone(res)
        self.assertIn("Wazuh v4.14.7", res)
        self.assertIn("ONLINE", res)
        self.assertIn("55000", res)
        self.assertNotIn("/ /", res)

    def test_query_alert_stats(self):
        res = self.assistant.resolve_wazuh_server_factual_query(
            "Cho tôi thống kê cảnh báo trong 24h qua",
            self.mock_context
        )
        self.assertIsNotNone(res)
        self.assertIn("150", res)
        self.assertIn("Khẩn cấp (Critical)", res)
        self.assertIn("5", res)
        self.assertNotIn("/ /", res)

    def test_query_rule_lookup(self):
        res = self.assistant.resolve_wazuh_server_factual_query(
            "Quy tắc rule 5710 có ý nghĩa gì?",
            self.mock_context
        )
        self.assertIsNotNone(res)
        self.assertIn("5710", res)
        self.assertNotIn("/ /", res)

    def test_investigate_incident_returns_deterministic_answer_directly(self):
        result = self.assistant.investigate_incident(
            "danh sách agent hiện tại",
            system_context=self.mock_context
        )
        self.assertIn("summary", result)
        self.assertIn("ubuntu-dmz", result["summary"])
        self.assertEqual(result["reasoning_steps"][1]["title"], "Ground-Truth Verification")


class IncidentReplay6466A39F8546Tests(unittest.TestCase):
    def test_replay_20_alerts_separates_noise_preserves_zip_extract_order_and_iocs(self):
        import json
        from pathlib import Path

        snap_path = Path(__file__).resolve().parent.parent / "data" / "incident_snapshots" / "INC-6466A39F8546.json"
        if not snap_path.exists():
            self.skipTest("Snapshot INC-6466A39F8546.json not found")

        snapshot = json.loads(snap_path.read_text(encoding="utf-8"))
        raw_events = []
        for a in snapshot["group"]["alerts"]:
            raw_events.extend(a.get("evidence_events") or [a])
        self.assertEqual(len(raw_events), 20)

        deduped = engine.deduplicate_alerts(raw_events, dedup_window_seconds=60)
        # safe-file.zip and safe-file/safe-file.txt must NOT be collapsed into one Rule 554 alert,
        # and CVE-2023-32047 vs CVE-2023-35374 must NOT collapse into one Rule 23505 alert.
        rule_554_paths = [
            engine._extract_file_path(item)
            for item in deduped
            if str((item.get("rule") or {}).get("id")) == "554"
        ]
        self.assertTrue(any("safe-file.zip" in p.lower() for p in rule_554_paths))
        self.assertTrue(any("safe-file\\safe-file.txt" in p.lower() or "safe-file/safe-file.txt" in p.lower() for p in rule_554_paths))

        mitre_map = json.loads((Path(__file__).resolve().parent.parent / "config" / "mitre_mapping.json").read_text(encoding="utf-8")).get("mappings", {})
        known_devs = json.loads((Path(__file__).resolve().parent.parent / "config" / "known_devices.json").read_text(encoding="utf-8"))
        asset_crit = {d["ip"]: d for d in known_devs if "ip" in d}

        groups = engine.correlate_alerts(deduped, time_window_minutes=5, max_incident_span_minutes=30, mitre_mapping=mitre_map)
        correlated = [g for g in groups if g.get("is_correlated")]

        # Find the main safe-file.zip -> safe-file.txt malware incident
        main_group = next(
            g for g in correlated
            if any("safe-file\\safe-file.txt" in engine._extract_file_path(a).lower() or "safe-file/safe-file.txt" in engine._extract_file_path(a).lower() for a in g["alerts"])
        )

        # 1. Paint 3D CVEs (23505) separated into host_vulnerabilities, not runtime alerts
        self.assertNotIn("23505", main_group["distinct_rule_ids"])
        self.assertTrue(any(v["cve"] == "CVE-2023-32047" for v in main_group["host_vulnerabilities"]))
        self.assertTrue(any(v["cve"] == "CVE-2023-35374" for v in main_group["host_vulnerabilities"]))

        # 2. FGT-SOC used instead of xinloihuy, and FortiGate deny (21:53) excluded
        self.assertIn("FGT-SOC", main_group["devices"])
        self.assertNotIn("xinloihuy", main_group["devices"])
        self.assertNotIn("23.33.126.195", main_group["destination_ips"])

        # 3. Session start of 125.234.51.27:443 (~21:59:55) ordered BEFORE 22:00:08 (.zip)
        ordered_rules = [str((a.get("rule") or {}).get("id")) for a in main_group["alerts"]]
        idx_81619 = ordered_rules.index("81619")
        idx_zip = next(
            i for i, a in enumerate(main_group["alerts"])
            if "safe-file.zip" in engine._extract_file_path(a).lower()
        )
        self.assertLess(idx_81619, idx_zip)
        self.assertIn("100050", ordered_rules)

        # 4. Mermaid preserves Rule 100050 (8/62) on safe-file.txt, marks WIN-01 as victim, and links vuln_ctx
        mermaid = main_group["attack_graph_mermaid"]
        self.assertIn("Endpoint WIN-01 (10.10.10.10)", mermaid)
        self.assertIn(":::victim", mermaid)
        self.assertIn("Rule 100050", mermaid)
        self.assertIn("8/62", mermaid)
        self.assertIn("safe-file/safe-file.txt", mermaid)
        self.assertIn("vuln_ctx", mermaid)

        # 5. Extracted IOCs contain MD5, SHA1, and VirusTotal permalink
        iocs = main_group["extracted_iocs"]
        self.assertIn("7472f5fddfd0d4218ec5d57aa39c9b19", iocs["hashes"]["md5"])
        self.assertIn("4206473fa51738e6d713b28fbb6dc28193a1d851", iocs["hashes"]["sha1"])
        self.assertTrue(any("virustotal.com/gui/file/" in link for link in iocs["virustotal_links"]))

        # 6. MITRE not double-counted and CMDB criticality resolved
        scoring = engine.score_priority(main_group, mitre_map, asset_crit)
        self.assertGreaterEqual(scoring["breakdown"]["entity_criticality_level"], 3)
        self.assertNotIn("Malicious File", scoring["breakdown"]["mitre_techniques_found"])


class ExternalInboundKillChainTests(unittest.TestCase):
    def test_external_kali_port_scan_dir_enum_bruteforce_compromise_correlates(self):
        import json
        from pathlib import Path

        mitre_map = json.loads((Path(__file__).resolve().parent.parent / "config" / "mitre_mapping.json").read_text(encoding="utf-8")).get("mappings", {})
        alerts = [
            {
                "id": "ext-1",
                "timestamp": "2026-11-26T23:50:00+0700",
                "rule": {"id": "100105", "level": 10, "description": "External Port Scanning detected on FGT-SOC", "groups": ["fortigate", "port_scan"], "mitre": {"id": ["T1046"], "tactic": ["Discovery"]}},
                "agent": {"id": "000", "name": "xinloihuy"},
                "data": {"srcip": "203.0.113.10", "dstip": "198.51.100.2", "devname": "FGT-SOC", "action": "deny"},
                "full_log": "devname=\"FGT-SOC\" srcip=203.0.113.10 dstip=198.51.100.2 dstport=22 action=\"deny\"",
            },
            {
                "id": "ext-2",
                "timestamp": "2026-11-26T23:50:12+0700",
                "rule": {"id": "100101", "level": 10, "description": "Phát hiện dò quét đường dẫn web", "groups": ["apache", "web_attack"], "mitre": {"id": ["T1595.001"], "tactic": ["Reconnaissance"]}},
                "agent": {"id": "008", "name": "WEB-01", "ip": "10.10.30.10"},
                "data": {"srcip": "203.0.113.10", "dstip": "10.10.30.10"},
                "full_log": "203.0.113.10 - - \"GET /admin HTTP/1.1\" 200 \"Kali-Audit/1.0\"",
            },
            {
                "id": "ext-3",
                "timestamp": "2026-11-26T23:50:25+0700",
                "rule": {"id": "100107", "level": 10, "description": "Credential Brute-Force on Web Portal", "groups": ["web_attack"], "mitre": {"id": ["T1110.001"], "tactic": ["Credential Access"]}},
                "agent": {"id": "008", "name": "WEB-01", "ip": "10.10.30.10"},
                "data": {},
                "full_log": "Nov 26 23:50:25 WEB-01 portal: [AUTH_FAILED] User 'admin' login FAILED from 203.0.113.10",
            },
            {
                "id": "ext-4",
                "timestamp": "2026-11-26T23:50:32+0700",
                "rule": {"id": "100108", "level": 12, "description": "Web Portal login succeeded after Brute-Force", "groups": ["web_attack"], "mitre": {"id": ["T1078"], "tactic": ["Initial Access"]}},
                "agent": {"id": "008", "name": "WEB-01", "ip": "10.10.30.10"},
                "data": {"srcip": "203.0.113.10"},
                "full_log": "Nov 26 23:50:32 WEB-01 portal: [AUTH_SUCCESS] User 'admin' login SUCCESS from 203.0.113.10",
            },
        ]
        groups = engine.correlate_alerts(alerts, time_window_minutes=5, max_incident_span_minutes=30, mitre_mapping=mitre_map)
        self.assertEqual(len(groups), 1)
        g = groups[0]
        self.assertTrue(g["is_correlated"])
        self.assertEqual(g["correlation_type"], "cross_device_rule_sequence")
        self.assertEqual(g["devices"], ["FGT-SOC", "WEB-01"])
        self.assertIn("Nguồn: 203.0.113.10", g["attack_graph_mermaid"])
        self.assertIn(":::attacker", g["attack_graph_mermaid"])
        for tid in ("T1046", "T1595.001", "T1110.001", "T1078"):
            self.assertIn(tid, g["mitre_techniques"])

    def test_attack_graph_merges_interleaved_port_scans_and_enforces_max_steps(self):
        # Simulate interleaved port scans from two sources across multiple target IPs
        # (like INC-7B4CB40F0CFC) plus >10 distinct critical/high rules.
        alerts = []
        for idx in range(6):
            alerts.append({
                "id": f"ext-scan-{idx}",
                "timestamp": f"2026-11-28T00:0{idx}:10+0700",
                "rule": {"id": "100105", "level": 10, "description": "Port scan", "groups": ["fortigate"]},
                "data": {"srcip": "203.0.113.10", "dstip": "198.51.100.2", "devname": "FGT-SOC"},
                "occurrence_count": 5,
            })
            alerts.append({
                "id": f"int-scan-{idx}",
                "timestamp": f"2026-11-28T00:0{idx}:20+0700",
                "rule": {"id": "100105", "level": 10, "description": "Port scan", "groups": ["fortigate"]},
                "data": {"srcip": "10.10.40.10", "dstip": f"10.10.{10 + (idx % 3) * 10}.10", "devname": "FGT-SOC"},
                "occurrence_count": 2,
            })
        # Add 12 distinct level-10/12 rules to test strict max_steps=10 cap
        for r_idx in range(12):
            alerts.append({
                "id": f"crit-{r_idx}",
                "timestamp": f"2026-11-28T00:1{r_idx:02d}:00+0700" if r_idx < 10 else f"2026-11-28T00:2{r_idx - 10}:00+0700",
                "rule": {"id": str(100200 + r_idx), "level": 12 if r_idx < 2 else 10, "description": f"Stage {r_idx}"},
                "agent": {"id": "008", "name": "WEB-01"},
            })

        mermaid = engine.generate_incident_attack_graph_mermaid({
            "entity": "10.10.40.10",
            "devices": ["FGT-SOC", "WEB-01"],
            "alerts": alerts,
        })
        step_lines = [line for line in mermaid.splitlines() if "Bước " in line]
        self.assertLessEqual(len(step_lines), 10)
        # Interleaved 203.0.113.10 port scans (6 * 5 = 30) should collapse into 1 node
        self.assertIn("Rule 100105 ×30", mermaid)
        # Interleaved 10.10.40.10 port scans across 3 targets (6 * 2 = 12) should collapse into 1 node
        self.assertIn("Rule 100105 ×12", mermaid)
        self.assertIn("3 mục tiêu", mermaid)
        # Level-12 stages must be retained over lower-priority steps
        self.assertIn("Rule 100200", mermaid)
        self.assertIn("Rule 100201", mermaid)

    def test_win01_gofile_download_does_not_merge_with_web01_or_fgt_port_scans(self):
        # Reproduce exact INC-94363AF81B26 false-merge scenario:
        # 1) WEB-01 Rule 503 (agent started)
        # 2) FGT-SOC Rule 100105 port scan 10.10.40.10 -> 10.10.30.10 (WEB-01) and -> 10.10.10.10 (WIN-01)
        # 3) FGT-SOC Rule 100105 outbound block 10.10.10.10 -> external telemetry IP
        # 4) WIN-01 routine Windows noise (60805, 61104) + browser .tmp/.crdownload FIM
        # 5) WIN-01 real gofile.io download -> safe-file.zip -> extract safe-file1\safe-file.txt -> VT EICAR 100050
        alerts = [
            {
                "id": "web-503",
                "timestamp": "2026-11-28T22:20:50+0700",
                "rule": {"id": "503", "level": 3, "description": "Wazuh agent started."},
                "agent": {"id": "008", "name": "WEB-01", "ip": "10.10.30.10"},
            },
            {
                "id": "fgt-scan-web",
                "timestamp": "2026-11-28T22:21:53+0700",
                "rule": {"id": "100105", "level": 10, "description": "Port scan", "groups": ["fortigate", "port_scan"], "mitre": {"id": ["T1046"], "tactic": ["Discovery"]}},
                "agent": {"id": "000", "name": "xinloihuy"},
                "data": {"srcip": "10.10.40.10", "dstip": "10.10.30.10", "devname": "FGT-SOC"},
            },
            {
                "id": "fgt-scan-win",
                "timestamp": "2026-11-28T22:22:05+0700",
                "rule": {"id": "100105", "level": 10, "description": "Port scan", "groups": ["fortigate", "port_scan"], "mitre": {"id": ["T1046"], "tactic": ["Discovery"]}},
                "agent": {"id": "000", "name": "xinloihuy"},
                "data": {"srcip": "10.10.40.10", "dstip": "10.10.10.10", "devname": "FGT-SOC"},
            },
            {
                "id": "fgt-win-deny",
                "timestamp": "2026-11-28T22:24:00+0700",
                "rule": {"id": "100105", "level": 10, "description": "Port scan", "groups": ["fortigate", "port_scan"], "mitre": {"id": ["T1046"], "tactic": ["Discovery"]}},
                "agent": {"id": "000", "name": "xinloihuy"},
                "data": {"srcip": "10.10.10.10", "dstip": "52.123.128.14", "devname": "FGT-SOC"},
            },
            {
                "id": "win-noise-60805",
                "timestamp": "2026-11-28T22:22:35+0700",
                "rule": {"id": "60805", "level": 3, "description": "The database engine is starting a new instance."},
                "agent": {"id": "009", "name": "WIN-01", "ip": "10.10.10.10"},
            },
            {
                "id": "win-tmp-553",
                "timestamp": "2026-11-28T22:25:59+0700",
                "rule": {"id": "553", "level": 7, "description": "File deleted.", "groups": ["syscheck"]},
                "agent": {"id": "009", "name": "WIN-01", "ip": "10.10.10.10"},
                "syscheck": {"path": r"c:\users\administrator\downloads\unconfirmed 154111.crdownload"},
            },
            {
                "id": "win-zip-554",
                "timestamp": "2026-11-28T22:26:27+0700",
                "rule": {"id": "554", "level": 5, "description": "File added to the system.", "groups": ["syscheck"]},
                "agent": {"id": "009", "name": "WIN-01", "ip": "10.10.10.10"},
                "syscheck": {"path": r"c:\users\administrator\downloads\safe-file.zip"},
            },
            {
                "id": "win-zip-motw-100054",
                "timestamp": "2026-11-28T22:26:27+0700",
                "rule": {"id": "100054", "level": 6, "description": "FortiGate UTM detected access to file-sharing / staging domain.", "groups": ["sysmon", "soc_correlation"], "mitre": {"id": ["T1105"], "tactic": ["Command and Control"]}},
                "agent": {"id": "009", "name": "WIN-01", "ip": "10.10.10.10"},
                "data": {"win": {"eventdata": {"targetFilename": r"C:\Users\Administrator\Downloads\safe-file.zip:Zone.Identifier", "contents": "[ZoneTransfer] ZoneId=3 ReferrerUrl=https://gofile.io/d/UYjsGhxE"}}},
            },
            {
                "id": "win-txt-554",
                "timestamp": "2026-11-28T22:26:38+0700",
                "rule": {"id": "554", "level": 5, "description": "File added to the system.", "groups": ["syscheck"]},
                "agent": {"id": "009", "name": "WIN-01", "ip": "10.10.10.10"},
                "syscheck": {"path": r"c:\users\administrator\downloads\safe-file1\safe-file.txt"},
            },
            {
                "id": "win-txt-motw-100051",
                "timestamp": "2026-11-28T22:26:38+0700",
                "rule": {"id": "100051", "level": 8, "description": "MOTW Download URL detected", "groups": ["sysmon", "sysmon_event_15"], "mitre": {"id": ["T1105"], "tactic": ["Command and Control"]}},
                "agent": {"id": "009", "name": "WIN-01", "ip": "10.10.10.10"},
                "data": {"win": {"eventdata": {"targetFilename": r"C:\Users\Administrator\Downloads\safe-file1\safe-file.txt:Zone.Identifier", "contents": r"[ZoneTransfer] ZoneId=3 ReferrerUrl=C:\Users\Administrator\Downloads\safe-file.zip"}}},
            },
            {
                "id": "win-vt-100050",
                "timestamp": "2026-11-28T22:26:41+0700",
                "rule": {"id": "100050", "level": 12, "description": "Malware detected by VirusTotal", "groups": ["virustotal"], "mitre": {"id": ["T1204.002"], "tactic": ["Execution"]}},
                "agent": {"id": "009", "name": "WIN-01", "ip": "10.10.10.10"},
                "data": {"virustotal": {"positives": 60, "total": 68, "source": {"file": r"c:\users\administrator\downloads\safe-file1\safe-file.txt", "md5": "44d88612fea8a8f36de82e1278abb02f"}}},
            },
        ]

        groups = engine.correlate_alerts(alerts, time_window_minutes=5, max_incident_span_minutes=30)
        malware_groups = [g for g in groups if any("100050" == str((a.get("rule") or {}).get("id")) for a in g["alerts"])]
        self.assertEqual(len(malware_groups), 1)
        mg = malware_groups[0]
        self.assertEqual(mg["entity"], "agent-WIN-01")
        self.assertEqual(mg["devices"], ["WIN-01"])
        self.assertNotIn("WEB-01", mg["devices"])
        self.assertNotIn("10.10.40.10", mg["source_ips"])
        self.assertNotIn("100105", mg["distinct_rule_ids"])
        self.assertNotIn("503", mg["distinct_rule_ids"])
        self.assertIn("gofile.io", mg["extracted_iocs"]["domains"])
        mermaid = mg["attack_graph_mermaid"]
        self.assertIn("Endpoint WIN-01 (10.10.10.10)", mermaid)
        self.assertNotIn("Endpoint WEB-01", mermaid)
        self.assertIn("gofile.io", mermaid)
        self.assertIn("Malware: safe-file1/safe-file.txt", mermaid)
