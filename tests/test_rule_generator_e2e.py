import unittest
import runpy
from unittest.mock import patch
from xml.etree import ElementTree

from integrations.wazuh_config_manager import WazuhConfigError, _validate
from services.rule_generator import generate_rule_proposal
from services.wazuh_logtest_service import parse_logtest_output
from services.wazuh_logtest_service import generate_canonical_sample_log


class RuleGeneratorTests(unittest.TestCase):
    def setUp(self):
        self.current_rules = '<group name="local,">\n</group>\n'
        self.logtest_report = {
            "ok": True,
            "matched_rule_id": 5716,
            "decoder_name": "sshd",
            "summary": "Decoder: sshd | Base Rule ID: 5716 (Level 5)",
            "tested_log": "Oct 16 12:00:00 server sshd[1234]: Failed password",
            "parsed": {
                "phase1": {"program_name": "sshd"},
                "phase2": {"name": "sshd", "srcip": "192.168.1.100"},
                "phase3": {"level": "5", "description": "sshd: authentication failed"},
            },
        }

    def test_proposal_uses_logtest_parent_and_valid_wazuh_rule_shape(self):
        with (
            patch("services.rule_generator.search_docs", return_value="Wazuh correlation docs"),
            patch("services.rule_generator.search_local", return_value="No similar local rules"),
            patch("services.rule_generator.get_next_free_rule_id", return_value=100501),
            patch("services.rule_generator.test_log_event", return_value=self.logtest_report),
            patch("services.rule_generator._try_llm_synthesis", return_value=None),
            patch("services.rule_generator.read_wazuh_config_target", return_value=(None, self.current_rules)),
        ):
            proposal = generate_rule_proposal("Tạo rule phát hiện 5 lần SSH thất bại trong 60 giây")

        root = ElementTree.fromstring(proposal["draft_xml"])
        rule = root.find(".//rule")
        self.assertEqual(rule.get("id"), "100501")
        self.assertEqual(rule.get("frequency"), "5")
        self.assertEqual(rule.get("timeframe"), "60")
        self.assertEqual(rule.findtext("if_matched_sid"), "5716")
        self.assertEqual(rule.findtext("match"), "Failed password")
        self.assertEqual(proposal["parent_rule_id"], 5716)
        _validate("rules", proposal["draft_xml"])

    def test_proposal_refuses_to_guess_parent_when_logtest_fails(self):
        failed_logtest = {**self.logtest_report, "ok": False, "matched_rule_id": None}
        with (
            patch("services.rule_generator.search_docs", return_value="docs"),
            patch("services.rule_generator.search_local", return_value=""),
            patch("services.rule_generator.get_next_free_rule_id", return_value=100501),
            patch("services.rule_generator.test_log_event", return_value=failed_logtest),
            patch("services.rule_generator._try_llm_synthesis") as llm_synthesis,
        ):
            with self.assertRaises(WazuhConfigError):
                generate_rule_proposal("SSH brute force")
        llm_synthesis.assert_not_called()

    def test_proposal_escapes_user_text_in_generated_xml(self):
        with (
            patch("services.rule_generator.search_docs", return_value="docs"),
            patch("services.rule_generator.search_local", return_value=""),
            patch("services.rule_generator.get_next_free_rule_id", return_value=100501),
            patch("services.rule_generator.test_log_event", return_value=self.logtest_report),
            patch("services.rule_generator._try_llm_synthesis", return_value=None),
            patch("services.rule_generator.read_wazuh_config_target", return_value=(None, self.current_rules)),
        ):
            proposal = generate_rule_proposal("Tạo rule <suspicious>& event")

        rule = ElementTree.fromstring(proposal["draft_xml"]).find(".//rule")
        self.assertEqual(rule.findtext("match"), "<suspicious>& event")
        self.assertIn("&lt;suspicious&gt;&amp; event", proposal["draft_xml"])

    def test_logtest_parser_extracts_decoder_and_parent_rule(self):
        output = """**Phase 1: Completed pre-decoding.
        timestamp: 'Oct 16 12:00:00'
        hostname: 'server'
        program_name: 'sshd'
        **Phase 2: Completed decoding.
        name: 'sshd'
        srcip: '192.168.1.100'
        **Phase 3: Completed filtering (rules).
        id: '5716'
        level: '5'
        description: 'sshd: authentication failed'
        """
        parsed = parse_logtest_output(output)
        self.assertEqual(parsed["decoder_name"], "sshd")
        self.assertEqual(parsed["matched_rule_id"], 5716)

    def test_ftp_canonical_log_matches_installed_wazuh_parent_rule(self):
        sample = generate_canonical_sample_log("Tạo rule phát hiện FTP brute-force")
        self.assertIn("pam_unix(vsftpd:auth)", sample)
        self.assertIn("authentication failure", sample)

    def test_privileged_helper_accepts_multi_group_wazuh_rules_file(self):
        helper = runpy.run_path("deploy/agentwazuh-wazuh-config")
        helper["validate"](
            "rules",
            '''<!-- Existing local rules -->
<group name="local,"><rule id="100001" level="5"><description>Existing</description></rule></group>
<group name="custom,"><rule id="100002" level="10" frequency="5" timeframe="60"><if_matched_sid>5503</if_matched_sid></rule></group>''',
        )

    def test_privileged_helper_rejects_malformed_multi_group_xml(self):
        helper = runpy.run_path("deploy/agentwazuh-wazuh-config")
        with self.assertRaises(SystemExit):
            helper["validate"](
                "rules",
                '<group name="one,"></group><group name="two,"><rule></group>',
            )


if __name__ == "__main__":
    unittest.main()
