import unittest
from pathlib import Path
from xml.etree import ElementTree

from integrations.wazuh_config_manager import WazuhConfigError, _validate, merge_rule_group


class WazuhRuleCorrelationTests(unittest.TestCase):
    def test_project_ssh_correlation_rule_uses_wazuh_supported_shape(self):
        root = ElementTree.fromstring(Path("config/local_rules.xml").read_text(encoding="utf-8"))
        rule = root.find(".//rule[@id='100001']")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.get("frequency"), "6")
        self.assertEqual(rule.get("timeframe"), "120")
        self.assertEqual(rule.findtext("if_matched_sid"), "5716")
        self.assertIsNone(rule.find("if_sid"))
        self.assertIsNone(rule.find("frequency"))
        self.assertIsNone(rule.find("timeframe"))
        _validate("rules", Path("config/local_rules.xml").read_text(encoding="utf-8"))

    def test_merge_normalizes_legacy_correlation_draft(self):
        current = '<group name="local,"></group>'
        legacy = '''<group name="custom,">
          <rule id="100105" level="10">
            <if_sid>5716</if_sid><frequency>5</frequency><timeframe>60</timeframe>
            <description>Legacy draft</description>
          </rule>
        </group>'''
        merged, rule_ids = merge_rule_group(current, legacy)
        root = ElementTree.fromstring(merged)
        rule = root.find(".//rule[@id='100105']")
        self.assertEqual(rule_ids, ["100105"])
        self.assertEqual(rule.get("frequency"), "5")
        self.assertEqual(rule.get("timeframe"), "60")
        self.assertEqual(rule.findtext("if_matched_sid"), "5716")

    def test_validation_rejects_child_frequency_tags(self):
        invalid = '''<group name="custom,">
          <rule id="100106" level="10">
            <if_matched_sid>5716</if_matched_sid><frequency>5</frequency><timeframe>60</timeframe>
          </rule>
        </group>'''
        with self.assertRaises(WazuhConfigError):
            _validate("rules", invalid)


if __name__ == "__main__":
    unittest.main()
