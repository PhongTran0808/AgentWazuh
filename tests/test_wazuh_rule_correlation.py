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

    def test_merge_supports_multiple_top_level_groups(self):
        current = '''<!-- Local rules -->
<group name="local,">
  <rule id="100001" level="5"><description>Existing</description></rule>
</group>
<group name="custom,">
  <rule id="100002" level="5"><description>Also existing</description></rule>
</group>'''
        candidate = '''<group name="new,">
  <rule id="100003" level="5"><description>New rule</description></rule>
</group>'''
        merged, rule_ids = merge_rule_group(current, candidate)
        wrapped = ElementTree.fromstring(f"<root>{merged}</root>")
        self.assertEqual(rule_ids, ["100003"])
        self.assertEqual([rule.get("id") for rule in wrapped.findall(".//rule")], [
            "100001", "100002", "100003",
        ])
        self.assertEqual(wrapped.findall(".//rule")[-1].findtext("group"), "new,")
        self.assertIn("<!-- Local rules -->", merged)
        _validate("rules", merged)


if __name__ == "__main__":
    unittest.main()
