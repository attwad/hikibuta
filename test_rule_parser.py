import rule_parser
import unittest

class RuleParserTest(unittest.TestCase):

  def setUp(self):
    super().setUp()
    self._rule = (
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"GPL DNS EXPLOIT '
        'named 8.2->8.2.1"; flow:to_server,established; content:"../../../"; '
        'reference:bugtraq,788; reference:cve,1999-0833; '
        'classtype:attempted-admin; sid:2100258; rev:7;)')

  def test_is_rule_line_empty(self):
    self.assertFalse(rule_parser.Rule.is_rule_line(''))

  def test_is_rule_line(self):
    self.assertTrue(rule_parser.Rule.is_rule_line(self._rule))

  def test_output_as_commented_or_not(self):
    rule = rule_parser.Rule(self._rule)
    self.assertTrue(rule.as_commented.startswith('#'))
    self.assertFalse(rule.as_uncommented.startswith('#'))
    self.assertEqual(rule.as_uncommented, self._rule)

  def test_is_rule_line_commented_out(self):
    self.assertTrue(rule_parser.Rule.is_rule_line('# ' + self._rule))

  def test_repr(self):
    rule = rule_parser.Rule(self._rule)
    self.assertTrue(str(rule))

  def test_not_commented(self):
    rule = rule_parser.Rule(self._rule)
    self.assertFalse(rule.commented)

  def test_commented(self):
    rule = rule_parser.Rule('#' + self._rule)
    self.assertTrue(rule.commented)

  def test_options(self):
    rule = rule_parser.Rule('#' + self._rule)
    self.assertTrue(rule.options)
    self.assertEqual('to_server,established', rule.options.get('flow'))
    self.assertEqual(
        '"GPL DNS EXPLOIT named 8.2->8.2.1"', rule.options.get('msg'))
    self.assertEqual('"../../../"', rule.options.get('content'))
    self.assertEqual('bugtraq,788; cve,1999-0833', rule.options.get('reference'))
    self.assertEqual('2100258', rule.options.get('sid'))
    self.assertEqual('attempted-admin', rule.options.get('classtype'))

  def test_properties(self):
    rule = rule_parser.Rule('#' + self._rule)
    self.assertEqual('alert', rule.action)
    self.assertEqual('tcp', rule.src_protocol)
    self.assertEqual('$EXTERNAL_NET', rule.src_net)
    self.assertEqual('any', rule.src_port)
    self.assertEqual('$HOME_NET', rule.dst_net)
    self.assertEqual('53', rule.dst_port)
