import unittest

from app.domain.rules import (
    RuleCondition,
    RuleValidationError,
    evaluate_rule,
    require_transition,
)


class RuleEngineTests(unittest.TestCase):
    def test_port_scan_rule_matches_all_conditions(self):
        conditions = [
            RuleCondition("destination_port_count_60s", ">", 50),
            RuleCondition("syn_ratio", ">", 0.7),
            RuleCondition("flow_duration", "<", 2),
        ]
        record = {
            "destination_port_count_60s": 76,
            "syn_ratio": 0.82,
            "flow_duration": 0.58,
        }
        self.assertTrue(evaluate_rule(conditions, record))

    def test_missing_feature_fails_closed(self):
        self.assertFalse(evaluate_rule([RuleCondition("syn_ratio", ">", 0.7)], {}))

    def test_unknown_field_is_rejected(self):
        with self.assertRaises(RuleValidationError):
            evaluate_rule([RuleCondition("magic_score", ">", 1)], {"magic_score": 10})

    def test_deployment_requires_confirmation(self):
        with self.assertRaises(RuleValidationError):
            require_transition("validated", "deployed")
        self.assertEqual(require_transition("validated", "confirmed").value, "confirmed")
        self.assertEqual(require_transition("confirmed", "deployed").value, "deployed")


if __name__ == "__main__":
    unittest.main()

