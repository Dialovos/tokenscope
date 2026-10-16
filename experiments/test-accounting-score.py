#!/usr/bin/env python3
"""Adversarial checks for identity matching and conservative accounting states."""
import unittest

from score_accounting import score, validate_reference


def server(aid, reported=True, counts=(7, 11)):
    row = {"event": "received", "attempt_id": aid, "response_id": "resp-" + aid,
           "assigned_usage": {"prompt_tokens": counts[0], "completion_tokens": counts[1],
                              "total_tokens": sum(counts)}, "status": 200, "scenario": "complete"}
    return [row, {**row, "event": "usage_emitted"}] if reported else [row]


def observed(aid, counts=(7, 11)):
    return {"response_id": "resp-" + aid, "input": counts[0], "output": counts[1]}


class AccountingTests(unittest.TestCase):
    def test_swapped_identity_does_not_pass_on_correct_aggregate(self):
        truth = server("a", counts=(7, 11)) + server("b", counts=(13, 17))
        rows = [observed("a", (13, 17)), observed("b", (7, 11))]
        result = score(truth, rows)
        self.assertEqual(result["summary"]["states"], {"incorrect": 2})

    def test_missing_zero_and_absent_attempt_are_distinct(self):
        truth = server("zero", counts=(0, 0)) + server("missing", False) + server("lost")
        result = score(truth, [observed("zero", (0, 0)), observed("missing", (None, None))])
        self.assertEqual(result["summary"]["states"], {"exact": 1, "unknown": 1, "unobserved": 1})

    def test_duplicate_records_are_not_summed(self):
        result = score(server("a"), [observed("a"), observed("a")])
        self.assertEqual(result["summary"]["exact_attempts"], 1)
        self.assertEqual(result["summary"]["duplicate_records"], 1)
        conflicting = score(server("a"), [observed("a"), observed("a", (7, 99))])
        self.assertEqual(conflicting["attempts"][0]["state"], "conflicting_duplicates")

    def test_unmatched_counts_and_conflicting_identity_are_preserved(self):
        rows = [observed("other"), {**observed("a"), "attempt_id": "b"}]
        result = score(server("a") + server("b"), rows)
        self.assertEqual(result["summary"]["unmatched_records"], 2)
        self.assertEqual(result["summary"]["matched_attempts"], 0)

    def test_no_claim_without_usage_evidence(self):
        result = score(server("a", False), [observed("a", (0, 0))])
        self.assertEqual(result["attempts"][0]["state"], "counts_without_emitted_evidence")

    def test_missing_application_attempt_invalidates_fixture(self):
        self.assertIn("application_server_attempt_inventory_mismatch", validate_reference(server("a"), []))


if __name__ == "__main__":
    unittest.main()
