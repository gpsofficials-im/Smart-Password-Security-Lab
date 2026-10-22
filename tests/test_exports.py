"""Unit tests verifying JSON export privacy invariants and field allowlists."""

import json
from typing import Any
import unittest
import password_analyzer as core


class ExportPrivacyTests(unittest.TestCase):
    def test_export_contains_only_allowlisted_fields(self):
        raw_password = "SuperSecretCandidate123!#$"
        result = core.analyze_password(raw_password)
        export = core.generate_allowlisted_export(result)

        allowed_fields = {
            "report_schema_version",
            "analysis_version",
            "generated_at",
            "score",
            "classification",
            "length_code_points",
            "criteria",
            "warnings",
            "recommendation_ids",
            "entropy_estimate",
        }

        for key in export.keys():
            self.assertIn(key, allowed_fields)

    def test_export_never_contains_secret_or_substrings(self):
        raw_password = "VeryConfidential-Keyphrase-9988!!"
        result = core.analyze_password(raw_password)
        export = core.generate_allowlisted_export(result)

        serialized = json.dumps(export)
        self.assertNotIn(raw_password, serialized)
        self.assertNotIn("VeryConfidential", serialized)
        self.assertNotIn("Keyphrase", serialized)
        self.assertNotIn("password_raw", serialized)
        self.assertNotIn("hash", serialized)
        self.assertNotIn("masked", serialized)

    def test_custom_dictionary_exact_match_does_not_leak_entry(self):
        secret_corp_entry = "TopSecretInternalVaultWord"
        custom_dict = frozenset({secret_corp_entry.casefold()})
        result = core.analyze_password(secret_corp_entry, custom_dict=custom_dict)
        export = core.generate_allowlisted_export(result)

        serialized = json.dumps(export)
        self.assertNotIn(secret_corp_entry, serialized)
    def test_analysis_result_object_never_contains_password_recursively(self):
        secret = "UltraSecretString!99"
        result = core.analyze_password(secret)

        def check_no_leak(obj: Any) -> None:
            if isinstance(obj, str):
                self.assertNotIn(secret, obj)
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    self.assertNotIn(secret, str(k))
                    check_no_leak(v)
            elif isinstance(obj, (list, tuple, set, frozenset)):
                for item in obj:
                    check_no_leak(item)

        check_no_leak(result)

    def test_custom_dictionary_bounds_rejection(self):
        # Oversized line (> 256 code points) is skipped safely
        valid_with_long = "normalword\n" + ("x" * 300) + "\nsecondword"
        dict_set = core.load_custom_dictionary(valid_with_long, is_content=True)
        self.assertIn("normalword", dict_set)
        self.assertIn("secondword", dict_set)
        self.assertEqual(len(dict_set), 2)


if __name__ == "__main__":
    unittest.main()
