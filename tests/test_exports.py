"""Unit tests verifying JSON export privacy invariants and field allowlists."""

import json
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
        self.assertNotIn(secret_corp_entry.casefold(), serialized)


if __name__ == "__main__":
    unittest.main()
