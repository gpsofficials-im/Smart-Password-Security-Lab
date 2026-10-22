"""Unit tests for deterministic pattern detection rules (tests/test_patterns.py)."""

import unittest
import password_analyzer as core


class PatternDetectionTests(unittest.TestCase):
    def test_ascending_and_descending_sequences(self):
        # Ascending alphanumeric
        self.assertGreater(core.detect_sequences("abcd"), 0)
        self.assertGreater(core.detect_sequences("1234"), 0)
        self.assertGreater(core.detect_sequences("6789"), 0)

        # Descending alphanumeric
        self.assertGreater(core.detect_sequences("dcba"), 0)
        self.assertGreater(core.detect_sequences("4321"), 0)
        self.assertGreater(core.detect_sequences("9876"), 0)

        # Non-sequential
        self.assertEqual(core.detect_sequences("a1c3e5"), 0)
        self.assertEqual(core.detect_sequences("mK9#vP2$"), 0)

    def test_repeated_characters(self):
        self.assertTrue(core.detect_repeated_runs("aaaa"))
        self.assertTrue(core.detect_repeated_runs("1111"))
        self.assertTrue(core.detect_repeated_runs("passsspass"))
        self.assertTrue(core.detect_repeated_runs("Prefix!!!!Suffix"))

        # Under threshold (3 repeats)
        self.assertFalse(core.detect_repeated_runs("aaa"))
        self.assertFalse(core.detect_repeated_runs("Prefix!!!Suffix"))

    def test_keyboard_walks(self):
        # Horizontal QWERTY walks
        self.assertTrue(core.detect_keyboard_walks("qwerty"))
        self.assertTrue(core.detect_keyboard_walks("asdf"))
        self.assertTrue(core.detect_keyboard_walks("zxcv"))
        self.assertTrue(core.detect_keyboard_walks("poiuyt"))

        # Vertical / diagonal walks
        self.assertTrue(core.detect_keyboard_walks("1qaz"))
        self.assertTrue(core.detect_keyboard_walks("zaq1"))
        self.assertTrue(core.detect_keyboard_walks("xsw2"))

        # Unrelated keys
        self.assertFalse(core.detect_keyboard_walks("qazxsw"))

    def test_year_suffix(self):
        self.assertTrue(core.detect_year_suffix("password2024"))
        self.assertTrue(core.detect_year_suffix("admin1999"))
        self.assertTrue(core.detect_year_suffix("welcome2026"))

        # Year alone without base word
        self.assertFalse(core.detect_year_suffix("2024"))
        # Non-year 4-digit number
        self.assertFalse(core.detect_year_suffix("admin3500"))

    def test_common_variants(self):
        # Leetspeak
        self.assertTrue(core.detect_common_variant("P@ssw0rd"))
        self.assertTrue(core.detect_common_variant("Adm1n"))

        # Numeric suffix on common base
        self.assertTrue(core.detect_common_variant("password123"))
        self.assertTrue(core.detect_common_variant("welcome2020"))
        self.assertTrue(core.detect_common_variant("letmein1"))

        # Clean random password is not a variant
        self.assertFalse(core.detect_common_variant("Quartz-Vortex-Pineapple7!"))

    def test_passphrase_substring_not_penalized_as_dictionary_match(self):
        # The word 'password' or 'dragon' inside a long passphrase should not trigger DICT_BUNDLED_EXACT
        res = core.analyze_password("MyDragonIsASecretKeeper-2026#")
        rule_ids = [p["rule_id"] for p in res["pattern_penalties"]]
        self.assertNotIn("DICT_BUNDLED_EXACT", rule_ids)
        self.assertGreaterEqual(res["score"], 60)


if __name__ == "__main__":
    unittest.main()
