"""Unit tests for pure password analyzer engine (password_analyzer.py)."""

import unittest
import password_analyzer as core


class PasswordAnalyzerCoreTests(unittest.TestCase):
    def test_unicode_code_point_counting(self):
        # ASCII
        self.assertEqual(core.count_code_points("abc123"), 6)
        # Accented characters and combining characters
        self.assertEqual(core.count_code_points("café"), 4)
        # Emoji (e.g. 🔒 is 1 code point)
        self.assertEqual(core.count_code_points("🔒🔑"), 2)

    def test_entropy_ascii_calculation(self):
        # All lowercase 8 chars -> pool 26 -> 8 * log2(26) ~= 37.6 bits
        res = core.calculate_entropy("abcdefgh")
        self.assertEqual(res["status"], "CALCULATED")
        self.assertEqual(res["pool_size"], 26)
        self.assertAlmostEqual(res["bits"], 37.6, delta=0.5)
        self.assertIsNone(res["warning"])

    def test_entropy_uncalibrated_for_non_ascii(self):
        res = core.calculate_entropy("Contraseña123!")
        self.assertEqual(res["status"], "UNAVAILABLE_NON_ASCII")
        self.assertEqual(res["warning"], "ENTROPY_UNCALIBRATED_UNICODE")
        self.assertIsNone(res["bits"])

    def test_empty_password_analysis(self):
        res = core.analyze_password("")
        self.assertEqual(res["score"], 0)
        self.assertEqual(res["classification"], "Very Weak")
        self.assertEqual(res["length_code_points"], 0)
        self.assertFalse(res["criteria"]["length_target_met"])

    def test_short_password_severity_caps(self):
        # 6 characters with mixed characters -> length < 8 caps at max 19
        res = core.analyze_password("A1!b#c")
        self.assertLessEqual(res["score"], 19)
        self.assertEqual(res["classification"], "Very Weak")

        # 10 characters with good composition -> length 8..11 caps at max 49
        res = core.analyze_password("A1!bcdefgh")
        self.assertLessEqual(res["score"], 49)
        self.assertIn(res["classification"], ("Weak", "Moderate"))

        # 13 characters -> length 12..14 caps at max 69
        res = core.analyze_password("A1!bcdefghijk")
        self.assertLessEqual(res["score"], 69)

    def test_strong_long_passphrase_uncapped(self):
        res = core.analyze_password("Correct-Horse-Battery-Staple-2026!")
        self.assertGreaterEqual(res["score"], 80)
        self.assertEqual(res["classification"], "Very Strong")

    def test_dictionary_exact_match_caps_at_9(self):
        for word in ("password", "admin", "123456", "dragon", "welcome"):
            res = core.analyze_password(word)
            self.assertLessEqual(res["score"], 9)
            self.assertEqual(res["classification"], "Very Weak")

    def test_custom_dictionary_exact_match(self):
        custom = frozenset({"internalprojectx", "acmecorp2026"})
        res = core.analyze_password("internalprojectx", custom_dict=custom)
        self.assertLessEqual(res["score"], 9)
        self.assertEqual(res["classification"], "Very Weak")
        rule_ids = [p["rule_id"] for p in res["pattern_penalties"]]
        self.assertIn("DICT_CUSTOM_EXACT", rule_ids)

    def test_custom_dictionary_size_and_entry_limits(self):
        # Exceeds max entries
        oversized_content = "\n".join(f"word{i}" for i in range(10005))
        with self.assertRaises(ValueError):
            core.load_custom_dictionary(oversized_content, is_content=True)


if __name__ == "__main__":
    unittest.main()
