"""Automated regression tests for Password Strength Checker.

Run with: python -m unittest -v
or:       python test_password_checker.py
"""

import contextlib
import io
import unittest

import password_strength_checker as psc


class PasswordStrengthCheckerTests(unittest.TestCase):
    def test_length_boundary(self):
        self.assertFalse(psc.check_length("A1!bcdefghi"))
        self.assertTrue(psc.check_length("A1!bcdefghij"))

    def test_core_score_is_at_most_five(self):
        results = psc.analyze_password("Mango!Cedar-Quartz7-Lantern")
        strength, score = psc.calculate_strength_score(results)
        self.assertEqual(score, 5)
        self.assertEqual(strength, "Strong")

    def test_common_password_is_always_very_weak(self):
        for password in ("password", "PASSWORD", "Password123!", "pass-word", "P@ssw0rd!", "Adm1n"):
            with self.subTest(password=password):
                results = psc.analyze_password(password)
                strength, score = psc.calculate_strength_score(results)
                self.assertTrue(results["common"])
                self.assertEqual(strength, "Very Weak")
                self.assertGreaterEqual(score, 0)
                self.assertLessEqual(score, 5)

    def test_sequential_pattern_caps_strength(self):
        results = psc.analyze_password("Abcd1234!Xyz")
        strength, score = psc.calculate_strength_score(results)
        self.assertTrue(results["sequence"])
        self.assertLessEqual(score, 5)
        self.assertEqual(strength, "Weak")

    def test_keyboard_walk_is_detected(self):
        results = psc.analyze_password("Tiger!Qwerty2026")
        self.assertTrue(results["keyboard"])
        self.assertTrue(results["predictable"])
        self.assertEqual(psc.calculate_strength_score(results)[0], "Weak")

    def test_repeated_characters_are_detected(self):
        results = psc.analyze_password("Mango!ZZZZ-Orbit7")
        self.assertTrue(results["repeated"])
        self.assertTrue(results["predictable"])

    def test_spaces_are_not_silently_trimmed(self):
        # Twelve spaces satisfy the length-only check but not composition checks.
        results = psc.analyze_password("            ")
        self.assertTrue(results["length"])
        self.assertFalse(results["uppercase"])
        self.assertFalse(results["special"])

    def test_empty_password_is_safe_to_analyze(self):
        results = psc.analyze_password("")
        strength, score = psc.calculate_strength_score(results)
        self.assertEqual(score, 0)
        self.assertEqual(strength, "Very Weak")

    def test_report_never_prints_password_text(self):
        password = "DoNotReveal-MySecret7!"
        results = psc.analyze_password(password)
        strength, score = psc.calculate_strength_score(results)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            psc.display_analysis_report(password, results, strength, score)
        self.assertNotIn(password, output.getvalue())
        self.assertIn("[hidden for privacy]", output.getvalue())
        self.assertIn("/5 criteria", output.getvalue())

    def test_score_denominator_matches_core_checks(self):
        results = psc.analyze_password("abc")
        _, score = psc.calculate_strength_score(results)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
