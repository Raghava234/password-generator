"""Unit tests for password_generator."""

from __future__ import annotations

import io
import string
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import password_generator as pg


class TestGeneratePassword(unittest.TestCase):
    """Tests for password generation logic and validation."""

    def test_default_password_properties(self) -> None:
        pwd = pg.generate_password()
        self.assertEqual(len(pwd), 16)
        self.assertTrue(any(c in string.ascii_uppercase for c in pwd))
        self.assertTrue(any(c in string.ascii_lowercase for c in pwd))
        self.assertTrue(any(c in string.digits for c in pwd))
        self.assertTrue(any(c in pg.SYMBOLS for c in pwd))

    def test_custom_length_and_minimum_class_guarantee(self) -> None:
        for _ in range(25):
            pwd = pg.generate_password(length=4)
            self.assertEqual(len(pwd), 4)
            self.assertTrue(any(c in string.ascii_uppercase for c in pwd))
            self.assertTrue(any(c in string.ascii_lowercase for c in pwd))
            self.assertTrue(any(c in string.digits for c in pwd))
            self.assertTrue(any(c in pg.SYMBOLS for c in pwd))

    def test_disable_character_sets(self) -> None:
        pwd = pg.generate_password(
            length=20,
            use_uppercase=False,
            use_lowercase=False,
            use_digits=True,
            use_symbols=False,
        )
        self.assertEqual(len(pwd), 20)
        self.assertTrue(all(c in string.digits for c in pwd))

    def test_exclude_ambiguous(self) -> None:
        for _ in range(30):
            pwd = pg.generate_password(length=32, exclude_ambiguous=True)
            self.assertTrue(pg.AMBIGUOUS_CHARS.isdisjoint(pwd))

    def test_custom_exclude_chars(self) -> None:
        excluded = "aeiouAEIOU!@#"
        for _ in range(20):
            pwd = pg.generate_password(length=24, exclude_chars=excluded)
            self.assertTrue(set(excluded).isdisjoint(pwd))

    def test_generate_multiple_passwords_unique(self) -> None:
        pwds = pg.generate_passwords(count=10, config=pg.PasswordConfig(length=16))
        self.assertEqual(len(pwds), 10)
        self.assertEqual(len(set(pwds)), 10)

    def test_validation_errors(self) -> None:
        with self.assertRaises(ValueError):
            pg.generate_password(length=0)

        with self.assertRaises(ValueError):
            pg.generate_password(
                length=10,
                use_uppercase=False,
                use_lowercase=False,
                use_digits=False,
                use_symbols=False,
            )

        with self.assertRaises(ValueError):
            pg.generate_password(length=3)

        with self.assertRaises(ValueError):
            pg.generate_password(
                length=8,
                use_uppercase=False,
                use_lowercase=False,
                use_digits=True,
                use_symbols=False,
                exclude_chars=string.digits,
            )

        with self.assertRaises(ValueError):
            pg.generate_passwords(count=0)


class TestEntropyAndStrength(unittest.TestCase):
    """Tests for entropy calculation and strength classification."""

    def test_empty_password_entropy(self) -> None:
        self.assertEqual(pg.calculate_entropy(""), 0.0)
        self.assertEqual(pg.assess_strength(0.0), "Very Weak")

    def test_strength_thresholds(self) -> None:
        self.assertEqual(pg.assess_strength(20), "Very Weak")
        self.assertEqual(pg.assess_strength(45), "Weak")
        self.assertEqual(pg.assess_strength(70), "Fair")
        self.assertEqual(pg.assess_strength(90), "Strong")
        self.assertEqual(pg.assess_strength(120), "Very Strong")

    def test_entropy_with_explicit_pool_size(self) -> None:
        entropy = pg.calculate_entropy("abcd", pool_size=16)
        self.assertAlmostEqual(entropy, 16.0)


class TestCLI(unittest.TestCase):
    """Tests for CLI argument parsing and output."""

    def test_cli_default_and_count(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = pg.main(["-l", "12", "-n", "3"])
        self.assertEqual(code, 0)
        lines = stdout.getvalue().strip().splitlines()
        self.assertEqual(len(lines), 3)
        self.assertTrue(all(len(line) == 12 for line in lines))

    def test_cli_show_strength(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = pg.main(["-l", "20", "--show-strength"])
        self.assertEqual(code, 0)
        output = stdout.getvalue().strip()
        self.assertIn("bits -", output)

    def test_cli_invalid_options_returns_nonzero(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = pg.main(["--no-upper", "--no-lower", "--no-digits", "--no-symbols"])
        self.assertEqual(code, 2)
        self.assertIn("Error:", stderr.getvalue())

    def test_cli_interactive_mode(self) -> None:
        answers = iter(["14", "2", "y", "y", "y", "n", "y", "", "n"])
        stdout = io.StringIO()
        with patch("builtins.input", side_effect=lambda _: next(answers)), redirect_stdout(stdout):
            code = pg.main(["--interactive"])
        self.assertEqual(code, 0)
        lines = stdout.getvalue().strip().splitlines()
        self.assertEqual(len(lines), 2)
        for line in lines:
            self.assertEqual(len(line), 14)
            self.assertTrue(pg.AMBIGUOUS_CHARS.isdisjoint(line))


if __name__ == "__main__":
    unittest.main()
