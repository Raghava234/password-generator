"""Cryptographically secure random password generator and CLI."""

from __future__ import annotations

import argparse
import math
import secrets
import string
import sys
from dataclasses import dataclass
from typing import Sequence

AMBIGUOUS_CHARS = frozenset("0Oo1lI|")
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/"

_SYSTEM_RANDOM = secrets.SystemRandom()


@dataclass(frozen=True)
class PasswordConfig:
    """Configuration options for password generation."""

    length: int = 16
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = False
    exclude_chars: str = ""


def _build_char_pools(config: PasswordConfig) -> list[str]:
    """Return non-empty character pools matching the configuration."""
    excluded = set(config.exclude_chars)
    if config.exclude_ambiguous:
        excluded.update(AMBIGUOUS_CHARS)

    raw_pools: list[tuple[bool, str, str]] = [
        (config.use_uppercase, "uppercase", string.ascii_uppercase),
        (config.use_lowercase, "lowercase", string.ascii_lowercase),
        (config.use_digits, "digits", string.digits),
        (config.use_symbols, "symbols", SYMBOLS),
    ]

    pools: list[str] = []
    for enabled, name, chars in raw_pools:
        if not enabled:
            continue
        filtered = "".join(ch for ch in chars if ch not in excluded)
        if not filtered:
            raise ValueError(
                f"Character set '{name}' has no remaining characters after exclusions."
            )
        pools.append(filtered)

    if not pools:
        raise ValueError("At least one character set must be enabled.")

    return pools


def generate_password(
    length: int = 16,
    *,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
    exclude_chars: str = "",
) -> str:
    """Generate a single cryptographically secure random password.

    Guarantees at least one character from each enabled character set.
    """
    config = PasswordConfig(
        length=length,
        use_uppercase=use_uppercase,
        use_lowercase=use_lowercase,
        use_digits=use_digits,
        use_symbols=use_symbols,
        exclude_ambiguous=exclude_ambiguous,
        exclude_chars=exclude_chars,
    )
    return generate_password_from_config(config)


def generate_password_from_config(config: PasswordConfig) -> str:
    """Generate a single password using a PasswordConfig instance."""
    if config.length < 1:
        raise ValueError("Password length must be at least 1.")

    pools = _build_char_pools(config)
    if config.length < len(pools):
        raise ValueError(
            f"Password length ({config.length}) must be at least {len(pools)} "
            "to include one character from each selected character set."
        )

    combined_pool = "".join(pools)
    chars = [secrets.choice(pool) for pool in pools]
    remaining = config.length - len(chars)
    chars.extend(secrets.choice(combined_pool) for _ in range(remaining))

    _SYSTEM_RANDOM.shuffle(chars)
    return "".join(chars)


def generate_passwords(count: int = 1, config: PasswordConfig | None = None) -> list[str]:
    """Generate one or more passwords with the given configuration."""
    if count < 1:
        raise ValueError("Count must be at least 1.")
    cfg = config or PasswordConfig()
    return [generate_password_from_config(cfg) for _ in range(count)]


def pool_size_for_config(config: PasswordConfig) -> int:
    """Calculate the total character pool size for a PasswordConfig."""
    pools = _build_char_pools(config)
    return len("".join(pools))


def estimate_pool_size(password: str) -> int:
    """Estimate character pool size from the character classes present in a password."""
    if not password:
        return 0
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += len(string.ascii_lowercase)
    if any(c in string.ascii_uppercase for c in password):
        pool += len(string.ascii_uppercase)
    if any(c in string.digits for c in password):
        pool += len(string.digits)
    if any(c in SYMBOLS for c in password):
        pool += len(SYMBOLS)
    other_chars = {
        c
        for c in password
        if c not in string.ascii_letters and c not in string.digits and c not in SYMBOLS
    }
    pool += len(other_chars)
    return pool


def calculate_entropy(password: str, pool_size: int | None = None) -> float:
    """Calculate Shannon-style brute-force entropy in bits: length * log2(pool_size)."""
    if not password:
        return 0.0
    effective_pool = pool_size if pool_size is not None else estimate_pool_size(password)
    if effective_pool <= 1:
        return 0.0
    return len(password) * math.log2(effective_pool)


def assess_strength(entropy_bits: float) -> str:
    """Map an entropy value in bits to a human-readable strength label."""
    if entropy_bits < 36:
        return "Very Weak"
    if entropy_bits < 60:
        return "Weak"
    if entropy_bits < 80:
        return "Fair"
    if entropy_bits < 100:
        return "Strong"
    return "Very Strong"


def _prompt_yes_no(prompt: str, default: bool = True) -> bool:
    """Prompt user for a yes/no answer in interactive mode."""
    suffix = " [Y/n]: " if default else " [y/N]: "
    raw = input(prompt + suffix).strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes"}


def _interactive_config() -> tuple[PasswordConfig, int, bool]:
    """Collect password generation options interactively from stdin."""
    length_raw = input("Password length [16]: ").strip()
    length = int(length_raw) if length_raw else 16

    count_raw = input("Number of passwords [1]: ").strip()
    count = int(count_raw) if count_raw else 1

    use_upper = _prompt_yes_no("Include uppercase letters (A-Z)?", True)
    use_lower = _prompt_yes_no("Include lowercase letters (a-z)?", True)
    use_digits = _prompt_yes_no("Include digits (0-9)?", True)
    use_symbols = _prompt_yes_no("Include symbols (!@#...)?", True)
    exclude_ambiguous = _prompt_yes_no("Exclude ambiguous characters (0, O, 1, l, I)?", False)
    exclude_chars = input("Any additional characters to exclude (leave blank for none): ")
    show_strength = _prompt_yes_no("Display entropy and strength?", True)

    config = PasswordConfig(
        length=length,
        use_uppercase=use_upper,
        use_lowercase=use_lower,
        use_digits=use_digits,
        use_symbols=use_symbols,
        exclude_ambiguous=exclude_ambiguous,
        exclude_chars=exclude_chars,
    )
    return config, count, show_strength


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Generate cryptographically secure random passwords."
    )
    parser.add_argument(
        "-l",
        "--length",
        type=int,
        default=16,
        help="Password length (default: 16)",
    )
    parser.add_argument(
        "-n",
        "--count",
        type=int,
        default=1,
        help="Number of passwords to generate (default: 1)",
    )
    parser.add_argument(
        "--no-upper",
        action="store_true",
        help="Exclude uppercase letters (A-Z)",
    )
    parser.add_argument(
        "--no-lower",
        action="store_true",
        help="Exclude lowercase letters (a-z)",
    )
    parser.add_argument(
        "--no-digits",
        action="store_true",
        help="Exclude digits (0-9)",
    )
    parser.add_argument(
        "--no-symbols",
        action="store_true",
        help="Exclude symbols",
    )
    parser.add_argument(
        "--exclude-ambiguous",
        action="store_true",
        help="Exclude ambiguous characters (0, O, o, 1, l, I, |)",
    )
    parser.add_argument(
        "--exclude",
        default="",
        help="Specific characters to exclude",
    )
    parser.add_argument(
        "--show-strength",
        action="store_true",
        help="Display estimated entropy (bits) and strength rating",
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Run in interactive prompt mode",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.interactive:
            config, count, show_strength = _interactive_config()
        else:
            config = PasswordConfig(
                length=args.length,
                use_uppercase=not args.no_upper,
                use_lowercase=not args.no_lower,
                use_digits=not args.no_digits,
                use_symbols=not args.no_symbols,
                exclude_ambiguous=args.exclude_ambiguous,
                exclude_chars=args.exclude,
            )
            count = args.count
            show_strength = args.show_strength

        passwords = generate_passwords(count=count, config=config)
        pool_size = pool_size_for_config(config) if show_strength else None
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    for pwd in passwords:
        if show_strength:
            entropy = calculate_entropy(pwd, pool_size=pool_size)
            rating = assess_strength(entropy)
            print(f"{pwd}  [{entropy:.1f} bits - {rating}]")
        else:
            print(pwd)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
