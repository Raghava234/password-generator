# Random Password Generator

A cryptographically secure random password generator written in Python using the standard library `secrets` module.

## Features

- Uses Python's `secrets` module (CSPRNG) and `secrets.SystemRandom` shuffling
- Guarantees at least one character from each enabled character class
- Configurable length and batch generation count
- Toggle uppercase, lowercase, digits, and symbols independently
- Option to exclude ambiguous characters (`0`, `O`, `o`, `1`, `l`, `I`, `|`) or custom characters
- Entropy calculation (in bits) and password strength rating
- Both CLI flags and interactive prompt mode
- Zero external dependencies (Python 3.10+)

## Usage

### Web Frontend

Start the local web server and open `http://127.0.0.1:8000` in your browser:

```bash
python server.py
```

### Command Line

Generate a default 16-character password:

```bash
python password_generator.py
```

Generate 5 passwords of length 24, excluding ambiguous characters, and display strength:

```bash
python password_generator.py -l 24 -n 5 --exclude-ambiguous --show-strength
```

Generate an alphanumeric-only password (no symbols):

```bash
python password_generator.py -l 12 --no-symbols
```

Run in interactive mode:

```bash
python password_generator.py --interactive
```

### Python API

```python
from password_generator import generate_password, calculate_entropy, assess_strength

password = generate_password(length=20, exclude_ambiguous=True)
entropy = calculate_entropy(password)
print(password, f"{entropy:.1f} bits", assess_strength(entropy))
```

## Running Tests

```bash
python -m unittest discover -s tests -v
```
