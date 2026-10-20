"""Phase 2 password generator tests: properties, controls, refusal.

The generator's promises are checked as properties over many
samples — lengths exact, switched-off kinds absent, switched-on
kinds present, outputs unique — never by comparing against a
recorded "random" value.
"""

import string

import pytest

from aegis.generator import generate_password

SYMBOLS = set("!@#$%^&*()-_=+[]{}<>?")


def test_default_length_and_all_kinds():
    for _ in range(100):
        pw = generate_password()
        assert len(pw) == 20
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in SYMBOLS for c in pw)


@pytest.mark.parametrize("length", [8, 12, 33, 64, 128])
def test_length_honored(length):
    assert len(generate_password(length)) == length


def test_short_password_still_has_every_kind():
    for _ in range(100):
        pw = generate_password(8)
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in SYMBOLS for c in pw)


def test_digits_off_means_no_digits():
    for _ in range(200):
        pw = generate_password(24, use_digits=False)
        assert not any(c in string.digits for c in pw)


def test_symbols_off_means_no_symbols():
    for _ in range(200):
        pw = generate_password(24, use_symbols=False)
        assert not any(c in SYMBOLS for c in pw)


def test_uppercase_off_means_no_uppercase():
    for _ in range(200):
        pw = generate_password(24, use_uppercase=False)
        assert not any(c in string.ascii_uppercase for c in pw)


def test_lowercase_only():
    for _ in range(200):
        pw = generate_password(
            24, use_uppercase=False, use_digits=False, use_symbols=False
        )
        assert pw.islower() and pw.isalpha()


def test_outputs_are_unique():
    samples = {generate_password() for _ in range(500)}
    assert len(samples) == 500


def test_length_out_of_range_refused():
    with pytest.raises(ValueError):
        generate_password(7)
    with pytest.raises(ValueError):
        generate_password(257)


def test_no_kinds_selected_refused():
    with pytest.raises(ValueError):
        generate_password(
            20,
            use_lowercase=False,
            use_uppercase=False,
            use_digits=False,
            use_symbols=False,
        )


def test_non_integer_length_refused():
    with pytest.raises(TypeError):
        generate_password("20")
    with pytest.raises(TypeError):
        generate_password(True)
