"""Test entropy calculation."""

from binscan.utils.entropy import EntropyCalculator


def test_empty_data_returns_zero():
    assert EntropyCalculator.calculate_entropy_for_data(b"") == 0.0


def test_uniform_data_low_entropy():
    data = b"A" * 1000
    entropy = EntropyCalculator.calculate_entropy_for_data(data)
    assert entropy == 0.0


def test_random_data_high_entropy():
    import os
    data = os.urandom(4096)
    entropy = EntropyCalculator.calculate_entropy_for_data(data)
    assert entropy > 7.0


def test_known_two_value():
    data = b"AB" * 500
    entropy = EntropyCalculator.calculate_entropy_for_data(data)
    assert abs(entropy - 1.0) < 0.01