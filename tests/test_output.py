from totp_batch.cli import render_json, render_plain
from totp_batch.model import GeneratedCode

SINGLE = GeneratedCode(None, "012345", 60, 60, 90)
BATCH = GeneratedCode("alpha", "012345", 60, 60, 90)


def test_plain_single_output_is_code_only() -> None:
    # Given
    codes = (SINGLE,)
    # When
    output = render_plain(codes, batch=False)
    # Then
    assert output == "012345\n"


def test_plain_batch_output_is_label_tab_code() -> None:
    # Given
    codes = (BATCH,)
    # When
    output = render_plain(codes, batch=True)
    # Then
    assert output == "alpha\t012345\n"


def test_json_output_has_version_and_generation_window_metadata() -> None:
    # Given
    codes = (BATCH,)
    # When
    output = render_json(codes)
    # Then
    assert '"schema":"totp-batch/output/v1"' in output
    assert '"generated_at":60' in output
    assert '"window_start":60' in output
    assert '"window_end":90' in output


def test_json_output_contains_no_credential_material() -> None:
    # Given
    forbidden_tokens = ('"secret"', '"fingerprint"', '"input"', '"uri"')
    # When
    output = render_json((BATCH,))
    # Then
    assert all(token not in output for token in forbidden_tokens)
    assert "JBSWY" not in output
