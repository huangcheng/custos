"""Env export contract (design §9): POSIX escaping, hazardous-name refusal."""

import shutil
import subprocess

import pytest

from custos.envexport import env_lines
from custos.errors import AppError
from custos.limits import FieldView


def fv(name: str, value: str) -> FieldView:
    return FieldView(name=name, secret=True, value=value)


ADVERSARIAL = [
    "'; cmd; echo '",
    "line1\nline2",
    "$(touch /tmp/custos-pwn-test)",
    "`touch /tmp/custos-pwn-test`",
    "a'b'c",
    "'\"\\$HOME",
    "semi;colon && echo pwned",
]


@pytest.mark.parametrize("value", ADVERSARIAL)
def test_eval_roundtrip_no_execution(value: str, tmp_path) -> None:
    marker = tmp_path / "pwn"
    expected = value.replace("/tmp/custos-pwn-test", str(marker))  # noqa: S108
    lines = env_lines([fv("TEST_VALUE", expected)])
    script = lines + '\nprintf %s "$TEST_VALUE"'
    bash = shutil.which("bash")
    assert bash is not None
    result = subprocess.run(  # noqa: S603 — fixed argv, the corpus IS the test
        [bash, "-c", script], capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 0
    assert result.stdout == expected
    assert not marker.exists()


def test_hazardous_names_commented_unconditionally() -> None:
    fields = [fv("PATH", "/evil"), fv("LD_PRELOAD", "/evil.so"), fv("NODE_OPTIONS", "--x"),
              fv("PYTHONPATH", "/evil"), fv("MY_OPT", "x"), fv("SAFE_NAME", "ok")]
    lines = env_lines(fields)  # unconditional refusal
    active = [ln for ln in lines.splitlines() if ln.startswith("export ")]
    assert active == ["export SAFE_NAME='ok'"]
    assert "# refused hazardous name: PATH" in lines


def test_output_bound(monkeypatch) -> None:
    # unreachable for legal items (256 KiB x 4); shrink the bound to test the
    # defensive assertion itself
    import custos.envexport as ee

    monkeypatch.setattr(ee, "ENV_OUTPUT_MAX", 16)
    with pytest.raises(AppError) as e:
        env_lines([fv("K", "'" * 16)])
    assert e.value.code == "payload_too_large"
