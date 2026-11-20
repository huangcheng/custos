"""Env export (design §9): POSIX single-quote escaping + hazardous-name refusal.

The eval-safety claim covers value escaping only. Hazardous names are a
best-effort foot-gun guard: on the agent plane they are ALWAYS commented
out (the override flag is operator-plane only, §6). Output bound 4 MiB.
"""

from __future__ import annotations

import re

from custos.errors import AppError
from custos.limits import FieldView

ENV_OUTPUT_MAX = 4 * 1024 * 1024

_HAZARD_EXACT = frozenset(
    {"PATH", "IFS", "BASH_ENV", "ENV", "PROMPT_COMMAND", "CDPATH", "SHELL", "PS1",
     "GLOBIGNORE", "NODE_OPTIONS", "PYTHONPATH", "PYTHONSTARTUP", "PERL5OPT", "RUBYOPT"}
)
_HAZARD_PATTERNS = re.compile(r"^(LD_.*|DYLD_.*|.*_OPT|.*_OPTIONS|PYTHON.*)\Z")


def _hazardous(name: str) -> bool:
    return name in _HAZARD_EXACT or _HAZARD_PATTERNS.match(name) is not None


def _escape(value: str) -> str:
    # standard POSIX idiom: close-quote, escaped-quote, reopen-quote
    return "'" + value.replace("'", "'\\''") + "'"


def env_lines(fields: list[FieldView], allow_hazardous: bool = False) -> str:
    """Hazardous names are refused unless the ADMIN plane explicitly overrides
    (step-up/allow_sensitive gated at the route; agent plane never passes True)."""
    lines: list[str] = []
    for f in sorted(fields, key=lambda f: f.name):
        if _hazardous(f.name) and not allow_hazardous:
            lines.append(f"# refused hazardous name: {f.name}")
        else:
            lines.append(f"export {f.name}={_escape(f.value)}")
    output = "\n".join(lines) + ("\n" if lines else "")
    if len(output.encode()) > ENV_OUTPUT_MAX:
        raise AppError("payload_too_large", "env output exceeds 4 MiB")
    return output
