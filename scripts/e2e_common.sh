# Shared log-root hardening for the e2e gates (sourced, never executed).
# The fixed root must be a real directory owned by us, 0700 — otherwise a
# local attacker could rename RUN_DIR and redirect artifacts (and the
# root-privileged chown bind source) into attacker-controlled space.
harden_log_dir() {
  local dir="$1"
  # Race-safe create; a loose-mode directory we own is tightened, not refused;
  # anything owned by someone else (or a symlink) is rejected. GNU stat first,
  # BSD fallback (on GNU, -f means --file-system and would print garbage).
  mkdir -p -m 700 "$dir" 2>/dev/null || true
  if [ -L "$dir" ] || [ ! -d "$dir" ]; then
    echo "refusing unsafe $dir (must be a real directory owned by you; remove it and rerun)" >&2
    return 1
  fi
  local owner mode
  owner="$(stat -c '%u' "$dir" 2>/dev/null || stat -f '%u' "$dir")"
  if [ "$owner" != "$(id -u)" ]; then
    echo "refusing unsafe $dir (owned by another user; remove it as its owner and rerun)" >&2
    return 1
  fi
  mode="$(stat -c '%a' "$dir" 2>/dev/null || stat -f '%Lp' "$dir")"
  if [ "$mode" != "700" ]; then
    chmod 700 "$dir"
    mode="$(stat -c '%a' "$dir" 2>/dev/null || stat -f '%Lp' "$dir")"
    if [ "$mode" != "700" ]; then
      echo "refusing unsafe $dir (must be a 0700 directory)" >&2
      return 1
    fi
  fi
}

# Create + validate the per-run secrets dir (symlink/ownership policy shared
# by every harness; the run dir itself was already hardened above).
make_secrets_dir() {
  python3 - "$1" <<'PYEOF'
import os, sys
run = sys.argv[1]
if os.path.islink(run) or os.path.realpath(run) != os.path.join(
        os.path.realpath(os.path.dirname(run)), os.path.basename(run)):
    sys.exit("refusing symlinked run dir")
os.makedirs(f"{run}/secrets", exist_ok=True)
if os.path.islink(f"{run}/secrets") or os.path.realpath(f"{run}/secrets") != os.path.join(
        os.path.realpath(run), "secrets"):
    sys.exit("refusing symlinked secrets dir")
if os.stat(f"{run}/secrets").st_uid != os.getuid():
    sys.exit("secrets dir is not owned by the running user")
PYEOF
}