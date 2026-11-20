//! `custos env` output rules (§9): POSIX single-quote escaping plus the
//! hazardous-name deny-set. The refusal itself is server-side; this module is
//! the CLI's own guard for locally-rendered output.

const DENY_EXACT: &[&str] = &[
    "PATH",
    "IFS",
    "BASH_ENV",
    "ENV",
    "PROMPT_COMMAND",
    "CDPATH",
    "SHELL",
    "PS1",
    "GLOBIGNORE",
    "NODE_OPTIONS",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PERL5OPT",
    "RUBYOPT",
];

const DENY_PREFIXES: &[&str] = &["LD_", "DYLD_", "PYTHON"];
const DENY_SUFFIXES: &[&str] = &["_OPT", "_OPTIONS"];

/// Standard POSIX idiom: wrap in single quotes and replace every `'` with
/// `'\''` (close-quote, escaped-quote, reopen-quote).
pub fn escape(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn is_hazardous(name: &str) -> bool {
    if DENY_EXACT.contains(&name) {
        return true;
    }
    if DENY_PREFIXES.iter().any(|p| name.starts_with(p)) {
        return true;
    }
    DENY_SUFFIXES.iter().any(|s| name.ends_with(s))
}

/// Render one `export NAME='value'` line, or a commented refusal.
pub fn line(name: &str, value: &str) -> String {
    if is_hazardous(name) {
        format!("# refused hazardous name: {name}")
    } else {
        format!("export {name}={}", escape(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_the_posix_way() {
        assert_eq!(escape("plain"), "'plain'");
        assert_eq!(escape("a'b"), "'a'\\''b'");
        assert_eq!(escape(""), "''");
    }

    #[test]
    fn hazardous_names_are_refused() {
        for name in [
            "PATH",
            "IFS",
            "LD_PRELOAD",
            "DYLD_X",
            "NODE_OPTIONS",
            "PYTHONPATH",
            "BAKE_OPT",
        ] {
            assert!(is_hazardous(name), "{name} must be hazardous");
        }
        for name in ["API_KEY", "DB_URL", "TOKEN_2", "PATHFINDER"] {
            assert!(!is_hazardous(name), "{name} must be allowed");
        }
    }

    #[test]
    fn refused_lines_are_commented() {
        assert_eq!(line("PATH", "/x"), "# refused hazardous name: PATH");
        assert_eq!(line("API_KEY", "v"), "export API_KEY='v'");
    }

    #[test]
    fn hostile_values_do_not_execute() {
        // The claim in §9: value escaping is what protects eval.
        let marker = std::env::temp_dir().join("custos-cli-eval-pwn");
        let _ = std::fs::remove_file(&marker);
        let hostile = format!("'; touch {}; echo '", marker.display());
        let script = format!("export V={}\nprintf '%s' \"$V\"", escape(&hostile));
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(&script)
            .output()
            .expect("bash");
        assert_eq!(String::from_utf8_lossy(&out.stdout), hostile, "round-trips");
        assert!(!marker.exists(), "no execution");
    }
}
