//! Locks in which minimum-publish-age configuration sources isolated candidate resolution sees.
//! A fake Cargo records its environment and working directory for both the isolated candidate
//! run and the final downstream run, so a refactor cannot silently drop env inheritance or the
//! copy of the project's `.cargo/config.toml`. No network or real Cargo is used.
//! This file holds a single test because it mutates the process environment.

use cargo_wrapper_supply_chain_guard::candidate::resolve_candidate;
use cargo_wrapper_supply_chain_guard::cargo_runner::{DirectCargoRunner, DownstreamRunner};
use cargo_wrapper_supply_chain_guard::command_policy::classify;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const AGE_VARIABLE: &str = "CARGO_REGISTRY_GLOBAL_MIN_PUBLISH_AGE";
const AGE_VALUE: &str = "30 days";
const PROJECT_CONFIG: &str = "[registry]\nglobal-min-publish-age = \"30 days\"\n";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "supply-chain-guard-age-visibility-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn compile_fake_cargo(directory: &Path) -> PathBuf {
    let source = directory.join("fake_cargo.rs");
    let executable = directory.join(format!("fake_cargo{}", env::consts::EXE_SUFFIX));
    fs::write(
        &source,
        r#"
use std::{env, fs, io::Write};

fn main() {
    let cwd = env::current_dir().unwrap();
    let config = fs::read_to_string(cwd.join(".cargo/config.toml")).unwrap_or_else(|_| "MISSING".to_owned());
    let record = format!(
        "cargo_home={}\nage={}\ncwd={}\nconfig={}\n---\n",
        env::var("CARGO_HOME").unwrap_or_else(|_| "UNSET".to_owned()),
        env::var("CARGO_REGISTRY_GLOBAL_MIN_PUBLISH_AGE").unwrap_or_else(|_| "UNSET".to_owned()),
        cwd.display(),
        config.replace('\n', "\\n"),
    );
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(env::var_os("AGE_VISIBILITY_RECORD").unwrap())
        .unwrap();
    file.write_all(record.as_bytes()).unwrap();
    fs::write(cwd.join("Cargo.lock"), "version = 4\n").unwrap();
}
"#,
    )
    .unwrap();
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc)
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    executable
}

fn field<'a>(record: &'a str, name: &str) -> &'a str {
    record
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("record has no {name}: {record}"))
}

#[test]
fn candidate_and_final_resolution_see_the_same_age_policy() {
    let directory = TestDirectory::new();
    let fake = compile_fake_cargo(&directory.0);
    let record_path = directory.0.join("record");
    let project = directory.0.join("project");
    fs::create_dir_all(project.join(".cargo")).unwrap();
    fs::write(project.join(".cargo/config.toml"), PROJECT_CONFIG).unwrap();
    fs::write(
        project.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    let project = project.canonicalize().unwrap();

    // Safe here: this is the only test in this integration-test process.
    unsafe {
        env::set_var(AGE_VARIABLE, AGE_VALUE);
        env::set_var("AGE_VISIBILITY_RECORD", &record_path);
    }

    let args = vec!["forcegenerate-lockfile".to_owned()];
    let invocation = classify(&args).expect("forcegenerate-lockfile is classified");
    let candidate = resolve_candidate(
        &DirectCargoRunner::new(fake.clone()),
        &project,
        &project,
        &args,
        &invocation,
    )
    .unwrap();
    DownstreamRunner::new(fake)
        .run(&["generate-lockfile".to_owned()], &project)
        .unwrap();

    let records = fs::read_to_string(&record_path).unwrap();
    let records: Vec<&str> = records
        .split("---\n")
        .filter(|record| !record.trim().is_empty())
        .collect();
    assert_eq!(records.len(), 2, "expected candidate and downstream runs");
    let (isolated, downstream) = (records[0], records[1]);

    // Both runs inherit the environment policy.
    assert_eq!(field(isolated, "age"), AGE_VALUE);
    assert_eq!(field(downstream, "age"), AGE_VALUE);

    // The candidate runs in the private Cargo home and in the copy, with the project config.
    assert_eq!(
        Path::new(field(isolated, "cargo_home")),
        candidate.cargo_home.as_path()
    );
    assert_ne!(
        Path::new(field(downstream, "cargo_home")),
        candidate.cargo_home.as_path()
    );
    let isolated_cwd = Path::new(field(isolated, "cwd")).canonicalize().unwrap();
    assert_eq!(
        isolated_cwd,
        candidate.working_directory.canonicalize().unwrap()
    );
    assert_ne!(isolated_cwd, project);
    let expected_config = PROJECT_CONFIG.replace('\n', "\\n");
    assert_eq!(field(isolated, "config"), expected_config);
    assert_eq!(field(downstream, "config"), expected_config);
}
