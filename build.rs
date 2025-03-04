//! Build script for lib-core

use std::{env, fs::File, io::Write, path::Path, process::Command};

use anyhow::Result;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    gen_server_version()?;

    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=./proto/metrics.capnp");

    capnpc::CompilerCommand::new()
        .file("./proto/metrics.capnp")
        .output_path("./src")
        .default_parent_module(vec!["proto".to_string()])
        .run()?;

    Ok(())
}

/// Gen server version
fn gen_server_version() -> Result<()> {
    let main_version = env!("CARGO_PKG_VERSION");
    let branch = Command::new("git")
        .args(["branch", "--show-current"])
        .output()
        .map(|o| String::from_utf8(o.stdout).unwrap())
        .unwrap();
    let commit = Command::new("git")
        .args(["describe", "--always"])
        .output()
        .map(|o| String::from_utf8(o.stdout).unwrap())
        .unwrap();
    let release_mode = if cfg!(debug_assertions) || cfg!(test) {
        "DEBUG"
    } else {
        "RELEASE"
    };
    let version =
        format!("{}-{}-{}-{}", main_version, branch, commit, release_mode).replace('\n', "");
    File::create(Path::new(&env::var("OUT_DIR")?).join("VERSION"))?
        .write_all(version.trim().as_bytes())?;

    let now = chrono::Local::now().to_rfc3339();
    File::create(Path::new(&env::var("OUT_DIR")?).join("BUILD_TIME"))?
        .write_all(now.trim().as_bytes())?;

    Ok(())
}
