/// Z-1.H.11: what a release build carries so a person never types a server address. Each
/// `ZBACS_BUILD_*` set at build time becomes `ZBACS_EMBEDDED_*` inside the binary; a runtime
/// `ZBACS_*` still overrides it on a developer box. Unset or empty means "not embedded".
fn embed() {
    for (build, embedded) in [
        ("ZBACS_BUILD_RELAY_URL", "ZBACS_EMBEDDED_RELAY_URL"),
        ("ZBACS_BUILD_CHAIN_RPC", "ZBACS_EMBEDDED_CHAIN_RPC"),
        ("ZBACS_BUILD_BUNDLER_URL", "ZBACS_EMBEDDED_BUNDLER_URL"),
        ("ZBACS_BUILD_PAYMASTER_POLICY", "ZBACS_EMBEDDED_PAYMASTER_POLICY"),
    ] {
        println!("cargo:rerun-if-env-changed={build}");
        if let Some(value) = std::env::var(build).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
        {
            println!("cargo:rustc-env={embedded}={value}");
        }
    }
    // The deployment file (`deployments/<chainId>.json`, Z-1.H.4) goes in whole, so the
    // addresses the installer talks to are the ones the deployment wrote down.
    println!("cargo:rerun-if-env-changed=ZBACS_BUILD_DEPLOYMENT");
    if let Some(path) =
        std::env::var("ZBACS_BUILD_DEPLOYMENT").ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
    {
        println!("cargo:rerun-if-changed={path}");
        match std::fs::read_to_string(&path) {
            Ok(json) => {
                let one_line: String = json.chars().filter(|c| *c != '\n' && *c != '\r').collect();
                println!("cargo:rustc-env=ZBACS_EMBEDDED_DEPLOYMENT_JSON={one_line}");
            }
            Err(e) => panic!("ZBACS_BUILD_DEPLOYMENT={path}: {e}"),
        }
    }
}

fn main() {
    embed();
    // Rule 8: the UI may only use values from the design tokens, so the stylesheet is copied
    // from the single source instead of being kept as a second copy that can drift.
    let tokens = std::path::Path::new("../../../packages/design-tokens/tokens.css");
    let dest = std::path::Path::new("../ui/tokens.css");
    match std::fs::read(tokens) {
        Ok(css) => {
            std::fs::write(dest, css).expect("copy design tokens into the UI directory");
            println!("cargo:rerun-if-changed=../../../packages/design-tokens/tokens.css");
        }
        Err(e) => panic!("design tokens not found at {}: {e}", tokens.display()),
    }
    tauri_build::build()
}
