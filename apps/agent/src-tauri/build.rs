fn main() {
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
