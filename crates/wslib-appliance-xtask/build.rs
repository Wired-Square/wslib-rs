//! Stamps the commit this tool was built from, when built from a checkout, into
//! `--version`, and never into a rendered file, which would then drift.

fn main() {
    wslib_build_id::emit();
    // The templates are `include_str!`-ed from outside `src`, which `emit`
    // watches, so an edited one must re-run this to mark the build dirty.
    println!("cargo:rerun-if-changed=templates");
}
