use shadow_rs::SdResult;
use std::io::Write;

fn main() -> SdResult<()> {
    shadow_rs::new_hook(const_hook)
}

fn const_hook(mut f: &std::fs::File) -> SdResult<()> {
    let gen_func: &str = r##"pub const CRYPTO_CTX: &str = shadow_rs::formatcp!("SSH_NG_CTX_{BUIlD_TIME_3339}_{RUST_VERSION}");"##;
    writeln!(f, "{gen_func}")?;
    Ok(())
}
