// O setor de boot e o stage2 formam uma imagem plana em 0x7C00. O script de
// link fixa esse endereço; o xtask extrai os bytes com llvm-objcopy.
fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg-bins=-T{manifest}/boot.ld");
    println!("cargo:rerun-if-changed=boot.ld");
    println!("cargo:rerun-if-changed=src/boot.s");
    println!("cargo:rerun-if-changed=src/stage2.s");
}
