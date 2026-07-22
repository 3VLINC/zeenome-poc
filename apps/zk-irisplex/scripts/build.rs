use sp1_build::build_program_with_args;

pub fn main() {
    // Build the program package. The function will automatically detect the package name
    // from program/Cargo.toml (zk-irisplex-program) and set SP1_ELF_irisplex-program
    build_program_with_args("../program", Default::default())
}
