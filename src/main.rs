use dgruft::backend::salt;

fn main() {
    println!("{}", salt::gen_salt_u32());
}
