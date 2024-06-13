use rand::Rng;

// Generate a random 32 bit integer for use as a salt.
pub fn gen_salt_u32() -> u32 {
    let mut rng = rand::thread_rng();
    rng.gen()
}
