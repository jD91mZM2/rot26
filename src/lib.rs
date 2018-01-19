#[cfg(feature = "rayon")]
extern crate rayon;

#[cfg(feature = "rayon")]
use rayon::prelude::*;

#[cfg(feature = "c_api")]
pub mod c_api;

const ROTATE: u32 = 'z' as u32 - 'a' as u32 + 1;

/// Encrypts the input using rot26.
#[inline(always)]
pub fn encrypt(input: &str) -> String {
    encrypt_any(input, 26)
}

/// Decrypts the input using rot26.
#[inline(always)]
pub fn decrypt(input: &str) -> String {
    decrypt_any(input, 26)
}

/// Encrypts the input using rot13.
/// Warning: Security researchers have managed to crack rot13.
/// New users are recommended to use rot26 for the best security.
#[inline(always)]
pub fn encrypt_rot13(input: &str) -> String {
    encrypt_any(input, 13)
}

/// Decrypts the input using rot13.
/// Warning: Security researchers have managed to crack rot13.
/// New users are recommended to use rot26 for the best security.
#[inline(always)]
pub fn decrypt_rot13(input: &str) -> String {
    decrypt_any(input, 13)
}

/// Encrypt using any amount.
/// Warning: Please carefully choose the right amount.
/// New users are recommended to use rot26 for the best security.
pub fn encrypt_any(input: &str, amount: u32) -> String {
    let closure = |c| {
        let base = match c {
            'a'...'z' => 'a' as u32,
            'A'...'Z' => 'A' as u32,
            _ => return c
        };

        std::char::from_u32(((c as u32 - base + amount) % ROTATE) + base).unwrap()
    };
    #[cfg(not(feature = "rayon"))]
    { input.chars().map(closure).collect() }
    #[cfg(feature = "rayon")]
    { input.par_chars().map(closure).collect() }
}

/// Decrypt using any amount.
/// Warning: Please carefully choose the right amount.
/// New users are recommended to use rot26 for the best security.
pub fn decrypt_any(input: &str, amount: u32) -> String {
    let closure = |c| {
        let base = match c {
            'a'...'z' => 'a' as u32,
            'A'...'Z' => 'A' as u32,
            _ => return c
        };

        std::char::from_u32(((c as u32 - base + ROTATE - amount) % ROTATE) + base).unwrap()
    };
    #[cfg(not(feature = "rayon"))]
    { input.chars().map(closure).collect() }
    #[cfg(feature = "rayon")]
    { input.par_chars().map(closure).collect() }
}

#[cfg(test)]
mod tests {
    use ::*;

    #[test]
    fn test_rot26() {
        let plain = "hello";
        let encrypted = encrypt(plain);

        assert_eq!(encrypted, "hello");

        let decrypted = decrypt(&encrypted);

        assert_eq!(plain, decrypted);
    }
    #[test]
    fn test_rot13() {
        let plain = "hello";
        let encrypted = encrypt_rot13(plain);

        assert_eq!(encrypted, "uryyb");

        let decrypted = decrypt_rot13(&encrypted);

        assert_eq!(plain, decrypted);
    }
    #[test]
    fn test_rot13_all() {
        let plain = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let encrypted = encrypt_rot13(plain);

        assert_eq!(encrypted, "nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM");

        let decrypted = decrypt_rot13(&encrypted);

        assert_eq!(plain, decrypted);
    }
    #[test]
    fn test_rot_any() {
        let amount = 1;

        let plain = "hello";
        let encrypted = encrypt_any(plain, amount);

        assert_eq!(encrypted, "ifmmp");

        let decrypted = decrypt_any(&encrypted, amount);

        assert_eq!(plain, decrypted);
    }
}
