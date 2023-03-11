use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::ops::Add;
use std::time::Instant;
use anyhow::anyhow;
use chacha20poly1305::aead::{OsRng, stream};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use zeroize::Zeroize;

//Source: https://github.com/skerkour/kerkour.com/blob/main/blog/2022/rust_file_encryption_with_password/src/main.rs
pub fn encrypt_file(input_file_path: &String, password: &String) -> anyhow::Result<u128> {
    let start_time = Instant::now();
    let password = password.as_bytes();

    let output_file_path = derive_output_file_path(input_file_path);

    let argon2_config = argon2_config();
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = argon2::hash_raw(password, &salt, &argon2_config)?;

    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];

    let mut input_file = File::open(input_file_path)?;
    let mut output_file = File::create(&output_file_path)?;

    output_file.write(&salt)?;
    output_file.write(&nonce)?;

    loop {
        let read_count = input_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            output_file.write(&ciphertext)?;
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            output_file.write(&ciphertext)?;
            break;
        }
    }

    replace_old_file_with_temp(&input_file_path, &output_file_path)
        .map_err(|err| anyhow!("Replacing the old file with temporary file: {}", err))?;

    salt.zeroize();
    nonce.zeroize();
    key.zeroize();

    let duration = start_time.elapsed();
    Ok(duration.as_millis())
}

pub(crate) fn decrypt_file(input_file_path: &String, password: &String) -> Result<u128, anyhow::Error> {
    let start_time = Instant::now();
    let output_file_path = derive_output_file_path(input_file_path);
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];

    let mut encrypted_file = File::open(&input_file_path)?;
    let mut output_file = File::create(&output_file_path)?;

    let mut read_count = encrypted_file.read(&mut salt)?;
    if read_count != salt.len() {
        return Err(anyhow!("Error reading salt."));
    }

    read_count = encrypted_file.read(&mut nonce)?;
    if read_count != nonce.len() {
        return Err(anyhow!("Error reading nonce."));
    }

    let argon2_config = argon2_config();

    let mut key = argon2::hash_raw(password.as_bytes(), &salt, &argon2_config)?;

    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500 + 16;
    let mut buffer = [0u8; BUFFER_LEN];

    loop {
        let read_count = encrypted_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            output_file.write(&plaintext)?;
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            output_file.write(&plaintext)?;
            break;
        }
    }
    replace_old_file_with_temp(&input_file_path, &output_file_path)
        .map_err(|err| anyhow!("Replacing the old file with temporary file: {}", err))?;

    salt.zeroize();
    nonce.zeroize();
    key.zeroize();

    let duration = start_time.elapsed();
    Ok(duration.as_millis())
}

fn derive_output_file_path(input_file_path: &String) -> String {
    String::from(input_file_path).add(".temp")
}

fn replace_old_file_with_temp(old_file_path: &String, temp_file_path: &String) -> std::io::Result<()> {
    fs::remove_file(old_file_path)?;
    fs::rename(temp_file_path, old_file_path)
}

fn argon2_config<'a>() -> argon2::Config<'a> {
    argon2::Config {
        variant: argon2::Variant::Argon2id,
        hash_length: 32,
        lanes: 8,
        mem_cost: 16 * 1024,
        time_cost: 8,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::ops::Add;
    use std::path::PathBuf;
    use anyhow::anyhow;
    use crate::encryption::{decrypt_file, derive_output_file_path, encrypt_file, replace_old_file_with_temp};

    #[test]
    fn test_path_derivation() {
        let mut input = String::from("test");
        let result = derive_output_file_path(&input);
        input = input.add(".temp");
        assert_eq!(result, input);
    }

    #[test]
    fn test_replace_file() -> Result<(), anyhow::Error> {
        let first_file_path = get_current_dir_and_join("first_file.txt")?;
        let second_file_path = get_current_dir_and_join("second_file.txt")?;

        let contents = "second_file";

        create_file(&first_file_path, "first_file".to_string())?;
        create_file(&second_file_path, contents.to_string())?;

        replace_old_file_with_temp(&first_file_path, &second_file_path)?;

        let text = fs::read_to_string(&first_file_path)?;

        assert_eq!(contents, text);
        delete_file(&first_file_path);
        delete_file(&second_file_path);
        Ok(())
    }

    fn get_current_dir() -> anyhow::Result<PathBuf> {
        std::env::current_dir().map_err(|err| anyhow!(err))
    }

    #[test]
    fn test_cryptor_operations() -> anyhow::Result<()> {
        let contents = "Hello World";
        let file_path = get_current_dir_and_join("data.txt")?;
        create_file(&file_path, contents.to_string())?;
        let password = "password".to_string();

        encrypt_file(&file_path, &password)?;

        decrypt_file(&file_path, &password)?;

        let decrypted = fs::read_to_string(&file_path)?;

        assert_eq!(contents, decrypted);

        delete_file(&file_path);

        Ok(())
    }

    fn create_file(file_path: &String, contents: String) -> anyhow::Result<File> {
        let mut file = File::create(file_path)?;
        file.write_all(&contents.as_bytes())?;
        Ok(file)
    }

    fn get_current_dir_and_join(suffix: &str) -> anyhow::Result<String> {
        let dir = get_current_dir()?;
        Ok(String::from(dir.join(suffix).to_string_lossy()))
    }

    fn delete_file(path: &String) {
        match fs::remove_file(path) {
            Ok(_) => {}
            Err(err) => { println!("Could not delete file {}", err) }
        }
    }
}