use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::ops::Add;
use std::time::{Duration, Instant};
use anyhow::anyhow;
use argon2::Config;
use chacha20poly1305::aead::{OsRng, stream};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use log::trace;
use zeroize::Zeroize;

//Source: https://github.com/skerkour/kerkour.com/blob/main/blog/2022/rust_file_encryption_with_password/src/main.rs
pub fn encrypt_file(input_file_path: &String, password: &String, argon2_config: &Config) -> anyhow::Result<Duration> {
    let start_time = Instant::now();
    let password = password.as_bytes();

    let output_file_path = derive_output_file_path(input_file_path);
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    trace!("Generated random salt and nonce");
    let mut key = argon2::hash_raw(password, &salt, argon2_config)?;
    trace!("Derived key from password and salt");
    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());
    trace!("Initialized stream encryptor");
    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];

    let mut input_file = File::open(input_file_path)?;
    let mut output_file = File::create(&output_file_path)?;
    trace!("Created temporary file {}", &output_file_path);
    output_file.write(&salt)?;
    output_file.write(&nonce)?;
    trace!("Wrote salt and nonce to temporary file");
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
    trace!("Finished encrypting data stream");
    replace_old_file_with_temp(&input_file_path, &output_file_path)
        .map_err(|err| anyhow!("Replacing the old file with temporary file: {}", err))?;
    trace!("Removed temporary file");
    salt.zeroize();
    nonce.zeroize();
    key.zeroize();
    trace!("Zeroized salt, nonce and key");
    Ok(start_time.elapsed())
}

pub(crate) fn decrypt_file(input_file_path: &String, password: &String, argon2_config: &Config) -> anyhow::Result<Duration> {
    let start_time = Instant::now();
    let output_file_path = derive_output_file_path(input_file_path);
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];

    let mut encrypted_file = File::open(&input_file_path)?;
    let mut output_file = File::create(&output_file_path)?;
    trace!("Created temporary file {}", &output_file_path);
    let mut read_count = encrypted_file.read(&mut salt)?;
    if read_count != salt.len() {
        return Err(anyhow!("Error reading salt."));
    }
    trace!("Read salt bytes from file");
    read_count = encrypted_file.read(&mut nonce)?;
    if read_count != nonce.len() {
        return Err(anyhow!("Error reading nonce."));
    }
    trace!("Read nonce bytes from file");
    let mut key = argon2::hash_raw(password.as_bytes(), &salt, argon2_config)?;
    trace!("Derived key from password and salt");
    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());
    trace!("Initialized stream decryptor");
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
    trace!("Finished decrypting data stream");
    replace_old_file_with_temp(&input_file_path, &output_file_path)
        .map_err(|err| anyhow!("Replacing the old file with temporary file: {}", err))?;
    trace!("Removed temporary file");
    salt.zeroize();
    nonce.zeroize();
    key.zeroize();
    trace!("Zeroized salt, nonce and key");
    Ok(start_time.elapsed())
}

fn derive_output_file_path(input_file_path: &String) -> String {
    String::from(input_file_path).add(".temp")
}

fn replace_old_file_with_temp(old_file_path: &String, temp_file_path: &String) -> std::io::Result<()> {
    fs::remove_file(old_file_path)?;
    fs::rename(temp_file_path, old_file_path)
}

pub fn argon2_config<'a>() -> Config<'a> {
    Config {
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
    use std::sync::Once;
    use anyhow::anyhow;
    use env_logger::Builder;
    use log::{debug, error, info, LevelFilter, trace};
    use crate::encryption::{argon2_config, decrypt_file, derive_output_file_path, encrypt_file, replace_old_file_with_temp};

    const INIT: Once = Once::new();

    #[test]
    fn test_path_derivation() {
        let mut input = String::from("test");
        let result = derive_output_file_path(&input);
        input = input.add(".temp");
        assert_eq!(result, input);
    }

    #[test]
    fn test_replace_file() -> Result<(), anyhow::Error> {
        init_logger();
        let first_file_path = get_current_dir_and_join("first_file.txt")?;
        let second_file_path = get_current_dir_and_join("second_file.txt")?;
        trace!("First file path: {}", &first_file_path);
        trace!("Second file path: {}", &second_file_path);
        let contents = "second_file";
        create_file(&first_file_path, "first_file".to_string())?;
        create_file(&second_file_path, contents.to_string())?;
        debug!("Created test files");
        replace_old_file_with_temp(&first_file_path, &second_file_path)?;
        debug!("Replaced first file with temporary file");
        let text = fs::read_to_string(&first_file_path)?;
        trace!("Contents of file: '{}'", &text);
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
        init_logger();
        let contents = "Hello World";
        let file_path = get_current_dir_and_join("data.txt")?;
        trace!("Test file path: {}", &file_path);
        create_file(&file_path, contents.to_string())?;
        debug!("Created test file");
        let password = "password".to_string();
        let argon2config = argon2_config();
        trace!("Attempting to encrypt the test file...");
        let duration = encrypt_file(&file_path, &password, &argon2config).unwrap();
        debug!("Encrypted the test file in {:?}", duration);
        trace!("Attempting to decrypt the test file...");
        let duration = decrypt_file(&file_path, &password, &argon2config).unwrap();
        debug!("Decrypted the test file in {:?}", duration);
        let decrypted = fs::read_to_string(&file_path)?;
        trace!("Decrypted contents are: '{}'", &decrypted);
        assert_eq!(contents, decrypted);
        delete_file(&file_path);
        Ok(())
    }

    fn create_file(file_path: &String, contents: String) -> anyhow::Result<File> {
        let mut file = File::create(file_path)?;
        file.write_all(&contents.as_bytes())?;
        trace!("Wrote '{}' to {}", contents, file_path);
        Ok(file)
    }

    fn get_current_dir_and_join(suffix: &str) -> anyhow::Result<String> {
        let dir = get_current_dir()?;
        Ok(String::from(dir.join(suffix).to_string_lossy()))
    }

    fn delete_file(path: &String) {
        match fs::remove_file(path) {
            Ok(_) => { debug!("Deleted file {}", path); }
            Err(err) => { error!("Could not delete file {}", err) }
        }
    }

    fn init_logger() {
        INIT.call_once(|| {
            let _ = Builder::new().is_test(true).filter_level(LevelFilter::Trace).try_init();
            info!("Initialized logger");
        })
    }
}