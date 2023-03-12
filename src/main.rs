#![feature(iter_collect_into)]

use std::env::consts::OS;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use atomic_counter::{AtomicCounter, RelaxedCounter};
use clap::Parser;
use colorful::{Color, Colorful};
use colorful::Color::Green;
use colorful::core::color_string::CString;
use env_logger::Builder;
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use log::{debug, error, info, warn};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use walkdir::{DirEntry, WalkDir};

use args::{CryptorArguments, CryptorArgumentsWithPassword};

use crate::args::CryptMode;
use crate::encryption::{decrypt_file, encrypt_file};

mod args;
mod encryption;

fn main() {
    let args = CryptorArguments::parse();
    print_colorful_when_supported("Type in the password you want to use for the operation", |msg| msg.color(Green));
    let password = rpassword::read_password().unwrap();
    print_colorful_when_supported("Repeat the password to ensure there are no typos", |msg| msg.color(Green));
    let password_check = rpassword::read_password().unwrap();
    if !password.eq(&password_check) {
        panic!("The passwords did not match!");
    }
    let argument_string = format!("root_file: {}\nencryption_mode: {}", args.root_file_path, args.mode);
    let argument_string = argument_string.as_str();
    print_colorful_when_supported(argument_string, |msg| msg.gradient(Color::Red));
    let args = CryptorArgumentsWithPassword::from(args, password);
    Builder::new().filter_level(args.verbose.log_level_filter()).init();
    let mode = args.mode.clone();
    match iterate_over_file_tree(args) {
        None => { error!("Could not perform {}-operation", mode) }
        Some(duration) => {
            let message = format!("Whole {}-operation took {:?}", mode, duration);
            let message = message.as_str();
            print_colorful_when_supported(message, |msg| msg.gradient(Color::Green));
        }
    }
}

fn iterate_over_file_tree(args: CryptorArgumentsWithPassword) -> Option<Duration> {
    let path = args.file_path();
    if !can_manipulate(path) {
        error!("Can't access the specified path {}", &args.root_file_path);
        return None;
    }
    info!("Beginning to scan all files...");
    let mut operable_files: Vec<DirEntry> = Vec::new();
    WalkDir::new(path).into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter(|e| {
            if can_manipulate(e.path()) {
                true
            } else {
                warn!("Could not perform {} for {} as file is read-only", args.mode, e.path().to_string_lossy());
                false
            }
        })
        .collect_into(&mut operable_files);
    info!("Found {} files eligible for {}", operable_files.len(), &args.mode);
    Some(perform_operation_on_files(args, &mut operable_files))
}

fn perform_operation_on_files(args: CryptorArgumentsWithPassword, operable_files: &mut Vec<DirEntry>) -> Duration {
    let start_time = Instant::now();
    info!("Beginning encryption...");
    let argon2_config = encryption::argon2_config();
    let counter = RelaxedCounter::new(0);
    let bar = create_progress_bar(operable_files.len() as u64);
    operable_files.par_iter().progress_with(bar).for_each(|entry| {
        let path = entry.path().to_string_lossy().to_string();
        debug!("{}/{} files already encrypted", counter.get(), operable_files.len());
        match args.mode {
            CryptMode::Encryption => {
                debug!("Attempting to encrypt {}", &path);
                match encrypt_file(&path, &args.password, &argon2_config) {
                    Ok(duration) => { debug!("Finished encrypting {} in {:?}", &path, duration); }
                    Err(err) => { warn!("Could not perform encryption for {} because {}", &path, err) }
                }
            }
            CryptMode::Decryption => {
                debug!("Attempting to decrypt {}", &path);
                match decrypt_file(&path, &args.password, &argon2_config) {
                    Ok(duration) => { debug!("Finished decrypting {} in {:?}", &path, duration); }
                    Err(err) => { warn!("Could not perform decryption for {} because {}", &path, err) }
                }
            }
        }
        counter.inc();
    });
    start_time.elapsed()
}

fn can_manipulate(path: &Path) -> bool {
    let permissions = match fs::metadata(path).map(|metadata| metadata.permissions()) {
        Ok(per) => { per }
        Err(_) => { return false; }
    };
    !permissions.readonly()
}

pub fn is_colorful_supported() -> bool {
    "linux".eq(OS)
}

fn print_colorful_when_supported(message: &str, function: fn(&str) -> CString) {
    if is_colorful_supported() {
        let message = function(message);
        println!("{}", message);
    } else {
        println!("{}", message);
    }
}

fn create_progress_bar(items: u64) -> ProgressBar {
    let bar = ProgressBar::new(items);
    bar.enable_steady_tick(Duration::from_secs(1));
    let style: Option<ProgressStyle> = match ProgressStyle::with_template
        ("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}") {
        Ok(_style) => { Some(_style) }
        Err(_) => {
            debug!("Could not retrieve progress bar style!");
            None
        }
    };
    if style.is_some() {
        let mut style = style.unwrap();
        style = style.progress_chars("##-");
        bar.set_style(style);
    }
    bar
}