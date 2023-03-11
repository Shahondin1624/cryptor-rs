#![feature(iter_collect_into)]

mod args;
mod encryption;

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};
use clap::Parser;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use walkdir::{DirEntry, WalkDir};
use args::{CryptorArguments, CryptorArgumentsWithPassword};
use crate::args::CryptMode;
use crate::encryption::{encrypt_file, decrypt_file};

fn main() {
    let args = CryptorArguments::parse();
    println!("Type in the password you want to use for the operation");
    let password = rpassword::read_password().unwrap();
    println!("Repeat the password to ensure there are no typos");
    let password_check = rpassword::read_password().unwrap();
    if !password.eq(&password_check) {
        panic!("The passwords did not match!");
    }
    println!("root_file: {}\nencryption_mode: {}", args.root_file_path, args.mode);
    let args = CryptorArgumentsWithPassword::from(args, password);
    let mode = args.mode.clone();
    match iterate_over_file_tree(args) {
        None => { println!("Could not perform {}-operation", mode) }
        Some(duration) => { println!("Whole {}-operation took {:?}", mode, duration) }
    }
}

fn iterate_over_file_tree(args: CryptorArgumentsWithPassword) -> Option<Duration> {
    let path = args.file_path();
    if !can_manipulate(path) {
        println!("Can't access the specified path {}", &args.root_file_path);
        return None;
    }
    println!("Beginning to scan all files...");
    let mut operable_files: Vec<DirEntry> = Vec::new();
    WalkDir::new(path).into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter(|e| {
            if can_manipulate(e.path()) {
                true
            } else {
                println!("Could not perform {} for {} as file is read-only", args.mode, e.path().to_string_lossy());
                false
            }
        })
        .collect_into(&mut operable_files);
    println!("Found {} files eligible for {}", operable_files.len(), &args.mode);
    Some(perform_operation_on_files(args, &mut operable_files))
}

fn perform_operation_on_files(args: CryptorArgumentsWithPassword, operable_files: &mut Vec<DirEntry>) -> Duration {
    let start_time = Instant::now();

    operable_files.par_iter().for_each(|entry| {
        let path = entry.path().to_string_lossy().to_string();
        match args.mode {
            CryptMode::Encryption => {
                match encrypt_file(&path, &args.password) {
                    Ok(_) => {}
                    Err(err) => { println!("Could not perform encryption for {} because {}", &path, err) }
                }
            }
            CryptMode::Decryption => {
                match decrypt_file(&path, &args.password) {
                    Ok(_) => {}
                    Err(err) => { println!("Could not perform decryption for {} because {}", &path, err) }
                }
            }
        }
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
