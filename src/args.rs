use std::fmt::{Display, Formatter};
use std::path::Path;
use clap::{Parser};

#[derive(Debug, Parser, Clone)]
#[clap(author = "Shahondin1624", about = "A simple cli-application for en-/decrypting files")]
pub struct CryptorArguments {
    ///The file or root-folder from where to start the crypt-operation
    pub root_file_path: String,
    ///Whether all files should be de-/encrypted
    #[clap(value_enum)]
    pub mode: CryptMode,
    ///Whether the logging should be verbose or not
    #[clap(flatten)]
    pub verbose: clap_verbosity_flag::Verbosity,
}

#[derive(Debug, clap::ValueEnum, Clone, Copy)]
pub enum CryptMode {
    Encryption,
    Decryption,
}

impl Display for CryptMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptMode::Encryption => {
                write!(f, "{}", "encryption")
            }
            CryptMode::Decryption => {
                write!(f, "{}", "decryption")
            }
        }
    }
}

pub struct CryptorArgumentsWithPassword {
    pub root_file_path: String,
    pub mode: CryptMode,
    pub password: String,
    pub verbose: clap_verbosity_flag::Verbosity,
}

impl CryptorArgumentsWithPassword {
    pub fn from(arguments: CryptorArguments, pwd: String) -> CryptorArgumentsWithPassword {
        CryptorArgumentsWithPassword {
            root_file_path: arguments.root_file_path,
            mode: arguments.mode,
            password: pwd,
            verbose: arguments.verbose,
        }
    }

    pub fn file_path(&self) -> &Path {
        get_path(self.root_file_path.as_str())
    }
}

pub fn get_path(path_string: &str) -> &Path {
    let path = Path::new(path_string);
    if !path.exists() {
        panic!("Not a valid path!");
    }
    path
}