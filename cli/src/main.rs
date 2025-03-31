use clap::{Parser, ArgGroup};
use runas_rs::{Options, Runas};
use std::error::Error;

/// Runas CLI with extended options for offensive security tasks
#[derive(Parser, Debug)]
#[command(
    name = "runas-rs",
    about = "A runas implementation with extra features in Rust",
    version = "1.0",
    group(
        ArgGroup::new("auth_mode")
            .args(&["profile", "no_profile", "netonly"])
            .required(true)
            .multiple(false)
    )
)]
struct Args {
    /// Username to run the command
    #[arg(short)]
    username: String,

    /// Password for the user
    #[arg(short)]
    password: String,

    /// Domain of the user (optional)
    #[arg(short = 'd', long)]
    domain: Option<String>,

    /// Command to execute as the specified user
    #[arg(short, long)]
    command: String,

    /// Use the environment of the current user
    #[arg(short)]
    env: bool,

    /// Load user profile
    #[arg(long)]
    profile: bool,

    /// Do not load user profile
    #[arg(long = "noprofile")]
    no_profile: bool,

    /// Use credentials for remote access only
    #[arg(long)]
    netonly: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // Handle Options based on args
    let mut options = Options(0);
    if args.env {
        options = options | Options::Env;
    }
    if args.profile {
        options = options | Options::Profile;
    }
    if args.no_profile {
        options = options | Options::NoProfile;
    }
    if args.netonly {
        options = options | Options::NetOnly;
    }

    let mut runas = Runas::new(&args.username, &args.password, args.domain.as_deref())
        .options(options)?;

    match runas.run(&args.command) {
        Ok(output) => print!("{}", output),
        Err(e) => println!("{}", e),
    }

    Ok(())
}
