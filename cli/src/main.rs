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
    
    /// Create the process with a new console window
    #[arg(long = "new-console")]
    new_console: bool,
    
    /// Create the process with a new process group
    #[arg(long = "new-process-group")]
    new_process_group: bool,
    
    /// Create the process with a new window
    #[arg(long = "new-window")]
    new_window: bool,
    
    /// Create the process with a suspended main thread
    #[arg(long)]
    suspended: bool,
    
    /// Create the process with a debug flag
    #[arg(long = "debug-process")]
    debug_process: bool,
    
    /// Create the process with a debug flag for child processes
    #[arg(long = "debug-only-this-process")]
    debug_only_this_process: bool,
    
    /// Create the process with a protected process flag
    #[arg(long = "protected-process")]
    protected_process: bool,
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
    
    // Process creation options
    if args.new_console {
        options = options | Options::NewConsole;
    }
    if args.new_process_group {
        options = options | Options::NewProcessGroup;
    }
    if args.new_window {
        options = options | Options::NewWindow;
    }
    if args.suspended {
        options = options | Options::Suspended;
    }
    if args.debug_process {
        options = options | Options::DebugProcess;
    }
    if args.debug_only_this_process {
        options = options | Options::DebugOnlyThisProcess;
    }
    if args.protected_process {
        options = options | Options::ProtectedProcess;
    }

    let mut runas = Runas::new(&args.username, &args.password, args.domain.as_deref())
        .options(options)?;

    match runas.run(&args.command) {
        Ok(output) => print!("{}", output),
        Err(e) => println!("{}", e),
    }

    Ok(())
}
