# runas-rs 🦀

![Rust](https://img.shields.io/badge/made%20with-Rust-red)
![crate](https://img.shields.io/crates/v/runas-rs.svg)
![docs](https://docs.rs/runas-rs/badge.svg)
![Forks](https://img.shields.io/github/forks/joaoviictorti/runas-rs)
![Stars](https://img.shields.io/github/stars/joaoviictorti/runas-rs)
![License](https://img.shields.io/github/license/joaoviictorti/runas-rs)

An offensive version of `runas` in Rust with extra features for security testing and red teaming operations.
As a security researcher, I've found this tool incredibly valuable for a fork. This is a fork of the original repository that continues to build upon the solid foundation laid by Victor. His expertise in Windows internals and offensive security tooling in Rust is impressive lmao..

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Core Features](#core-features)
   - [Process Creation and Management](#process-creation-and-management)
   - [Token Manipulation](#token-manipulation)
   - [Process Injection](#process-injection)
   - [Memory Manipulation](#memory-manipulation)
   - [Process Monitoring and Hooking](#process-monitoring-and-hooking)
   - [Process Isolation and Sandboxing](#process-isolation-and-sandboxing)
4. [CLI Usage](#cli-usage)
5. [Security Considerations](#security-considerations)
6. [References](#references)
7. [Contributing](#contributing)
8. [License](#license)

## Introduction

This crate provides both a CLI and a Rust crate for spawning processes under different Windows user accounts, with support for privileges, secure token manipulation, profile/environment loading, and more. It's designed for security testing and red teaming operations.

## Installation

Add `runas-rs` to your project by updating your `Cargo.toml`:

```powershell
cargo add runas-rs
```

## Core Features

### Process Creation and Management

The library provides advanced process creation and management capabilities:

```rust
use runas_rs::{Runas, Options};
use anyhow::Result;

fn main() -> Result<()> {
    let output = Runas::new("username", "password", Some("DOMAIN"))
        .options(Options::Env | Options::Profile)?
        .run("cmd.exe /c whoami")?;

    println!("Output: {}", output);
    Ok(())
}
```

Available process creation options:
- `Options::Env` - Use current user's environment
- `Options::Profile` - Load full user profile
- `Options::NoProfile` - Skip profile loading
- `Options::NetOnly` - Remote access only
- `Options::NewConsole` - New console window
- `Options::NewProcessGroup` - New process group
- `Options::NewWindow` - New window
- `Options::Suspended` - Create suspended
- `Options::DebugProcess` - Debug flag
- `Options::DebugOnlyThisProcess` - Debug child processes
- `Options::ProtectedProcess` - Protected process flag

### Token Manipulation

Comprehensive token manipulation capabilities:

```rust
use runas_rs::Token;
use anyhow::Result;

fn main() -> Result<()> {
    // Check integrity level
    let level = Token::integrity_level()?;
    println!("Integrity Level: {}", level);

    // Check privileges
    if Token::has_privilege("SeAssignPrimaryTokenPrivilege")? {
        println!("Privilege available");
    }

    // Enable privilege
    if Token::enable_privilege("SeImpersonatePrivilege")? {
        println!("Privilege enabled");
    }

    Ok(())
}
```

### Process Injection

Multiple injection techniques supported:

```rust
use runas_rs::{ProcessInjector, InjectionConfig, InjectionTechnique};
use anyhow::Result;

fn main() -> Result<()> {
    let config = InjectionConfig {
        pid: 1234,
        technique: InjectionTechnique::CreateRemoteThread,
        shellcode: vec![0x90, 0x90, 0x90],
        wait_for_completion: true,
        stealth_mode: false,
    };
    
    ProcessInjector::inject(&config)?;
    Ok(())
}
```

Available injection techniques:
- CreateRemoteThread
- NtMapViewOfSection
- QueueUserAPC
- SetWindowsHookEx
- Process Hollowing

### Memory Manipulation

Advanced memory manipulation capabilities:

```rust
use runas_rs::ProcessMemory;
use anyhow::Result;

fn main() -> Result<()> {
    let process_handle = ProcessMemory::open_process(1234, PROCESS_ALL_ACCESS)?;
    
    // Allocate memory
    let address = ProcessMemory::allocate_memory(process_handle, 1024, MemoryProtection::ReadWrite)?;
    
    // Write data
    let data = vec![0x90, 0x90, 0x90];
    ProcessMemory::write_bytes(process_handle, address, &data)?;
    
    // Read data
    let read_data = ProcessMemory::read_bytes(process_handle, address, 3)?;
    
    Ok(())
}
```

### Process Monitoring and Hooking

Comprehensive monitoring and hooking capabilities:

```rust
use runas_rs::{ProcessMonitor, HookType};
use anyhow::Result;

fn main() -> Result<()> {
    let mut monitor = ProcessMonitor::new(1234)?;
    
    // Install hook
    let hook_bytes = vec![0x90, 0x90, 0x90];
    monitor.install_hook(HookType::Inline, 0x12345678, &hook_bytes)?;
    
    // Monitor memory
    let memory_info = monitor.get_memory_info(0x12345678)?;
    
    Ok(())
}
```

Available hook types:
- Inline Hooking
- IAT Hooking
- EAT Hooking
- VEH Hooking
- Trampoline Hooking
- Hotpatch Hooking
- Hardware Breakpoint Hooking

### Process Isolation and Sandboxing

Job object and sandboxing capabilities:

```rust
use runas_rs::{JobObject, JobLimit, JobUIRestriction};
use anyhow::Result;

fn main() -> Result<()> {
    let job_object = JobObject::new()?;
    
    // Set limits
    job_object.set_limits(&[
        JobLimit::BreakawayOk,
        JobLimit::DieOnUnhandledException,
        JobLimit::KillOnJobClose,
    ])?;
    
    // Set UI restrictions
    job_object.set_ui_restrictions(&[
        JobUIRestriction::Desktop,
        JobUIRestriction::DisplaySettings,
    ])?;
    
    Ok(())
}
```

## CLI Usage

The CLI binary provides command-line access to core functionality:

```cmd
C:\> runas.exe -u joao -p joao -c "whoami" --profile
desktop-34dc0j2\joao
```

CLI Options:
- `-u <USERNAME>` - Username
- `-p <PASSWORD>` - Password
- `-d, --domain <DOMAIN>` - Domain (optional)
- `-c, --command <COMMAND>` - Command to execute
- `-e` - Use current environment
- `--profile` - Load user profile
- `--noprofile` - Skip profile loading
- `--netonly` - Remote access only
- `--new-console` - New console window
- `--new-process-group` - New process group
- `--new-window` - New window
- `--suspended` - Create suspended
- `--debug-process` - Debug flag
- `--debug-only-this-process` - Debug child processes
- `--protected-process` - Protected process flag


## References

Special thanks to:
- [@joaoviictorti](https://github.com/joaoviictorti) for creating this outstanding project. 
- [Pavel - CreateProcessAsUser vs. CreateProcessWithTokenW](https://www.youtube.com/watch?v=y42BsQJhd5w&t=816s)
- [Pavel - Window Stations and Desktops](https://scorpiosoftware.net/2023/06/20/window-stations-and-desktops/)
- [RunasCs](https://github.com/antonioCoco/RunasCs)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the [**GPL-3.0 license**](/LICENSE).
