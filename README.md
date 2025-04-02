
# runas-rs 🦀

![Rust](https://img.shields.io/badge/made%20with-Rust-red)
![crate](https://img.shields.io/crates/v/runas-rs.svg)
![docs](https://docs.rs/runas-rs/badge.svg)
![Forks](https://img.shields.io/github/forks/joaoviictorti/runas-rs)
![Stars](https://img.shields.io/github/stars/joaoviictorti/runas-rs)
![License](https://img.shields.io/github/license/joaoviictorti/runas-rs)

An offensive version of `runas` in Rust with extra features

This crate provides both a CLI and a Rust crate for spawning processes under different Windows user accounts, with support for privileges, secure token manipulation, profile/environment loading, and more.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
    - [Creating and Running a Process as Another User](#creating-and-running-a-process-as-another-user)
    - [Checking Privileges and Token Integrity](#checking-privileges-and-token-integrity)
    - [Token Manipulation and Impersonation](#token-manipulation-and-impersonation)
    - [Process Injection Capabilities](#process-injection-capabilities)
    - [Process Memory Manipulation](#process-memory-manipulation)
    - [Process Token Manipulation](#process-token-manipulation)
    - [Process Suspension and Resumption](#process-suspension-and-resumption)
    - [Available Options](#available-options)
- [CLI](#cli)
    - [CLI Help](#cli-help)
- [References](#references)
- [Contributing to runas-rs](#contributing-to-runas-rs)
- [License](#license)

## Installation

Add `runas-rs` to your project by updating your `Cargo.toml`:

```powershell
cargo add runas-rs
```

## Usage

`runas-rs` offers fine-grained control over user impersonation and process spawning on Windows. It allows you to run commands under different user credentials, while dynamically selecting the most appropriate Windows API for process creation based on current privileges and token integrity.

### Creating and Running a Process as Another User

This crate chooses among `CreateProcessAsUserW`, `CreateProcessWithTokenW`, or `CreateProcessWithLogonW` depending on the privileges and integrity level available to the current process.

| API                        | Required Privilege                   | Required Integrity Level | 
|----------------------------|--------------------------------------|--------------------------|
| `CreateProcessAsUserW`     | `SeAssignPrimaryTokenPrivilege`      | Medium or higher         |
| `CreateProcessWithTokenW`  | `SeImpersonatePrivilege`             | High or System           |
| `CreateProcessWithLogonW`  | _None_                               | Any                      |

Example:

```rs
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

### Checking Privileges and Token Integrity

You can inspect and manipulate the current process token to determine what kind of impersonation is possible.

```rs
use runas_rs::Token;
use anyhow::Result;

fn main() -> Result<()> {
    // Check the current integrity level
    let level = Token::integrity_level()?;
    println!("Integrity Level: {}", level);

    // Check if privileges are available
    if Token::has_privilege("SeAssignPrimaryTokenPrivilege")? {
        println!("Privilege SeAssignPrimaryTokenPrivilege is available.");
    }

    if Token::has_privilege("SeImpersonatePrivilege")? {
        println!("Privilege SeImpersonatePrivilege is available.");
    }

    // Try enabling a privilege manually
    if Token::enable_privilege("SeImpersonatePrivilege")? {
        println!("Privilege SeImpersonatePrivilege successfully enabled.");
    } else {
        println!("Failed to enable SeImpersonatePrivilege.");
    }

    Ok(())
}
```

### Token Manipulation and Impersonation

You can perform advanced token manipulation and impersonation operations:

```rs
use runas_rs::{Token, get_user_sid};
use anyhow::Result;

fn main() -> Result<()> {
    // Get the SID for a user
    let user_sid = get_user_sid("username", "domain")?;
    
    // Impersonate the user by their SID
    Token::impersonate_by_sid(&user_sid)?;
    println!("Successfully impersonated user");
    
    // Perform operations as the impersonated user
    // ...
    
    // Revert impersonation when done
    Token::revert_impersonation()?;
    println!("Successfully reverted impersonation");
    
    // Duplicate a token with specific access rights
    let h_token = Token::duplicate_token(
        TOKEN_ALL_ACCESS,
        SecurityImpersonation,
        TokenPrimary
    )?;
    println!("Successfully duplicated token");
    
    // Get all privileges available in the current token
    let privileges = Token::get_all_privileges()?;
    for privilege in privileges {
        println!("Privilege: {}", privilege);
    }
    
    Ok(())
}
```

### Process Injection Capabilities

`runas-rs` provides a comprehensive set of process injection techniques for security testing and red teaming. The library supports multiple injection methods, each with its own advantages and use cases.

#### Available Injection Techniques

| Technique | Description | Use Case |
|-----------|-------------|----------|
| CreateRemoteThread | Most common and straightforward | General purpose injection |
| NtMapViewOfSection | More advanced technique | When stealth is required |
| QueueUserAPC | Requires suspended thread | For specific thread targeting |
| SetWindowsHookEx | Uses hooks for injection | GUI application injection |
| Process Hollowing | Replaces process image | Advanced process replacement |

#### Basic Shellcode Injection

```rs
use runas_rs::{ProcessInjector, InjectionConfig, InjectionTechnique};
use anyhow::Result;

fn main() -> Result<()> {
    // Create an injection configuration
    let config = InjectionConfig {
        pid: 1234, // Target process ID
        technique: InjectionTechnique::CreateRemoteThread,
        shellcode: vec![0x90, 0x90, 0x90], // NOP sled example
        wait_for_completion: true,
        stealth_mode: false,
    };
    
    // Perform the injection
    ProcessInjector::inject(&config)?;
    
    Ok(())
}
```

#### DLL Injection

```rs
use runas_rs::ProcessInjector;
use anyhow::Result;

fn main() -> Result<()> {
    // Inject a DLL into a process
    ProcessInjector::inject_dll(1234, "C:\\path\\to\\dll.dll")?;
    
    Ok(())
}
```

#### Reflective DLL Injection

```rs
use runas_rs::ProcessInjector;
use anyhow::Result;

fn main() -> Result<()> {
    // Load a DLL from memory without writing to disk
    let shellcode = vec![/* DLL bytes */];
    ProcessInjector::reflective_dll_injection(1234, &shellcode)?;
    
    Ok(())
}
```

#### Advanced Injection Options

The `InjectionConfig` struct provides several options for customizing the injection process:

- `wait_for_completion`: Whether to wait for the injection to complete
- `stealth_mode`: Whether to use techniques to hide the injection from detection

#### Security Considerations

When using process injection capabilities:

1. Ensure you have the necessary permissions to access the target process
2. Be aware of antivirus and security software that may detect injection attempts
3. Use appropriate error handling to manage injection failures
4. Consider the integrity level and privileges of both the source and target processes

### Process Memory Manipulation

`runas-rs` provides comprehensive process memory manipulation capabilities for security testing and red teaming. These features allow you to read, write, and manipulate memory in target processes.

#### Memory Protection

The library supports various memory protection flags:

| Protection | Description |
|------------|-------------|
| ReadOnly | Memory can only be read |
| ReadWrite | Memory can be read and written |
| Execute | Memory can only be executed |
| ExecuteRead | Memory can be read and executed |
| ExecuteReadWrite | Memory can be read, written, and executed |

#### Basic Memory Operations

```rs
use runas_rs::{ProcessMemory, MemoryProtection};
use anyhow::Result;
use windows_sys::Win32::System::Threading::PROCESS_ALL_ACCESS;

fn main() -> Result<()> {
    // Open a process with full access
    let pid = 1234; // Target process ID
    let process_handle = ProcessMemory::open_process(pid, PROCESS_ALL_ACCESS)?;
    
    // Allocate memory in the target process
    let address = ProcessMemory::allocate_memory(
        process_handle,
        1024, // Size in bytes
        MemoryProtection::ReadWrite,
    )?;
    
    // Write data to the allocated memory
    let data = vec![0x90, 0x90, 0x90]; // NOP sled
    ProcessMemory::write_bytes(process_handle, address, &data)?;
    
    // Read data from memory
    let read_data = ProcessMemory::read_bytes(process_handle, address, 3)?;
    println!("Read data: {:?}", read_data);
    
    // Change memory protection
    ProcessMemory::change_protection(
        process_handle,
        address,
        1024,
        MemoryProtection::ExecuteRead,
    )?;
    
    // Free the allocated memory
    ProcessMemory::free_memory(
        process_handle,
        address,
        1024,
        windows_sys::Win32::System::Memory::MEM_RELEASE,
    )?;
    
    Ok(())
}
```

#### Memory Scanning

```rs
use runas_rs::ProcessMemory;
use anyhow::Result;
use windows_sys::Win32::System::Threading::PROCESS_ALL_ACCESS;

fn main() -> Result<()> {
    // Open a process with full access
    let pid = 1234; // Target process ID
    let process_handle = ProcessMemory::open_process(pid, PROCESS_ALL_ACCESS)?;
    
    // Scan for a pattern in memory
    let pattern = vec![0x48, 0x89, 0x5C, 0x24]; // Example pattern
    let mask = vec![1, 1, 1, 1]; // All bytes must match
    
    let results = ProcessMemory::scan_memory(
        process_handle,
        0x00000000, // Start address
        0x7FFFFFFF, // End address
        &pattern,
        &mask,
    )?;
    
    println!("Found pattern at addresses: {:?}", results);
    
    Ok(())
}
```

#### Memory Patching

```rs
use runas_rs::ProcessMemory;
use anyhow::Result;
use windows_sys::Win32::System::Threading::PROCESS_ALL_ACCESS;

fn main() -> Result<()> {
    // Open a process with full access
    let pid = 1234; // Target process ID
    let process_handle = ProcessMemory::open_process(pid, PROCESS_ALL_ACCESS)?;
    
    // Patch memory at a specific address
    let address = 0x12345678; // Target address
    let patch = vec![0x90, 0x90]; // NOP instructions
    
    ProcessMemory::patch_memory(process_handle, address, &patch)?;
    
    Ok(())
}
```

#### Memory Dumping

```rs
use runas_rs::ProcessMemory;
use anyhow::Result;
use windows_sys::Win32::System::Threading::PROCESS_ALL_ACCESS;

fn main() -> Result<()> {
    // Open a process with full access
    let pid = 1234; // Target process ID
    let process_handle = ProcessMemory::open_process(pid, PROCESS_ALL_ACCESS)?;
    
    // Dump a region of memory to a file
    ProcessMemory::dump_memory(
        process_handle,
        0x00400000, // Start address
        1024 * 1024, // Size (1MB)
        "memory_dump.bin",
    )?;
    
    Ok(())
}
```

#### Shellcode Injection

```rs
use runas_rs::ProcessMemory;
use anyhow::Result;
use windows_sys::Win32::System::Threading::PROCESS_ALL_ACCESS;

fn main() -> Result<()> {
    // Open a process with full access
    let pid = 1234; // Target process ID
    let process_handle = ProcessMemory::open_process(pid, PROCESS_ALL_ACCESS)?;
    
    // Inject shellcode into the process
    let shellcode = vec![0x90, 0x90, 0x90]; // NOP sled
    let address = ProcessMemory::inject_shellcode(process_handle, &shellcode)?;
    
    println!("Shellcode injected at address: 0x{:X}", address);
    
    Ok(())
}
```

#### Security Considerations

When using process memory manipulation capabilities:

1. Ensure you have the necessary permissions to access the target process
2. Be aware of antivirus and security software that may detect memory manipulation
3. Use appropriate error handling to manage operation failures
4. Consider the integrity level and privileges of both the source and target processes
5. Be cautious when modifying executable memory regions, as this can cause crashes

### Process Token Manipulation

The `runas-rs` crate provides comprehensive Process Token Manipulation capabilities for security testing and red teaming operations. These capabilities allow you to manipulate process tokens to gain elevated privileges, impersonate users, and perform various token-based operations.

#### Token Operations

The library supports the following token operations:

- **Enable/Disable/Remove Privileges**: Manipulate token privileges to gain or restrict capabilities
- **Add/Remove Groups**: Modify the security groups associated with a token
- **Set Integrity Level**: Change the integrity level of a token (low, medium, high, system)
- **Set Token Type**: Change the token type (primary or impersonation)
- **Set Impersonation Level**: Modify the impersonation level of a token
- **Token Elevation**: Elevate a token to have administrative privileges
- **Token Stealing**: Steal a token from another process
- **Token Filtering**: Filter a token to remove certain privileges and groups
- **Set Session ID**: Change the session ID associated with a token
- **Set Token Origin**: Modify the token origin
- **Set Token UI Access**: Enable or disable UI access for a token
- **Set Token Sandbox Inert**: Enable or disable sandbox inert for a token
- **Get Token Statistics**: Retrieve statistics about a token
- **Get Linked Token**: Obtain the linked token
- **Check Token Elevation**: Determine if a token is elevated

#### Basic Token Manipulation

```rust
use runas_rs::TokenManipulator;

fn main() -> anyhow::Result<()> {
    // Create a token manipulator for the current process
    let manipulator = TokenManipulator::new(std::process::id())?;
    
    // Enable a privilege
    manipulator.enable_privilege("SeDebugPrivilege")?;
    
    // Set the integrity level to high
    manipulator.set_integrity_level("high")?;
    
    // Elevate the token
    manipulator.elevate_token()?;
    
    Ok(())
}
```

#### Token Impersonation

```rust
use runas_rs::TokenManipulator;

fn main() -> anyhow::Result<()> {
    // Create a token manipulator for a target process
    let manipulator = TokenManipulator::new(target_pid)?;
    
    // Impersonate the token
    manipulator.impersonate()?;
    
    // Perform operations with the impersonated token
    
    // Revert impersonation when done
    TokenManipulator::revert_impersonation()?;
    
    Ok(())
}
```

#### Advanced Token Manipulation

```rust
use runas_rs::{TokenManipulator, TokenOperation, TokenConfig};

fn main() -> anyhow::Result<()> {
    // Create a token manipulator for a target process
    let manipulator = TokenManipulator::new(target_pid)?;
    
    // Create a token configuration
    let config = TokenConfig {
        operation: TokenOperation::EnablePrivilege,
        target: "SeDebugPrivilege".to_string(),
        params: vec![],
    };
    
    // Apply the configuration
    manipulator.apply_config(&config)?;
    
    // Steal a token from another process
    manipulator.steal_token(another_pid)?;
    
    // Filter the token
    manipulator.filter_token(windows_sys::Win32::Security::DISABLE_MAX_PRIVILEGES)?;
    
    // Set the session ID
    manipulator.set_session_id(session_id)?;
    
    // Check if the token is elevated
    let is_elevated = manipulator.is_token_elevated()?;
    
    Ok(())
}
```

#### Security Considerations

When using Process Token Manipulation capabilities, keep the following security considerations in mind:

1. **Permissions**: Token manipulation requires appropriate permissions. Some operations may require administrative privileges.
2. **Error Handling**: Always check for errors when manipulating tokens, as failures can lead to security issues.
3. **Resource Cleanup**: Ensure that token handles are properly closed to prevent resource leaks.
4. **Impersonation**: When impersonating a token, always revert the impersonation when done to prevent security vulnerabilities.
5. **Elevation**: Be cautious when elevating tokens, as this can lead to privilege escalation vulnerabilities if not properly managed.
6. **Token Stealing**: Token stealing can be detected by security tools and may be considered malicious behavior.

### Process Suspension and Resumption

The library provides functions to suspend and resume processes:

```rust
use runas_rs::Runas;

fn main() -> anyhow::Result<()> {
    let runas = Runas::new("username", "password", Some("domain"));
    
    // Suspend a process by its PID
    runas.suspend_process(1234)?;
    
    // Resume a suspended process
    runas.resume_process(1234)?;
    
    // Suspend all threads in a process
    runas.suspend_all_threads(1234)?;
    
    // Resume all threads in a process
    runas.resume_all_threads(1234)?;
    
    Ok(())
}
```

These functions are useful for:
- Temporarily pausing a process for analysis
- Implementing process manipulation techniques
- Controlling process execution flow
- Red team operations that require process suspension

### Available Options

You can combine the following options using | (bitflags):

| Option               | Description                                                   |
|----------------------|---------------------------------------------------------------|
| `Options::Env`       | Use the current user's environment block.                     |
| `Options::Profile`   | Load the full user profile.                                   |
| `Options::NoProfile` | Do not load the user profile.                                 |
| `Options::NetOnly`   | Use credentials for remote access only (e.g., network shares).|
| `Options::NewConsole` | Create the process with a new console window.                 |
| `Options::NewProcessGroup` | Create the process with a new process group.              |
| `Options::NewWindow` | Create the process with a new window.                         |
| `Options::Suspended` | Create the process with a suspended main thread.              |
| `Options::DebugProcess` | Create the process with a debug flag.                        |
| `Options::DebugOnlyThisProcess` | Create the process with a debug flag for child processes. |
| `Options::ProtectedProcess` | Create the process with a protected process flag.            |

Example with process creation options:

```rs
use runas_rs::{Runas, Options};
use anyhow::Result;

fn main() -> Result<()> {
    // Run a process with a new console window and suspended
    let output = Runas::new("username", "password", Some("DOMAIN"))
        .options(Options::NewConsole | Options::Suspended)?
        .run("cmd.exe /c whoami")?;

    println!("Output: {}", output);
    Ok(())
}
```

## CLI

The CLI binary lets you run processes as other users directly from the command line, similar to runas.exe.

Example:
```cmd
C:\> runas.exe -u joao -p joao -c "whoami" --profile
desktop-34dc0j2\joao
```

### CLI Help

```
Usage: runas.exe [OPTIONS] -u <USERNAME> -p <PASSWORD> --command <COMMAND> <--profile|--noprofile|--netonly>

Options:
  -u <USERNAME>            Username to run the command
  -p <PASSWORD>            Password for the user
  -d, --domain <DOMAIN>    Domain of the user (optional)
  -c, --command <COMMAND>  Command to execute as the specified user
  -e                       Use the environment of the current user
      --profile            Load user profile
      --noprofile          Do not load user profile
      --netonly            Use credentials for remote access only
      --new-console        Create the process with a new console window
      --new-process-group  Create the process with a new process group
      --new-window         Create the process with a new window
      --suspended          Create the process with a suspended main thread
      --debug-process      Create the process with a debug flag
      --debug-only-this-process  Create the process with a debug flag for child processes
      --protected-process  Create the process with a protected process flag
  -h, --help               Print help
  -V, --version            Print version
```

## References

I want to express my gratitude to these projects that inspired me to create `runas-rs` and contribute with some features:

* [Pavel - CreateProcessAsUser vs. CreateProcessWithTokenW](https://www.youtube.com/watch?v=y42BsQJhd5w&t=816s)
* [Pavel - Window Stations and Desktops](https://scorpiosoftware.net/2023/06/20/window-stations-and-desktops/)
* [RunasCs](https://github.com/antonioCoco/RunasCs)

## Contributing to runas-rs

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the [**GPL-3.0 license**](/LICENSE). See the LICENSE file for details.
