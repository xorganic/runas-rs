#![doc = include_str!("../README.md")]
#![allow(non_upper_case_globals)]

mod pipe;
mod runas;
mod acl;
mod sid;
mod output;
mod injection;
mod memory;
mod token;
mod environment;
mod handle;
mod sandbox;
mod monitor;

pub use runas::{Runas, Options, Token, SecurityContext};
pub use sid::get_user_sid;
pub use acl::{Acl, Object};
pub use pipe::Pipe;
pub use injection::{ProcessInjector, InjectionTechnique, InjectionConfig};
pub use memory::{ProcessMemory, MemoryProtection, MemoryRegion};
pub use token::{TokenManipulator, TokenOperation, TokenConfig};
pub use output::*;
pub use environment::ProcessEnvironment;
pub use handle::{ProcessHandle, ProcessAccess, HandleTable, HandleTableEntry};
pub use sandbox::{JobObject, JobLimit, JobUIRestriction, SandboxedProcess};
pub use monitor::{ProcessMonitor, ProcessHook, HookType};
