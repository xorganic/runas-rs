use anyhow::{bail, Result};
use core::{
    ptr::{null, null_mut},
    mem::size_of,
};
use std::ffi::CString;

use windows_sys::{
    Win32::Foundation::{CloseHandle, GetLastError, FALSE, TRUE, HANDLE},
    Win32::System::Threading::{
        OpenProcess, VirtualAllocEx, WriteProcessMemory, ReadProcessMemory,
        PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
        PROCESS_VM_WRITE, PROCESS_VM_READ, PROCESS_ALL_ACCESS,
    },
    Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_READWRITE,
        VirtualProtectEx, VirtualFreeEx, MEM_RELEASE, MEM_DECOMMIT,
    },
    Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32First, Process32Next,
        TH32CS_SNAPPROCESS, PROCESSENTRY32W,
    },
};

/// Represents memory protection flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryProtection {
    /// Read-only memory
    ReadOnly,
    /// Read-write memory
    ReadWrite,
    /// Execute-only memory
    Execute,
    /// Execute-read memory
    ExecuteRead,
    /// Execute-read-write memory
    ExecuteReadWrite,
}

impl MemoryProtection {
    /// Converts the enum to the corresponding Windows API flag
    fn to_windows_flag(&self) -> u32 {
        match self {
            MemoryProtection::ReadOnly => PAGE_READONLY,
            MemoryProtection::ReadWrite => PAGE_READWRITE,
            MemoryProtection::Execute => PAGE_EXECUTE,
            MemoryProtection::ExecuteRead => PAGE_EXECUTE_READ,
            MemoryProtection::ExecuteReadWrite => PAGE_EXECUTE_READWRITE,
        }
    }
}

/// Represents a memory region in a process
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Base address of the memory region
    pub base_address: usize,
    /// Size of the memory region
    pub size: usize,
    /// Protection flags of the memory region
    pub protection: MemoryProtection,
    /// Whether the memory region is committed
    pub is_committed: bool,
}

/// Handles process memory manipulation operations
pub struct ProcessMemory;

impl ProcessMemory {
    /// Opens a process with the necessary access rights
    ///
    /// # Parameters
    ///
    /// * `pid` - The process ID to open
    /// * `access_rights` - The access rights to request
    ///
    /// # Returns
    ///
    /// * `Ok(HANDLE)` - If the process was opened successfully
    /// * `Err(anyhow::Error)` - If the process could not be opened
    pub fn open_process(pid: u32, access_rights: u32) -> Result<HANDLE> {
        unsafe {
            let handle = OpenProcess(access_rights, FALSE, pid);
            if handle == 0 {
                bail!("Failed to open process: {}", GetLastError());
            }
            Ok(handle)
        }
    }

    /// Allocates memory in a process
    ///
    /// # Parameters
    ///
    /// * `process_handle` - Handle to the process
    /// * `size` - Size of memory to allocate
    /// * `protection` - Memory protection flags
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Base address of the allocated memory
    /// * `Err(anyhow::Error)` - If memory could not be allocated
    pub fn allocate_memory(
        process_handle: HANDLE,
        size: usize,
        protection: MemoryProtection,
    ) -> Result<usize> {
        unsafe {
            let address = VirtualAllocEx(
                process_handle,
                null(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                protection.to_windows_flag(),
            );
            
            if address == null_mut() {
                bail!("Failed to allocate memory: {}", GetLastError());
            }
            
            Ok(address as usize)
        }
    }

    /// Frees memory in a process
    ///
    /// # Parameters
    ///
    /// * `process_handle` - Handle to the process
    /// * `address` - Base address of the memory to free
    /// * `size` - Size of the memory to free
    /// * `free_type` - Type of free operation (MEM_RELEASE or MEM_DECOMMIT)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If memory was freed successfully
    /// * `Err(anyhow::Error)` - If memory could not be freed
    pub fn free_memory(
        process_handle: HANDLE,
        address: usize,
        size: usize,
        free_type: u32,
    ) -> Result<()> {
        unsafe {
            if VirtualFreeEx(process_handle, address as *mut _, size, free_type) == FALSE {
                bail!("Failed to free memory: {}", GetLastError());
            }
            Ok(())
        }
    }

    /// Changes the protection of a memory region
    ///
    /// # Parameters
    ///
    /// * `process_handle` - Handle to the process
    /// * `address` - Base address of the memory region
    /// * `size` - Size of the memory region
    /// * `new_protection` - New protection flags
    ///
    /// # Returns
    ///
    /// * `Ok(u32)` - Old protection flags
    /// * `Err(anyhow::Error)` - If protection could not be changed
    pub fn change_protection(
        process_handle: HANDLE,
        address: usize,
        size: usize,
        new_protection: MemoryProtection,
    ) -> Result<u32> {
        unsafe {
            let mut old_protection = 0;
            if VirtualProtectEx(
                process_handle,
                address as *mut _,
                size,
                new_protection.to_windows_flag(),
                &mut old_protection,
            ) == FALSE {
                bail!("Failed to change memory protection: {}", GetLastError());
            }
            Ok(old_protection)
        }
    }

    /// Writes data to process memory
    ///
    /// # Parameters
    ///
    /// * `process_handle` - Handle to the process
    /// * `address` - Base address to write to
    /// * `data` - Data to write
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If data was written successfully
    /// * `Err(anyhow::Error)` - If data could not be written
    pub fn write_memory<T>(
        process_handle: HANDLE,
        address: usize,
        data: &T,
    ) -> Result<()> {
        unsafe {
            let mut bytes_written = 0;
            if WriteProcessMemory(
                process_handle,
                address as *mut _,
                data as *const _ as *const _,
                size_of::<T>(),
                &mut bytes_written,
            ) == FALSE {
                bail!("Failed to write memory: {}", GetLastError());
            }
            Ok(())
        }
    }

    /// Writes raw bytes to process memory
    ///
    /// # Parameters
    ///
    /// * `process_handle` - Handle to the process
    /// * `address` - Base address to write to
    /// * `data` - Data to write
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If data was written successfully
    /// * `Err(anyhow::Error)` - If data could not be written
    pub fn write_bytes(
        process_handle: HANDLE,
        address: usize,
        data: &[u8],
    ) -> Result<()> {
        unsafe {
            let mut bytes_written = 0;
            if WriteProcessMemory(
                process_handle,
                address as *mut _,
                data.as_ptr() as *const _,
                data.len(),
                &mut bytes_written,
            ) == FALSE {
                bail!("Failed to write memory: {}", GetLastError());
            }
            Ok(())
        }
    }

    /// Reads data from process memory
    ///
    /// # Parameters
    ///
    /// * `process_handle` - Handle to the process
    /// * `address` - Base address to read from
    ///
    /// # Returns
    ///
    /// * `Ok(T)` - The data read from memory
    /// * `Err(anyhow::Error)` - If data could not be read
    pub fn read_memory<T>(
        process_handle: HANDLE,
        address: usize,
    ) -> Result<T> {
        unsafe {
            let mut data: T = std::mem::zeroed();
            let mut bytes_read = 0;
            if ReadProcessMemory(
                process_handle,
                address as *const _,
                &mut data as *mut _ as *mut _,
                size_of::<T>(),
                &mut bytes_read,
            ) == FALSE {
                bail!("Failed to read memory: {}", GetLastError());
            }
            Ok(data)
        }
    }

    /// Reads raw bytes from process memory
    ///
    /// # Parameters
    ///
    /// * `process_handle` - Handle to the process
    /// * `address` - Base address to read from
    /// * `size` - Number of bytes to read
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The bytes read from memory
    /// * `Err(anyhow::Error)` - If data could not be read
    pub fn read_bytes(
        process_handle: HANDLE,
        address: usize,
        size: usize,
    ) -> Result<Vec<u8>> {
        unsafe {
            let mut buffer = vec![0u8; size];
            let mut bytes_read = 0;
            if ReadProcessMemory(
                process_handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                size,
                &mut bytes_read,
            ) == FALSE {
                bail!("Failed to read memory: {}", GetLastError());
            }
            Ok(buffer)
        }
    }

    /// Scans process memory for a pattern
    ///
    /// # Parameters
    ///
    /// * `process_handle` - Handle to the process
    /// * `start_address` - Starting address to scan from
    /// * `end_address` - Ending address to scan to
    /// * `pattern` - Pattern to search for
    /// * `mask` - Mask for the pattern (1 for bytes to match, 0 for wildcards)
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<usize>)` - Addresses where the pattern was found
    /// * `Err(anyhow::Error)` - If scanning failed
    pub fn scan_memory(
        process_handle: HANDLE,
        start_address: usize,
        end_address: usize,
        pattern: &[u8],
        mask: &[u8],
    ) -> Result<Vec<usize>> {
        let mut results = Vec::new();
        let chunk_size = 4096; // Read in 4KB chunks
        
        for address in (start_address..end_address).step_by(chunk_size) {
            let size = std::cmp::min(chunk_size, end_address - address);
            let buffer = Self::read_bytes(process_handle, address, size)?;
            
            for i in 0..buffer.len() {
                let mut found = true;
                for j in 0..pattern.len() {
                    if i + j >= buffer.len() {
                        found = false;
                        break;
                    }
                    
                    if mask[j] == 1 && buffer[i + j] != pattern[j] {
                        found = false;
                        break;
                    }
                }
                
                if found {
                    results.push(address + i);
                }
            }
        }
        
        Ok(results)
    }

    /// Gets memory regions in a process
    ///
    /// # Parameters
    ///
    /// * `process_handle` - Handle to the process
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<MemoryRegion>)` - List of memory regions
    /// * `Err(anyhow::Error)` - If memory regions could not be retrieved
    pub fn get_memory_regions(process_handle: HANDLE) -> Result<Vec<MemoryRegion>> {
        // This is a placeholder implementation
        // In a real implementation, this would use VirtualQueryEx to get memory regions
        bail!("Memory region enumeration not implemented yet");
    }

    /// Dumps process memory to a file
    ///
    /// # Parameters
    ///
    /// * `process_handle` - Handle to the process
    /// * `start_address` - Starting address to dump from
    /// * `size` - Size of memory to dump
    /// * `file_path` - Path to save the dump to
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If memory was dumped successfully
    /// * `Err(anyhow::Error)` - If memory could not be dumped
    pub fn dump_memory(
        process_handle: HANDLE,
        start_address: usize,
        size: usize,
        file_path: &str,
    ) -> Result<()> {
        let memory = Self::read_bytes(process_handle, start_address, size)?;
        std::fs::write(file_path, memory)?;
        Ok(())
    }

    /// Injects shellcode into a process
    ///
    /// # Parameters
    ///
    /// * `process_handle` - Handle to the process
    /// * `shellcode` - Shellcode to inject
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Address where the shellcode was injected
    /// * `Err(anyhow::Error)` - If shellcode could not be injected
    pub fn inject_shellcode(
        process_handle: HANDLE,
        shellcode: &[u8],
    ) -> Result<usize> {
        // Allocate memory for the shellcode
        let address = Self::allocate_memory(
            process_handle,
            shellcode.len(),
            MemoryProtection::ExecuteReadWrite,
        )?;
        
        // Write the shellcode to the allocated memory
        Self::write_bytes(process_handle, address, shellcode)?;
        
        Ok(address)
    }

    /// Patches memory in a process
    ///
    /// # Parameters
    ///
    /// * `process_handle` - Handle to the process
    /// * `address` - Address to patch
    /// * `patch` - Patch data
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If memory was patched successfully
    /// * `Err(anyhow::Error)` - If memory could not be patched
    pub fn patch_memory(
        process_handle: HANDLE,
        address: usize,
        patch: &[u8],
    ) -> Result<()> {
        // Change memory protection to allow writing
        let old_protection = Self::change_protection(
            process_handle,
            address,
            patch.len(),
            MemoryProtection::ReadWrite,
        )?;
        
        // Write the patch
        Self::write_bytes(process_handle, address, patch)?;
        
        // Restore original memory protection
        Self::change_protection(
            process_handle,
            address,
            patch.len(),
            Self::protection_from_windows_flag(old_protection)?,
        )?;
        
        Ok(())
    }

    /// Converts a Windows protection flag to a MemoryProtection enum
    #[allow(non_snake_case)]
    fn protection_from_windows_flag(flag: u32) -> Result<MemoryProtection> {
        match flag {
            PAGE_READONLY => Ok(MemoryProtection::ReadOnly),
            PAGE_READWRITE => Ok(MemoryProtection::ReadWrite),
            PAGE_EXECUTE => Ok(MemoryProtection::Execute),
            PAGE_EXECUTE_READ => Ok(MemoryProtection::ExecuteRead),
            PAGE_EXECUTE_READWRITE => Ok(MemoryProtection::ExecuteReadWrite),
            _ => bail!("Unknown protection flag: {}", flag),
        }
    }
} 