use anyhow::{anyhow, Result};
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, PROCESS_ALL_ACCESS, PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE,
    PROCESS_QUERY_INFORMATION, PROCESS_SET_INFORMATION, PROCESS_TERMINATE, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE,
};
use windows_sys::Win32::System::SystemInformation::{
    NtQuerySystemInformation, SystemHandleInformation, SYSTEM_HANDLE_ENTRY, SYSTEM_HANDLE_INFORMATION,
    SYSTEM_HANDLE_TABLE_ENTRY_INFO,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    NtQueryInformationProcess, ProcessBasicInformation, PROCESS_BASIC_INFORMATION,
};
use windows_sys::Win32::System::Threading::{
    GetProcessId, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_QUERY,
};

/// Represents different access rights for process handles
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessAccess {
    /// All access rights
    AllAccess,
    /// Create thread access
    CreateThread,
    /// Duplicate handle access
    DupHandle,
    /// Query information access
    QueryInformation,
    /// Set information access
    SetInformation,
    /// Terminate process access
    Terminate,
    /// VM operation access
    VmOperation,
    /// VM read access
    VmRead,
    /// VM write access
    VmWrite,
    /// Custom access rights
    Custom(u32),
}

impl ProcessAccess {
    /// Convert to Windows access rights
    pub fn to_access_rights(&self) -> u32 {
        match self {
            ProcessAccess::AllAccess => PROCESS_ALL_ACCESS,
            ProcessAccess::CreateThread => PROCESS_CREATE_THREAD,
            ProcessAccess::DupHandle => PROCESS_DUP_HANDLE,
            ProcessAccess::QueryInformation => PROCESS_QUERY_INFORMATION,
            ProcessAccess::SetInformation => PROCESS_SET_INFORMATION,
            ProcessAccess::Terminate => PROCESS_TERMINATE,
            ProcessAccess::VmOperation => PROCESS_VM_OPERATION,
            ProcessAccess::VmRead => PROCESS_VM_READ,
            ProcessAccess::VmWrite => PROCESS_VM_WRITE,
            ProcessAccess::Custom(rights) => *rights,
        }
    }
}

/// Represents a process handle with manipulation capabilities
pub struct ProcessHandle {
    handle: HANDLE,
    process_id: u32,
}

impl ProcessHandle {
    /// Creates a new ProcessHandle for the specified process with the given access rights
    pub fn new(process_id: u32, access: ProcessAccess) -> Result<Self> {
        let handle = unsafe {
            OpenProcess(access.to_access_rights(), 0, process_id)
        };

        if handle == 0 {
            return Err(anyhow!("Failed to open process"));
        }

        Ok(Self {
            handle,
            process_id,
        })
    }

    /// Gets the raw handle value
    pub fn get_handle(&self) -> HANDLE {
        self.handle
    }

    /// Gets the process ID
    pub fn get_process_id(&self) -> u32 {
        self.process_id
    }

    /// Checks if the handle is valid
    pub fn is_valid(&self) -> bool {
        self.handle != 0 && self.handle != INVALID_HANDLE_VALUE
    }

    /// Duplicates the handle with the specified access rights
    pub fn duplicate(&self, access: ProcessAccess) -> Result<ProcessHandle> {
        let mut new_handle = 0;
        let current_process = unsafe { GetCurrentProcess() };

        let result = unsafe {
            DuplicateHandle(
                current_process,
                self.handle,
                current_process,
                &mut new_handle,
                access.to_access_rights(),
                0,
                0,
            )
        };

        if result == 0 {
            return Err(anyhow!("Failed to duplicate handle"));
        }

        Ok(ProcessHandle {
            handle: new_handle,
            process_id: self.process_id,
        })
    }

    /// Duplicates the handle to another process
    pub fn duplicate_to_process(&self, target_process: HANDLE, access: ProcessAccess) -> Result<HANDLE> {
        let mut new_handle = 0;
        let current_process = unsafe { GetCurrentProcess() };

        let result = unsafe {
            DuplicateHandle(
                current_process,
                self.handle,
                target_process,
                &mut new_handle,
                access.to_access_rights(),
                0,
                0,
            )
        };

        if result == 0 {
            return Err(anyhow!("Failed to duplicate handle to target process"));
        }

        Ok(new_handle)
    }

    /// Closes the handle
    pub fn close(&mut self) -> Result<()> {
        if self.is_valid() {
            let result = unsafe { CloseHandle(self.handle) };
            if result == 0 {
                return Err(anyhow!("Failed to close handle"));
            }
            self.handle = 0;
        }
        Ok(())
    }

    /// Gets the process ID for a handle
    pub fn get_handle_process_id(&self) -> Result<u32> {
        let mut process_id = 0;
        let result = unsafe { GetProcessId(self.handle) };
        
        if result == 0 {
            return Err(anyhow!("Failed to get process ID for handle"));
        }
        
        Ok(result)
    }

    /// Gets basic information about the process
    pub fn get_process_info(&self) -> Result<PROCESS_BASIC_INFORMATION> {
        let mut info: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let mut return_length = 0;
        
        let status = unsafe {
            NtQueryInformationProcess(
                self.handle,
                ProcessBasicInformation,
                &mut info as *mut _ as *mut _,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                &mut return_length,
            )
        };
        
        if status != 0 {
            return Err(anyhow!("Failed to query process information"));
        }
        
        Ok(info)
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if self.is_valid() {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

/// Represents a handle table entry
pub struct HandleTableEntry {
    /// The handle value
    pub handle: HANDLE,
    /// The process ID that owns the handle
    pub process_id: u32,
    /// The object type
    pub object_type: String,
    /// The access rights
    pub access_rights: u32,
}

/// Represents a handle table with manipulation capabilities
pub struct HandleTable {
    /// The process ID that owns the handle table
    pub process_id: u32,
    /// The handle to the process
    pub process_handle: HANDLE,
}

impl HandleTable {
    /// Creates a new HandleTable for the specified process
    pub fn new(process_id: u32) -> Result<Self> {
        let process_handle = unsafe {
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, 0, process_id)
        };

        if process_handle == 0 {
            return Err(anyhow!("Failed to open process"));
        }

        Ok(Self {
            process_id,
            process_handle,
        })
    }

    /// Gets all handles in the handle table
    pub fn get_all_handles(&self) -> Result<Vec<HandleTableEntry>> {
        let mut buffer_size = 0;
        let mut return_length = 0;
        
        // First call to get required buffer size
        unsafe {
            NtQuerySystemInformation(
                SystemHandleInformation,
                ptr::null_mut(),
                0,
                &mut return_length,
            );
        }
        
        // Allocate buffer with some extra space
        buffer_size = return_length + 1024;
        let mut buffer = vec![0u8; buffer_size as usize];
        
        // Query system handle information
        let status = unsafe {
            NtQuerySystemInformation(
                SystemHandleInformation,
                buffer.as_mut_ptr() as *mut _,
                buffer_size,
                &mut return_length,
            )
        };
        
        if status != 0 {
            return Err(anyhow!("Failed to query system handle information"));
        }
        
        // Parse the handle information
        let handle_info = unsafe { &*(buffer.as_ptr() as *const SYSTEM_HANDLE_INFORMATION) };
        let mut entries = Vec::new();
        
        for i in 0..handle_info.HandleCount {
            let entry = unsafe { &*((&handle_info.Handles as *const _ as *const u8).add(i as usize * std::mem::size_of::<SYSTEM_HANDLE_ENTRY>()) as *const SYSTEM_HANDLE_ENTRY) };
            
            // Filter handles belonging to our target process
            if entry.ProcessId == self.process_id {
                // Get object type name (simplified - in a real implementation you would use NtQueryObject)
                let object_type = match entry.ObjectTypeNumber {
                    1 => "Directory".to_string(),
                    2 => "SymbolicLink".to_string(),
                    3 => "Token".to_string(),
                    4 => "Process".to_string(),
                    5 => "Thread".to_string(),
                    6 => "Job".to_string(),
                    7 => "Event".to_string(),
                    8 => "EventPair".to_string(),
                    9 => "Mutant".to_string(),
                    10 => "Semaphore".to_string(),
                    11 => "Timer".to_string(),
                    12 => "Key".to_string(),
                    13 => "File".to_string(),
                    14 => "Section".to_string(),
                    15 => "Port".to_string(),
                    16 => "WaitablePort".to_string(),
                    17 => "ALPC Port".to_string(),
                    18 => "WindowStation".to_string(),
                    19 => "Desktop".to_string(),
                    20 => "Composition".to_string(),
                    _ => format!("Unknown({})", entry.ObjectTypeNumber),
                };
                
                entries.push(HandleTableEntry {
                    handle: entry.Handle,
                    process_id: entry.ProcessId,
                    object_type,
                    access_rights: entry.GrantedAccess,
                });
            }
        }
        
        Ok(entries)
    }

    /// Closes a specific handle in the handle table
    pub fn close_handle(&self, handle: HANDLE) -> Result<()> {
        let current_process = unsafe { GetCurrentProcess() };
        let result = unsafe {
            DuplicateHandle(
                self.process_handle,
                handle,
                current_process,
                ptr::null_mut(),
                0,
                0,
                0,
            )
        };

        if result == 0 {
            return Err(anyhow!("Failed to close handle"));
        }

        Ok(())
    }

    /// Closes all handles in the handle table
    pub fn close_all_handles(&self) -> Result<()> {
        let handles = self.get_all_handles()?;
        for entry in handles {
            self.close_handle(entry.handle)?;
        }
        Ok(())
    }
    
    /// Gets a specific handle by its value
    pub fn get_handle(&self, handle_value: HANDLE) -> Result<HandleTableEntry> {
        let handles = self.get_all_handles()?;
        
        for entry in handles {
            if entry.handle == handle_value {
                return Ok(entry);
            }
        }
        
        Err(anyhow!("Handle not found"))
    }
    
    /// Gets all handles of a specific object type
    pub fn get_handles_by_type(&self, object_type: &str) -> Result<Vec<HandleTableEntry>> {
        let handles = self.get_all_handles()?;
        let mut filtered = Vec::new();
        
        for entry in handles {
            if entry.object_type == object_type {
                filtered.push(entry);
            }
        }
        
        Ok(filtered)
    }
}

impl Drop for HandleTable {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.process_handle);
        }
    }
} 