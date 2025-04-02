use anyhow::{anyhow, Result};
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, EXCEPTION_POINTERS,
    EXCEPTION_RECORD, VEH_EXCEPTION_HANDLER, EXCEPTION_BREAKPOINT,
    EXCEPTION_SINGLE_STEP, EXCEPTION_ACCESS_VIOLATION,
    CONTEXT, CONTEXT_DEBUG_REGISTERS, DR7_CONTROL_ENABLED, DR7_CONTROL_LENGTH_1,
    DR7_CONTROL_RW_EXECUTE, DR7_CONTROL_RW_READ, DR7_CONTROL_RW_WRITE,
    GetThreadContext, SetThreadContext,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleHandleW, GetProcAddress, LoadLibraryW, FreeLibrary,
};
use windows_sys::Win32::System::Memory::{
    VirtualProtect, VirtualQuery, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_READ, PAGE_READWRITE,
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS, PROCESS_CREATE_THREAD,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    GetCurrentProcess,
    GetThreadId, GetCurrentThreadId,
    SuspendThread, ResumeThread, OpenThread, THREAD_ALL_ACCESS,
};
use core::ptr;

/// Represents different types of hooks that can be installed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookType {
    /// Inline hook that replaces the first few bytes of a function
    Inline,
    /// IAT (Import Address Table) hook that modifies the import table
    IAT,
    /// EAT (Export Address Table) hook that modifies the export table
    EAT,
    /// VEH (Vectored Exception Handler) hook that handles exceptions
    VEH,
    /// Trampoline hook that preserves the original function
    Trampoline,
    /// Hotpatch hook that uses the hotpatch area
    Hotpatch,
    /// Hardware breakpoint hook
    HardwareBreakpoint,
}

/// Represents a hook installed in a process
pub struct ProcessHook {
    process_id: u32,
    hook_type: HookType,
    target_address: usize,
    original_bytes: Vec<u8>,
    hook_handle: Option<HANDLE>,
    veh_handle: Option<HANDLE>,
    trampoline_address: Option<usize>,
    breakpoint_handle: Option<HANDLE>,
    target_function: String,
}

impl ProcessHook {
    /// Creates a new process hook
    pub fn new(process_id: u32, hook_type: HookType, target_address: usize) -> Result<Self> {
        Ok(Self {
            process_id,
            hook_type,
            target_address,
            original_bytes: Vec::new(),
            hook_handle: None,
            veh_handle: None,
            trampoline_address: None,
            breakpoint_handle: None,
            target_function: String::new(),
        })
    }

    /// Installs the hook in the target process
    pub fn install(&mut self, hook_bytes: &[u8]) -> Result<()> {
        let process_handle = unsafe {
            OpenProcess(
                PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                0,
                self.process_id,
            )
        };

        if process_handle == 0 {
            return Err(anyhow!("Failed to open process"));
        }

        match self.hook_type {
            HookType::Inline => self.install_inline_hook(process_handle, hook_bytes)?,
            HookType::IAT => self.install_iat_hook(process_handle, hook_bytes)?,
            HookType::EAT => self.install_eat_hook(process_handle, hook_bytes)?,
            HookType::VEH => self.install_veh_hook(process_handle, hook_bytes)?,
            HookType::Trampoline => self.install_trampoline_hook(process_handle, hook_bytes)?,
            HookType::Hotpatch => self.install_hotpatch_hook(process_handle, hook_bytes)?,
            HookType::HardwareBreakpoint => self.install_hardware_breakpoint_hook(process_handle, hook_bytes)?,
        }

        unsafe {
            CloseHandle(process_handle);
        }

        Ok(())
    }

    /// Removes the hook from the target process
    pub fn remove(&mut self) -> Result<()> {
        let process_handle = unsafe {
            OpenProcess(
                PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                0,
                self.process_id,
            )
        };

        if process_handle == 0 {
            return Err(anyhow!("Failed to open process"));
        }

        match self.hook_type {
            HookType::Inline => self.remove_inline_hook(process_handle)?,
            HookType::IAT => self.remove_iat_hook(process_handle)?,
            HookType::EAT => self.remove_eat_hook(process_handle)?,
            HookType::VEH => self.remove_veh_hook(process_handle)?,
            HookType::Trampoline => self.remove_trampoline_hook(process_handle)?,
            HookType::Hotpatch => self.remove_hotpatch_hook(process_handle)?,
            HookType::HardwareBreakpoint => self.remove_hardware_breakpoint_hook(process_handle)?,
        }

        unsafe {
            CloseHandle(process_handle);
        }

        Ok(())
    }

    fn install_inline_hook(&mut self, process_handle: HANDLE, hook_bytes: &[u8]) -> Result<()> {
        // Save original bytes
        let mut original_bytes = vec![0u8; hook_bytes.len()];
        let mut bytes_read = 0;
        unsafe {
            windows_sys::Win32::System::Memory::ReadProcessMemory(
                process_handle,
                self.target_address as *const _,
                original_bytes.as_mut_ptr() as *mut _,
                hook_bytes.len(),
                &mut bytes_read,
            );
        }
        self.original_bytes = original_bytes;

        // Change memory protection
        let mut old_protect = 0;
        unsafe {
            VirtualProtect(
                self.target_address as *mut _,
                hook_bytes.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );
        }

        // Write hook bytes
        let mut bytes_written = 0;
        unsafe {
            windows_sys::Win32::System::Memory::WriteProcessMemory(
                process_handle,
                self.target_address as *mut _,
                hook_bytes.as_ptr() as *const _,
                hook_bytes.len(),
                &mut bytes_written,
            );
        }

        Ok(())
    }

    fn remove_inline_hook(&mut self, process_handle: HANDLE) -> Result<()> {
        // Restore original bytes
        let mut bytes_written = 0;
        unsafe {
            windows_sys::Win32::System::Memory::WriteProcessMemory(
                process_handle,
                self.target_address as *mut _,
                self.original_bytes.as_ptr() as *const _,
                self.original_bytes.len(),
                &mut bytes_written,
            );
        }

        Ok(())
    }

    fn install_trampoline_hook(&mut self, process_handle: HANDLE, hook_bytes: &[u8]) -> Result<()> {
        // Allocate memory for trampoline
        let trampoline_size = hook_bytes.len() + 5; // Size of hook bytes + size of jump back
        let trampoline_address = unsafe {
            windows_sys::Win32::System::Memory::VirtualAllocEx(
                process_handle,
                ptr::null_mut(),
                trampoline_size,
                windows_sys::Win32::System::Memory::MEM_COMMIT | windows_sys::Win32::System::Memory::MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };

        if trampoline_address.is_null() {
            return Err(anyhow!("Failed to allocate trampoline memory"));
        }

        self.trampoline_address = Some(trampoline_address as usize);

        // Save original bytes
        let mut original_bytes = vec![0u8; hook_bytes.len()];
        let mut bytes_read = 0;
        unsafe {
            windows_sys::Win32::System::Memory::ReadProcessMemory(
                process_handle,
                self.target_address as *const _,
                original_bytes.as_mut_ptr() as *mut _,
                hook_bytes.len(),
                &mut bytes_read,
            );
        }
        self.original_bytes = original_bytes;

        // Write original bytes to trampoline
        let mut bytes_written = 0;
        unsafe {
            windows_sys::Win32::System::Memory::WriteProcessMemory(
                process_handle,
                trampoline_address,
                self.original_bytes.as_ptr() as *const _,
                self.original_bytes.len(),
                &mut bytes_written,
            );
        }

        // Add jump back to original function
        let jump_back = self.create_jump_bytes(
            (trampoline_address as usize + self.original_bytes.len()) as usize,
            self.target_address + self.original_bytes.len(),
        );
        unsafe {
            windows_sys::Win32::System::Memory::WriteProcessMemory(
                process_handle,
                trampoline_address.add(self.original_bytes.len()),
                jump_back.as_ptr() as *const _,
                jump_back.len(),
                &mut bytes_written,
            );
        }

        // Write hook bytes to original function
        let mut bytes_written = 0;
        unsafe {
            windows_sys::Win32::System::Memory::WriteProcessMemory(
                process_handle,
                self.target_address as *mut _,
                hook_bytes.as_ptr() as *const _,
                hook_bytes.len(),
                &mut bytes_written,
            );
        }

        Ok(())
    }

    fn remove_trampoline_hook(&mut self, process_handle: HANDLE) -> Result<()> {
        // Restore original bytes
        let mut bytes_written = 0;
        unsafe {
            windows_sys::Win32::System::Memory::WriteProcessMemory(
                process_handle,
                self.target_address as *mut _,
                self.original_bytes.as_ptr() as *const _,
                self.original_bytes.len(),
                &mut bytes_written,
            );
        }

        // Free trampoline memory
        if let Some(trampoline_address) = self.trampoline_address {
            unsafe {
                windows_sys::Win32::System::Memory::VirtualFreeEx(
                    process_handle,
                    trampoline_address as *mut _,
                    0,
                    windows_sys::Win32::System::Memory::MEM_RELEASE,
                );
            }
        }

        Ok(())
    }

    fn install_hotpatch_hook(&mut self, process_handle: HANDLE, hook_bytes: &[u8]) -> Result<()> {
        // Check if function has hotpatch area
        let mut original_bytes = vec![0u8; 2];
        let mut bytes_read = 0;
        unsafe {
            windows_sys::Win32::System::Memory::ReadProcessMemory(
                process_handle,
                (self.target_address - 2) as *const _,
                original_bytes.as_mut_ptr() as *mut _,
                2,
                &mut bytes_read,
            );
        }

        // If not a hotpatch area, create one
        if original_bytes != [0xCC, 0xCC] {
            // Save original bytes
            let mut original_bytes = vec![0u8; hook_bytes.len()];
            let mut bytes_read = 0;
            unsafe {
                windows_sys::Win32::System::Memory::ReadProcessMemory(
                    process_handle,
                    self.target_address as *const _,
                    original_bytes.as_mut_ptr() as *mut _,
                    hook_bytes.len(),
                    &mut bytes_read,
                );
            }
            self.original_bytes = original_bytes;

            // Create hotpatch area
            let hotpatch_bytes = vec![0xCC, 0xCC];
            let mut bytes_written = 0;
            unsafe {
                windows_sys::Win32::System::Memory::WriteProcessMemory(
                    process_handle,
                    (self.target_address - 2) as *mut _,
                    hotpatch_bytes.as_ptr() as *const _,
                    hotpatch_bytes.len(),
                    &mut bytes_written,
                );
            }
        }

        // Write hook bytes
        let mut bytes_written = 0;
        unsafe {
            windows_sys::Win32::System::Memory::WriteProcessMemory(
                process_handle,
                self.target_address as *mut _,
                hook_bytes.as_ptr() as *const _,
                hook_bytes.len(),
                &mut bytes_written,
            );
        }

        Ok(())
    }

    fn remove_hotpatch_hook(&mut self, process_handle: HANDLE) -> Result<()> {
        // Restore original bytes
        let mut bytes_written = 0;
        unsafe {
            windows_sys::Win32::System::Memory::WriteProcessMemory(
                process_handle,
                self.target_address as *mut _,
                self.original_bytes.as_ptr() as *const _,
                self.original_bytes.len(),
                &mut bytes_written,
            );
        }

        Ok(())
    }

    fn install_hardware_breakpoint_hook(&mut self, process_handle: HANDLE, hook_bytes: &[u8]) -> Result<()> {
        // Get thread context
        let mut context: CONTEXT = unsafe { std::mem::zeroed() };
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        // Find a free debug register
        let mut free_reg = None;
        for i in 0..4 {
            if (context.Dr7 & (1 << (i * 2))) == 0 {
                free_reg = Some(i);
                break;
            }
        }

        let reg = free_reg.ok_or_else(|| anyhow!("No free debug registers available"))?;

        // Set the breakpoint address
        match reg {
            0 => context.Dr0 = self.target_address as u64,
            1 => context.Dr1 = self.target_address as u64,
            2 => context.Dr2 = self.target_address as u64,
            3 => context.Dr3 = self.target_address as u64,
            _ => unreachable!(),
        }

        // Configure DR7
        let dr7_shift = reg * 2;
        context.Dr7 |= DR7_CONTROL_ENABLED << dr7_shift;
        context.Dr7 |= DR7_CONTROL_LENGTH_1 << (dr7_shift + 16);
        context.Dr7 |= DR7_CONTROL_RW_EXECUTE << (dr7_shift + 18);

        // Set the context
        if unsafe { SetThreadContext(process_handle, &context) } == 0 {
            return Err(anyhow!("Failed to set thread context"));
        }

        self.breakpoint_handle = Some(process_handle);
        Ok(())
    }

    fn remove_hardware_breakpoint_hook(&mut self, process_handle: HANDLE) -> Result<()> {
        // Get thread context
        let mut context: CONTEXT = unsafe { std::mem::zeroed() };
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if unsafe { GetThreadContext(process_handle, &mut context) } == 0 {
            return Err(anyhow!("Failed to get thread context"));
        }

        // Clear DR7
        context.Dr7 = 0;

        // Set the context
        if unsafe { SetThreadContext(process_handle, &context) } == 0 {
            return Err(anyhow!("Failed to set thread context"));
        }

        Ok(())
    }

    fn create_jump_bytes(&self, from: usize, to: usize) -> Vec<u8> {
        let relative_address = to as isize - (from + 5) as isize;
        let mut bytes = vec![0xE9]; // JMP instruction
        bytes.extend_from_slice(&relative_address.to_le_bytes()[..4]);
        bytes
    }

    fn install_iat_hook(&mut self, process_handle: HANDLE, hook_bytes: &[u8]) -> Result<()> {
        // Get module base address
        let module_base = unsafe { GetModuleHandleW(ptr::null()) };
        if module_base == 0 {
            return Err(anyhow!("Failed to get module base address"));
        }

        // Parse PE headers
        let dos_header = unsafe { &*(module_base as *const IMAGE_DOS_HEADER) };
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(anyhow!("Invalid DOS header"));
        }

        let nt_headers = unsafe { &*((module_base as usize + dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS) };
        if nt_headers.Signature != IMAGE_NT_SIGNATURE {
            return Err(anyhow!("Invalid NT headers"));
        }

        // Get import directory
        let import_dir = &nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
        if import_dir.Size == 0 {
            return Err(anyhow!("No import directory found"));
        }

        // Find target function in IAT
        let mut import_desc = unsafe { &*((module_base as usize + import_dir.VirtualAddress as usize) as *const IMAGE_IMPORT_DESCRIPTOR) };
        while import_desc.Name != 0 {
            let dll_name = unsafe { std::ffi::CStr::from_ptr((module_base as usize + import_desc.Name as usize) as *const i8) };
            let thunk_data = unsafe { &*((module_base as usize + import_desc.FirstThunk as usize) as *const IMAGE_THUNK_DATA) };

            // Check if this is the target function
            if thunk_data.u1.AddressOfData != 0 {
                let import_by_name_ptr = unsafe {
                    (module_base as *const u8).add(thunk_data.u1.AddressOfData as usize) as *const IMAGE_IMPORT_BY_NAME
                };
                let import_by_name = unsafe { &*import_by_name_ptr };
                let func_name = unsafe { std::ffi::CStr::from_ptr(&import_by_name.Name as *const i8) };

                if func_name.to_str()? == self.target_function {
                    // Get the function address first as a standalone variable
                    let func_ptr = thunk_data.u1.Function as usize;
                    
                    // Save original address
                    self.original_bytes = vec![0; std::mem::size_of::<usize>()];
                    let mut bytes_read = 0;
                    
                    windows_sys::Win32::System::Memory::ReadProcessMemory(
                        process_handle,
                        func_ptr as *const _,
                        self.original_bytes.as_mut_ptr() as *mut _,
                        std::mem::size_of::<usize>(),
                        &mut bytes_read,
                    );

                    // Write hook address
                    let mut bytes_written = 0;
                    windows_sys::Win32::System::Memory::WriteProcessMemory(
                        process_handle,
                        &thunk_data.u1.Function as *const _ as *mut _,
                        hook_bytes.as_ptr() as *const _,
                        std::mem::size_of::<usize>(),
                        &mut bytes_written,
                    );

                    return Ok(());
                }
            }

            import_desc = unsafe { &*((import_desc as *const _ as usize + std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>()) as *const IMAGE_IMPORT_DESCRIPTOR) };
        }

        Err(anyhow!("Target function not found in IAT"))
    }

    fn remove_iat_hook(&mut self, process_handle: HANDLE) -> Result<()> {
        // Implementation for removing IAT hook
        Ok(())
    }

    fn install_eat_hook(&mut self, process_handle: HANDLE, hook_bytes: &[u8]) -> Result<()> {
        // Get module base address
        let module_base = unsafe { GetModuleHandleW(ptr::null()) };
        if module_base == 0 {
            return Err(anyhow!("Failed to get module base address"));
        }

        // Parse PE headers
        let dos_header = unsafe { &*(module_base as *const IMAGE_DOS_HEADER) };
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(anyhow!("Invalid DOS header"));
        }

        let nt_headers = unsafe { &*((module_base as usize + dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS) };
        if nt_headers.Signature != IMAGE_NT_SIGNATURE {
            return Err(anyhow!("Invalid NT headers"));
        }

        // Get export directory
        let export_dir = &nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
        if export_dir.Size == 0 {
            return Err(anyhow!("No export directory found"));
        }

        let export_dir = unsafe { &*((module_base as usize + export_dir.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY) };

        // Find target function in EAT
        let names = unsafe { &*((module_base as usize + export_dir.AddressOfNames as usize) as *const u32) };
        let ordinals = unsafe { &*((module_base as usize + export_dir.AddressOfNameOrdinals as usize) as *const u16) };
        let functions = unsafe { &*((module_base as usize + export_dir.AddressOfFunctions as usize) as *const u32) };

        for i in 0..export_dir.NumberOfNames {
            let name_rva = unsafe { *names.add(i as usize) };
            let name = unsafe { std::ffi::CStr::from_ptr((module_base as usize + name_rva as usize) as *const i8) };

            if name.to_str()? == self.target_function {
                let ordinal = unsafe { *ordinals.add(i as usize) };
                let func_rva = unsafe { *functions.add(ordinal as usize) };
                let func_addr = module_base as usize + func_rva as usize;

                // Save original bytes
                self.original_bytes = vec![0; hook_bytes.len()];
                let mut bytes_read = 0;
                windows_sys::Win32::System::Memory::ReadProcessMemory(
                    process_handle,
                    func_addr as *const _,
                    self.original_bytes.as_mut_ptr() as *mut _,
                    hook_bytes.len(),
                    &mut bytes_read,
                );

                // Write hook bytes
                let mut bytes_written = 0;
                windows_sys::Win32::System::Memory::WriteProcessMemory(
                    process_handle,
                    func_addr as *mut _,
                    hook_bytes.as_ptr() as *const _,
                    hook_bytes.len(),
                    &mut bytes_written,
                );

                return Ok(());
            }
        }

        Err(anyhow!("Target function not found in EAT"))
    }

    fn remove_eat_hook(&mut self, process_handle: HANDLE) -> Result<()> {
        // Implementation for removing EAT hook
        Ok(())
    }

    fn install_veh_hook(&mut self, process_handle: HANDLE, hook_bytes: &[u8]) -> Result<()> {
        // Create a vectored exception handler
        let handler: VEH_EXCEPTION_HANDLER = Some(veh_handler);
        let veh_handle = unsafe { AddVectoredExceptionHandler(1, handler) };
        
        if veh_handle.is_null() {
            return Err(anyhow!("Failed to add vectored exception handler"));
        }

        self.veh_handle = Some(veh_handle);
        self.original_bytes = hook_bytes.to_vec();

        // Set a breakpoint at the target address
        let mut original_byte = [0u8];
        let mut bytes_read = 0;
        unsafe {
            windows_sys::Win32::System::Memory::ReadProcessMemory(
                process_handle,
                self.target_address as *const _,
                original_byte.as_mut_ptr() as *mut _,
                1,
                &mut bytes_read,
            );
        }
        self.original_bytes = original_byte.to_vec();

        let breakpoint_byte = [0xCC];
        let mut bytes_written = 0;
        unsafe {
            windows_sys::Win32::System::Memory::WriteProcessMemory(
                process_handle,
                self.target_address as *mut _,
                breakpoint_byte.as_ptr() as *const _,
                1,
                &mut bytes_written,
            );
        }

        Ok(())
    }

    fn remove_veh_hook(&mut self, process_handle: HANDLE) -> Result<()> {
        if let Some(veh_handle) = self.veh_handle {
            unsafe {
                RemoveVectoredExceptionHandler(veh_handle);
            }
            self.veh_handle = None;
        }

        // Restore original byte
        let mut bytes_written = 0;
        unsafe {
            windows_sys::Win32::System::Memory::WriteProcessMemory(
                process_handle,
                self.target_address as *mut _,
                self.original_bytes.as_ptr() as *const _,
                self.original_bytes.len(),
                &mut bytes_written,
            );
        }

        Ok(())
    }
}

unsafe extern "system" fn veh_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    let exception_record = &*(*exception_info).ExceptionRecord;
    let context = &mut *(*exception_info).ContextRecord;

    match exception_record.ExceptionCode {
        windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_BREAKPOINT => {
            // Handle breakpoint exception
            // Execute hook code
            // Set single-step flag for next instruction
            context.EFlags |= 0x100; // TF flag
            0 // EXCEPTION_CONTINUE_EXECUTION
        }
        windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_SINGLE_STEP => {
            // Handle single-step exception
            // Restore original instruction
            // Continue execution
            0 // EXCEPTION_CONTINUE_EXECUTION
        }
        _ => 1 // EXCEPTION_CONTINUE_SEARCH
    }
}

/// Represents a process monitor
pub struct ProcessMonitor {
    process_id: u32,
    hooks: Vec<ProcessHook>,
    breakpoints: Vec<usize>,
    memory_regions: Vec<MEMORY_BASIC_INFORMATION>,
}

impl ProcessMonitor {
    /// Creates a new process monitor
    pub fn new(process_id: u32) -> Result<Self> {
        Ok(Self {
            process_id,
            hooks: Vec::new(),
            breakpoints: Vec::new(),
            memory_regions: Vec::new(),
        })
    }

    /// Installs a hook in the monitored process
    pub fn install_hook(
        &mut self,
        hook_type: HookType,
        target_address: usize,
        hook_bytes: &[u8],
    ) -> Result<()> {
        let mut hook = ProcessHook::new(self.process_id, hook_type, target_address)?;
        hook.install(hook_bytes)?;
        self.hooks.push(hook);
        Ok(())
    }

    /// Removes all hooks from the monitored process
    pub fn remove_all_hooks(&mut self) -> Result<()> {
        for hook in &mut self.hooks {
            hook.remove()?;
        }
        self.hooks.clear();
        Ok(())
    }

    /// Gets information about the process memory
    pub fn get_memory_info(&self, address: usize) -> Result<MEMORY_BASIC_INFORMATION> {
        let process_handle = unsafe {
            OpenProcess(PROCESS_QUERY_INFORMATION, 0, self.process_id)
        };

        if process_handle == 0 {
            return Err(anyhow!("Failed to open process"));
        }

        let mut memory_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let result = unsafe {
            VirtualQuery(
                address as *const _,
                &mut memory_info as *mut _,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        unsafe {
            CloseHandle(process_handle);
        }

        if result == 0 {
            return Err(anyhow!("Failed to query memory information"));
        }

        Ok(memory_info)
    }

    /// Reads memory from the monitored process
    pub fn read_memory(&self, address: usize, size: usize) -> Result<Vec<u8>> {
        let process_handle = unsafe {
            OpenProcess(PROCESS_VM_READ, 0, self.process_id)
        };

        if process_handle == 0 {
            return Err(anyhow!("Failed to open process"));
        }

        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0;

        let result = unsafe {
            windows_sys::Win32::System::Memory::ReadProcessMemory(
                process_handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                size,
                &mut bytes_read,
            )
        };

        unsafe {
            CloseHandle(process_handle);
        }

        if result == 0 {
            return Err(anyhow!("Failed to read process memory"));
        }

        Ok(buffer)
    }

    /// Writes memory to the monitored process
    pub fn write_memory(&self, address: usize, data: &[u8]) -> Result<()> {
        let process_handle = unsafe {
            OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, self.process_id)
        };

        if process_handle == 0 {
            return Err(anyhow!("Failed to open process"));
        }

        let mut bytes_written = 0;

        let result = unsafe {
            windows_sys::Win32::System::Memory::WriteProcessMemory(
                process_handle,
                address as *mut _,
                data.as_ptr() as *const _,
                data.len(),
                &mut bytes_written,
            )
        };

        unsafe {
            CloseHandle(process_handle);
        }

        if result == 0 {
            return Err(anyhow!("Failed to write process memory"));
        }

        Ok(())
    }

    /// Scans memory for a pattern
    pub fn scan_memory(&self, pattern: &[u8], mask: &[u8]) -> Result<Vec<usize>> {
        let process_handle = unsafe {
            OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, self.process_id)
        };

        if process_handle == 0 {
            return Err(anyhow!("Failed to open process"));
        }

        let mut results = Vec::new();
        let mut address = 0;
        let mut memory_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

        while unsafe {
            VirtualQuery(
                address as *const _,
                &mut memory_info as *mut _,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        } != 0 {
            if memory_info.State == windows_sys::Win32::System::Memory::MEM_COMMIT
                && memory_info.Protect & PAGE_READWRITE != 0
            {
                let mut buffer = vec![0u8; memory_info.RegionSize];
                let mut bytes_read = 0;

                if unsafe {
                    windows_sys::Win32::System::Memory::ReadProcessMemory(
                        process_handle,
                        address as *const _,
                        buffer.as_mut_ptr() as *mut _,
                        memory_info.RegionSize,
                        &mut bytes_read,
                    )
                } != 0 {
                    for i in 0..(buffer.len() - pattern.len()) {
                        let mut found = true;
                        for j in 0..pattern.len() {
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
            }

            address = memory_info.BaseAddress as usize + memory_info.RegionSize;
        }

        unsafe {
            CloseHandle(process_handle);
        }

        Ok(results)
    }

    /// Sets a software breakpoint at the specified address
    pub fn set_breakpoint(&mut self, address: usize) -> Result<()> {
        let process_handle = unsafe {
            OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, 0, self.process_id)
        };

        if process_handle == 0 {
            return Err(anyhow!("Failed to open process"));
        }

        // Save original byte
        let mut original_byte = [0u8];
        let mut bytes_read = 0;
        unsafe {
            windows_sys::Win32::System::Memory::ReadProcessMemory(
                process_handle,
                address as *const _,
                original_byte.as_mut_ptr() as *mut _,
                1,
                &mut bytes_read,
            );
        }

        // Write breakpoint instruction (0xCC)
        let breakpoint_byte = [0xCC];
        let mut bytes_written = 0;
        unsafe {
            windows_sys::Win32::System::Memory::WriteProcessMemory(
                process_handle,
                address as *mut _,
                breakpoint_byte.as_ptr() as *const _,
                1,
                &mut bytes_written,
            );
        }

        self.breakpoints.push(address);

        unsafe {
            CloseHandle(process_handle);
        }

        Ok(())
    }

    /// Removes all breakpoints
    pub fn remove_breakpoints(&mut self) -> Result<()> {
        let process_handle = unsafe {
            OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, 0, self.process_id)
        };

        if process_handle == 0 {
            return Err(anyhow!("Failed to open process"));
        }

        for &address in &self.breakpoints {
            // Read original byte from memory
            let mut original_byte = [0u8];
            let mut bytes_read = 0;
            unsafe {
                windows_sys::Win32::System::Memory::ReadProcessMemory(
                    process_handle,
                    (address - 1) as *const _,
                    original_byte.as_mut_ptr() as *mut _,
                    1,
                    &mut bytes_read,
                );
            }

            // Write original byte back
            let mut bytes_written = 0;
            unsafe {
                windows_sys::Win32::System::Memory::WriteProcessMemory(
                    process_handle,
                    address as *mut _,
                    original_byte.as_ptr() as *const _,
                    1,
                    &mut bytes_written,
                );
            }
        }

        self.breakpoints.clear();

        unsafe {
            CloseHandle(process_handle);
        }

        Ok(())
    }

    /// Suspends all threads in the process
    pub fn suspend_all_threads(&self) -> Result<()> {
        let process_handle = unsafe {
            OpenProcess(PROCESS_ALL_ACCESS, 0, self.process_id)
        };

        if process_handle == 0 {
            return Err(anyhow!("Failed to open process"));
        }

        // Create snapshot of all threads
        let snapshot = unsafe {
            windows_sys::Win32::System::Threading::CreateToolhelp32Snapshot(
                windows_sys::Win32::System::Threading::TH32CS_SNAPTHREAD,
                0,
            )
        };

        if snapshot == INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(process_handle) };
            return Err(anyhow!("Failed to create thread snapshot"));
        }

        let mut thread_entry: windows_sys::Win32::System::Threading::THREADENTRY32 = unsafe { std::mem::zeroed() };
        thread_entry.dwSize = std::mem::size_of::<windows_sys::Win32::System::Threading::THREADENTRY32>() as u32;

        if unsafe { windows_sys::Win32::System::Threading::Thread32First(snapshot, &mut thread_entry) } != 0 {
            loop {
                if thread_entry.th32OwnerProcessID == self.process_id {
                    let thread_handle = unsafe {
                        OpenThread(THREAD_ALL_ACCESS, 0, thread_entry.th32ThreadID)
                    };

                    if thread_handle != 0 {
                        unsafe { SuspendThread(thread_handle) };
                        unsafe { CloseHandle(thread_handle) };
                    }
                }

                if unsafe { windows_sys::Win32::System::Threading::Thread32Next(snapshot, &mut thread_entry) } == 0 {
                    break;
                }
            }
        }

        unsafe {
            CloseHandle(snapshot);
            CloseHandle(process_handle);
        }

        Ok(())
    }

    /// Resumes all threads in the process
    pub fn resume_all_threads(&self) -> Result<()> {
        let process_handle = unsafe {
            OpenProcess(PROCESS_ALL_ACCESS, 0, self.process_id)
        };

        if process_handle == 0 {
            return Err(anyhow!("Failed to open process"));
        }

        // Create snapshot of all threads
        let snapshot = unsafe {
            windows_sys::Win32::System::Threading::CreateToolhelp32Snapshot(
                windows_sys::Win32::System::Threading::TH32CS_SNAPTHREAD,
                0,
            )
        };

        if snapshot == INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(process_handle) };
            return Err(anyhow!("Failed to create thread snapshot"));
        }

        let mut thread_entry: windows_sys::Win32::System::Threading::THREADENTRY32 = unsafe { std::mem::zeroed() };
        thread_entry.dwSize = std::mem::size_of::<windows_sys::Win32::System::Threading::THREADENTRY32>() as u32;

        if unsafe { windows_sys::Win32::System::Threading::Thread32First(snapshot, &mut thread_entry) } != 0 {
            loop {
                if thread_entry.th32OwnerProcessID == self.process_id {
                    let thread_handle = unsafe {
                        OpenThread(THREAD_ALL_ACCESS, 0, thread_entry.th32ThreadID)
                    };

                    if thread_handle != 0 {
                        unsafe { ResumeThread(thread_handle) };
                        unsafe { CloseHandle(thread_handle) };
                    }
                }

                if unsafe { windows_sys::Win32::System::Threading::Thread32Next(snapshot, &mut thread_entry) } == 0 {
                    break;
                }
            }
        }

        unsafe {
            CloseHandle(snapshot);
            CloseHandle(process_handle);
        }

        Ok(())
    }

    /// Gets the context of a specific thread
    pub fn get_thread_context(&self, thread_id: u32) -> Result<CONTEXT> {
        let thread_handle = unsafe {
            OpenThread(THREAD_ALL_ACCESS, 0, thread_id)
        };

        if thread_handle == 0 {
            return Err(anyhow!("Failed to open thread"));
        }

        let mut context: CONTEXT = unsafe { std::mem::zeroed() };
        context.ContextFlags = CONTEXT_ALL;

        if unsafe { GetThreadContext(thread_handle, &mut context) } == 0 {
            unsafe { CloseHandle(thread_handle) };
            return Err(anyhow!("Failed to get thread context"));
        }

        unsafe { CloseHandle(thread_handle) };
        Ok(context)
    }

    /// Sets the context of a specific thread
    pub fn set_thread_context(&self, thread_id: u32, context: &CONTEXT) -> Result<()> {
        let thread_handle = unsafe {
            OpenThread(THREAD_ALL_ACCESS, 0, thread_id)
        };

        if thread_handle == 0 {
            return Err(anyhow!("Failed to open thread"));
        }

        if unsafe { SetThreadContext(thread_handle, context) } == 0 {
            unsafe { CloseHandle(thread_handle) };
            return Err(anyhow!("Failed to set thread context"));
        }

        unsafe { CloseHandle(thread_handle) };
        Ok(())
    }

    /// Scans memory for a pattern with advanced options
    pub fn advanced_scan_memory(
        &self,
        pattern: &[u8],
        mask: &[u8],
        start_address: Option<usize>,
        end_address: Option<usize>,
        protection: Option<u32>,
    ) -> Result<Vec<usize>> {
        let process_handle = unsafe {
            OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, self.process_id)
        };

        if process_handle == 0 {
            return Err(anyhow!("Failed to open process"));
        }

        let mut results = Vec::new();
        let mut address = start_address.unwrap_or(0);
        let mut memory_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

        while unsafe {
            VirtualQuery(
                address as *const _,
                &mut memory_info as *mut _,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        } != 0 {
            if let Some(end) = end_address {
                if address >= end {
                    break;
                }
            }

            if memory_info.State == windows_sys::Win32::System::Memory::MEM_COMMIT
                && (protection.is_none() || memory_info.Protect & protection.unwrap() != 0)
            {
                let mut buffer = vec![0u8; memory_info.RegionSize];
                let mut bytes_read = 0;

                if unsafe {
                    windows_sys::Win32::System::Memory::ReadProcessMemory(
                        process_handle,
                        address as *const _,
                        buffer.as_mut_ptr() as *mut _,
                        memory_info.RegionSize,
                        &mut bytes_read,
                    )
                } != 0 {
                    for i in 0..(buffer.len() - pattern.len()) {
                        let mut found = true;
                        for j in 0..pattern.len() {
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
            }

            address = memory_info.BaseAddress as usize + memory_info.RegionSize;
        }

        unsafe {
            CloseHandle(process_handle);
        }

        Ok(results)
    }
}

impl Drop for ProcessMonitor {
    fn drop(&mut self) {
        self.remove_all_hooks().ok();
        self.remove_breakpoints().ok();
    }
}

// Add safe pointer helper functions
fn ptr_to_usize<T>(ptr: *const T) -> usize {
    ptr as usize
}

fn usize_to_ptr<T>(addr: usize) -> *const T {
    addr as *const T
}

fn usize_to_ptr_mut<T>(addr: usize) -> *mut T {
    addr as *mut T
} 