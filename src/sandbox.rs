use anyhow::{anyhow, Result};
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DuplicateTokenEx, GetTokenInformation, IsTokenRestricted, SECURITY_ATTRIBUTES,
    TOKEN_DUPLICATION, TOKEN_IMPERSONATION, TOKEN_QUERY, TOKEN_RESTRICTED_SIDS, TOKEN_SANDBOX_INERT,
    TOKEN_SECURITY_ATTRIBUTES, TOKEN_USER, TOKEN_ACCESS_MASK, TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DEFAULT_DACL, TOKEN_GROUPS, TOKEN_OWNER, TOKEN_PRIMARY_GROUP, TOKEN_PRIVILEGES,
    TOKEN_SOURCE, TOKEN_STATISTICS, TOKEN_TYPE, TOKEN_USER_SID, TOKEN_VIRTUALIZE_ALLOWED,
    TOKEN_VIRTUALIZE_ENABLED, TOKEN_WRITE_RESTRICTED, TOKEN_READ, TOKEN_WRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, OpenProcessToken, PROCESS_INFORMATION, STARTUPINFOW,
    CREATE_NEW_CONSOLE, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    DETACHED_PROCESS, EXTENDED_STARTUPINFO_PRESENT, CREATE_BREAKAWAY_FROM_JOB,
    CREATE_DEFAULT_ERROR_MODE, CREATE_PROTECTED_PROCESS, CREATE_SECURE_PROCESS,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, QueryInformationJobObject, SetInformationJobObject,
    JOBOBJECT_BASIC_LIMIT_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_JOB_TIME, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME, JOB_OBJECT_LIMIT_PRIORITY_CLASS,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOB_OBJECT_LIMIT_PROCESS_TIME,
    JOB_OBJECT_LIMIT_SCHEDULING_CLASS, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    JOB_OBJECT_LIMIT_SUBSET_AFFINITY, JOB_OBJECT_LIMIT_WORKINGSET,
    JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
    JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_GLOBALATOMS,
    JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
};

/// Represents different job object limits
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobLimit {
    /// Breakaway OK
    BreakawayOk,
    /// Die on unhandled exception
    DieOnUnhandledException,
    /// Job memory limit
    JobMemory,
    /// Job time limit
    JobTime,
    /// Kill on job close
    KillOnJobClose,
    /// Preserve job time
    PreserveJobTime,
    /// Priority class limit
    PriorityClass,
    /// Process memory limit
    ProcessMemory,
    /// Process time limit
    ProcessTime,
    /// Scheduling class limit
    SchedulingClass,
    /// Silent breakaway OK
    SilentBreakawayOk,
    /// Subset affinity limit
    SubsetAffinity,
    /// Working set limit
    WorkingSet,
}

impl JobLimit {
    /// Convert to Windows job object limit flags
    pub fn to_limit_flags(&self) -> u32 {
        match self {
            JobLimit::BreakawayOk => JOB_OBJECT_LIMIT_BREAKAWAY_OK,
            JobLimit::DieOnUnhandledException => JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
            JobLimit::JobMemory => JOB_OBJECT_LIMIT_JOB_MEMORY,
            JobLimit::JobTime => JOB_OBJECT_LIMIT_JOB_TIME,
            JobLimit::KillOnJobClose => JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JobLimit::PreserveJobTime => JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME,
            JobLimit::PriorityClass => JOB_OBJECT_LIMIT_PRIORITY_CLASS,
            JobLimit::ProcessMemory => JOB_OBJECT_LIMIT_PROCESS_MEMORY,
            JobLimit::ProcessTime => JOB_OBJECT_LIMIT_PROCESS_TIME,
            JobLimit::SchedulingClass => JOB_OBJECT_LIMIT_SCHEDULING_CLASS,
            JobLimit::SilentBreakawayOk => JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
            JobLimit::SubsetAffinity => JOB_OBJECT_LIMIT_SUBSET_AFFINITY,
            JobLimit::WorkingSet => JOB_OBJECT_LIMIT_WORKINGSET,
        }
    }
}

/// Represents different UI restrictions for job objects
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobUIRestriction {
    /// Desktop restriction
    Desktop,
    /// Display settings restriction
    DisplaySettings,
    /// Exit windows restriction
    ExitWindows,
    /// Global atoms restriction
    GlobalAtoms,
    /// Handles restriction
    Handles,
    /// Read clipboard restriction
    ReadClipboard,
    /// System parameters restriction
    SystemParameters,
    /// Write clipboard restriction
    WriteClipboard,
}

impl JobUIRestriction {
    /// Convert to Windows job object UI restriction flags
    pub fn to_ui_restriction_flags(&self) -> u32 {
        match self {
            JobUIRestriction::Desktop => JOB_OBJECT_UILIMIT_DESKTOP,
            JobUIRestriction::DisplaySettings => JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
            JobUIRestriction::ExitWindows => JOB_OBJECT_UILIMIT_EXITWINDOWS,
            JobUIRestriction::GlobalAtoms => JOB_OBJECT_UILIMIT_GLOBALATOMS,
            JobUIRestriction::Handles => JOB_OBJECT_UILIMIT_HANDLES,
            JobUIRestriction::ReadClipboard => JOB_OBJECT_UILIMIT_READCLIPBOARD,
            JobUIRestriction::SystemParameters => JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
            JobUIRestriction::WriteClipboard => JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
        }
    }
}

/// Represents a job object with isolation capabilities
pub struct JobObject {
    handle: HANDLE,
}

impl JobObject {
    /// Creates a new job object
    pub fn new() -> Result<Self> {
        let handle = unsafe {
            CreateJobObjectW(ptr::null_mut(), ptr::null())
        };

        if handle == 0 {
            return Err(anyhow!("Failed to create job object"));
        }

        Ok(Self { handle })
    }

    /// Assigns a process to the job object
    pub fn assign_process(&self, process_handle: HANDLE) -> Result<()> {
        let result = unsafe {
            AssignProcessToJobObject(self.handle, process_handle)
        };

        if result == 0 {
            return Err(anyhow!("Failed to assign process to job object"));
        }

        Ok(())
    }

    /// Sets job object limits
    pub fn set_limits(&self, limits: &[JobLimit]) -> Result<()> {
        let mut limit_info: JOBOBJECT_BASIC_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        let mut limit_flags = 0;

        for limit in limits {
            limit_flags |= limit.to_limit_flags();
        }

        limit_info.LimitFlags = limit_flags;

        let result = unsafe {
            SetInformationJobObject(
                self.handle,
                JOBOBJECT_BASIC_LIMIT_INFORMATION,
                &limit_info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
            )
        };

        if result == 0 {
            return Err(anyhow!("Failed to set job object limits"));
        }

        Ok(())
    }

    /// Sets job object UI restrictions
    pub fn set_ui_restrictions(&self, restrictions: &[JobUIRestriction]) -> Result<()> {
        let mut ui_restrictions: JOBOBJECT_BASIC_UI_RESTRICTIONS = unsafe { std::mem::zeroed() };
        let mut restriction_flags = 0;

        for restriction in restrictions {
            restriction_flags |= restriction.to_ui_restriction_flags();
        }

        ui_restrictions.UIRestrictionsClass = restriction_flags;

        let result = unsafe {
            SetInformationJobObject(
                self.handle,
                JOBOBJECT_BASIC_UI_RESTRICTIONS,
                &ui_restrictions as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            )
        };

        if result == 0 {
            return Err(anyhow!("Failed to set job object UI restrictions"));
        }

        Ok(())
    }

    /// Gets job object information
    pub fn get_info(&self) -> Result<JOBOBJECT_BASIC_LIMIT_INFORMATION> {
        let mut info: JOBOBJECT_BASIC_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        let mut return_length = 0;

        let result = unsafe {
            QueryInformationJobObject(
                self.handle,
                JOBOBJECT_BASIC_LIMIT_INFORMATION,
                &mut info as *mut _ as *mut _,
                std::mem::size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
                &mut return_length,
            )
        };

        if result == 0 {
            return Err(anyhow!("Failed to get job object information"));
        }

        Ok(info)
    }
}

impl Drop for JobObject {
    fn drop(&mut self) {
        if self.handle != 0 && self.handle != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

/// Represents a sandboxed process
pub struct SandboxedProcess {
    process_info: PROCESS_INFORMATION,
    job_object: Option<JobObject>,
}

impl SandboxedProcess {
    /// Creates a new sandboxed process
    pub fn new(
        application_name: &str,
        command_line: &str,
        job_limits: Option<&[JobLimit]>,
        ui_restrictions: Option<&[JobUIRestriction]>,
    ) -> Result<Self> {
        // Create job object if limits or restrictions are specified
        let job_object = if job_limits.is_some() || ui_restrictions.is_some() {
            let job = JobObject::new()?;
            if let Some(limits) = job_limits {
                job.set_limits(limits)?;
            }
            if let Some(restrictions) = ui_restrictions {
                job.set_ui_restrictions(restrictions)?;
            }
            Some(job)
        } else {
            None
        };

        // Create process
        let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        let app_name_wide: Vec<u16> = application_name.encode_utf16().chain(std::iter::once(0)).collect();
        let cmd_line_wide: Vec<u16> = command_line.encode_utf16().chain(std::iter::once(0)).collect();

        let result = unsafe {
            CreateProcessAsUserW(
                ptr::null_mut(),
                app_name_wide.as_ptr(),
                cmd_line_wide.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut startup_info,
                &mut process_info,
            )
        };

        if result == 0 {
            return Err(anyhow!("Failed to create sandboxed process"));
        }

        // Assign process to job object if one was created
        if let Some(job) = &job_object {
            job.assign_process(process_info.hProcess)?;
        }

        Ok(Self {
            process_info,
            job_object,
        })
    }

    /// Gets the process handle
    pub fn get_process_handle(&self) -> HANDLE {
        self.process_info.hProcess
    }

    /// Gets the thread handle
    pub fn get_thread_handle(&self) -> HANDLE {
        self.process_info.hThread
    }

    /// Gets the process ID
    pub fn get_process_id(&self) -> u32 {
        self.process_info.dwProcessId
    }

    /// Gets the thread ID
    pub fn get_thread_id(&self) -> u32 {
        self.process_info.dwThreadId
    }

    /// Terminates the process
    pub fn terminate(&self) -> Result<()> {
        unsafe {
            CloseHandle(self.process_info.hThread);
            CloseHandle(self.process_info.hProcess);
        }
        Ok(())
    }
}

impl Drop for SandboxedProcess {
    fn drop(&mut self) {
        self.terminate().ok();
    }
} 