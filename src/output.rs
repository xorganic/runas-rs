use anyhow::Result;
use std::{
    io::{self, Write},
    process::ExitStatus,
};
use windows_sys::Win32::{
    Foundation::HANDLE,
    System::Threading::{WaitForSingleObject, INFINITE},
};

use crate::pipe::Pipe;

/// Represents the output format for process output
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Plain text output
    Text,
    /// JSON formatted output
    Json,
    /// XML formatted output
    Xml,
    /// Binary output (raw bytes)
    Binary,
}

/// Represents the output destination for process output
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputDestination {
    /// Output to string
    String,
    /// Output to file
    File,
    /// Output to stdout
    Stdout,
    /// Output to stderr
    Stderr,
    /// Output to both stdout and stderr
    Both,
}

/// Represents the output options for process output
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputOptions {
    /// The format of the output
    pub format: OutputFormat,
    /// The destination of the output
    pub destination: OutputDestination,
    /// Whether to include the exit code in the output
    pub include_exit_code: bool,
    /// Whether to include the process ID in the output
    pub include_pid: bool,
    /// Whether to include the command in the output
    pub include_command: bool,
    /// Whether to include timestamps in the output
    pub include_timestamp: bool,
    /// Whether to wait for the process to complete
    pub wait_for_completion: bool,
}

impl Default for OutputOptions {
    fn default() -> Self {
        Self {
            format: OutputFormat::Text,
            destination: OutputDestination::String,
            include_exit_code: false,
            include_pid: false,
            include_command: false,
            include_timestamp: false,
            wait_for_completion: true,
        }
    }
}

/// Represents the output of a process
#[derive(Debug, Clone)]
pub struct ProcessOutput {
    /// The standard output of the process
    pub stdout: String,
    /// The standard error of the process
    pub stderr: String,
    /// The exit code of the process
    pub exit_code: Option<i32>,
    /// The process ID
    pub pid: Option<u32>,
    /// The command that was executed
    pub command: Option<String>,
    /// The timestamp when the process was started
    pub start_time: Option<std::time::SystemTime>,
    /// The timestamp when the process was completed
    pub end_time: Option<std::time::SystemTime>,
}

impl ProcessOutput {
    /// Creates a new `ProcessOutput` instance
    pub fn new() -> Self {
        Self {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: None,
            pid: None,
            command: None,
            start_time: None,
            end_time: None,
        }
    }

    /// Sets the standard output
    pub fn with_stdout(mut self, stdout: String) -> Self {
        self.stdout = stdout;
        self
    }

    /// Sets the standard error
    pub fn with_stderr(mut self, stderr: String) -> Self {
        self.stderr = stderr;
        self
    }

    /// Sets the exit code
    pub fn with_exit_code(mut self, exit_code: i32) -> Self {
        self.exit_code = Some(exit_code);
        self
    }

    /// Sets the process ID
    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Sets the command
    pub fn with_command(mut self, command: String) -> Self {
        self.command = Some(command);
        self
    }

    /// Sets the start time
    pub fn with_start_time(mut self, start_time: std::time::SystemTime) -> Self {
        self.start_time = Some(start_time);
        self
    }

    /// Sets the end time
    pub fn with_end_time(mut self, end_time: std::time::SystemTime) -> Self {
        self.end_time = Some(end_time);
        self
    }

    /// Formats the output according to the specified format
    pub fn format(&self, format: OutputFormat) -> String {
        match format {
            OutputFormat::Text => self.format_text(),
            OutputFormat::Json => self.format_json(),
            OutputFormat::Xml => self.format_xml(),
            OutputFormat::Binary => self.format_binary(),
        }
    }

    /// Formats the output as plain text
    fn format_text(&self) -> String {
        let mut output = String::new();

        if let Some(command) = &self.command {
            output.push_str(&format!("Command: {}\n", command));
        }

        if let Some(pid) = &self.pid {
            output.push_str(&format!("PID: {}\n", pid));
        }

        if let Some(start_time) = &self.start_time {
            output.push_str(&format!("Start Time: {:?}\n", start_time));
        }

        if let Some(end_time) = &self.end_time {
            output.push_str(&format!("End Time: {:?}\n", end_time));
        }

        if !self.stdout.is_empty() {
            output.push_str("STDOUT:\n");
            output.push_str(&self.stdout);
            output.push_str("\n");
        }

        if !self.stderr.is_empty() {
            output.push_str("STDERR:\n");
            output.push_str(&self.stderr);
            output.push_str("\n");
        }

        if let Some(exit_code) = &self.exit_code {
            output.push_str(&format!("Exit Code: {}\n", exit_code));
        }

        output
    }

    /// Formats the output as JSON
    fn format_json(&self) -> String {
        let mut json = String::new();
        json.push_str("{\n");

        if let Some(command) = &self.command {
            json.push_str(&format!("  \"command\": \"{}\",\n", command));
        }

        if let Some(pid) = &self.pid {
            json.push_str(&format!("  \"pid\": {},\n", pid));
        }

        if let Some(start_time) = &self.start_time {
            json.push_str(&format!("  \"start_time\": \"{:?}\",\n", start_time));
        }

        if let Some(end_time) = &self.end_time {
            json.push_str(&format!("  \"end_time\": \"{:?}\",\n", end_time));
        }

        json.push_str(&format!("  \"stdout\": \"{}\",\n", self.stdout.replace("\"", "\\\"")).replace("\n", "\\n"));
        json.push_str(&format!("  \"stderr\": \"{}\",\n", self.stderr.replace("\"", "\\\"")).replace("\n", "\\n"));

        if let Some(exit_code) = &self.exit_code {
            json.push_str(&format!("  \"exit_code\": {}\n", exit_code));
        } else {
            json.push_str("  \"exit_code\": null\n");
        }

        json.push_str("}");
        json
    }

    /// Formats the output as XML
    fn format_xml(&self) -> String {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<process_output>\n");

        if let Some(command) = &self.command {
            xml.push_str(&format!("  <command>{}</command>\n", command));
        }

        if let Some(pid) = &self.pid {
            xml.push_str(&format!("  <pid>{}</pid>\n", pid));
        }

        if let Some(start_time) = &self.start_time {
            xml.push_str(&format!("  <start_time>{:?}</start_time>\n", start_time));
        }

        if let Some(end_time) = &self.end_time {
            xml.push_str(&format!("  <end_time>{:?}</end_time>\n", end_time));
        }

        xml.push_str("  <stdout>\n");
        xml.push_str(&format!("    <![CDATA[{}]]>\n", self.stdout));
        xml.push_str("  </stdout>\n");

        xml.push_str("  <stderr>\n");
        xml.push_str(&format!("    <![CDATA[{}]]>\n", self.stderr));
        xml.push_str("  </stderr>\n");

        if let Some(exit_code) = &self.exit_code {
            xml.push_str(&format!("  <exit_code>{}</exit_code>\n", exit_code));
        }

        xml.push_str("</process_output>");
        xml
    }

    /// Formats the output as binary (raw bytes)
    fn format_binary(&self) -> String {
        // For binary output, we'll just return the raw bytes as a hex string
        let mut binary = String::new();
        
        // Add stdout
        for byte in self.stdout.bytes() {
            binary.push_str(&format!("{:02x}", byte));
        }
        
        // Add stderr
        for byte in self.stderr.bytes() {
            binary.push_str(&format!("{:02x}", byte));
        }
        
        binary
    }
}

/// Handles process output
pub struct OutputHandler {
    /// The output options
    options: OutputOptions,
    /// The process output
    output: ProcessOutput,
    /// The process handle
    process_handle: Option<HANDLE>,
}

impl OutputHandler {
    /// Creates a new `OutputHandler` instance
    pub fn new(options: OutputOptions) -> Self {
        Self {
            options,
            output: ProcessOutput::new(),
            process_handle: None,
        }
    }

    /// Sets the process handle
    pub fn with_process_handle(mut self, handle: HANDLE) -> Self {
        self.process_handle = Some(handle);
        self
    }

    /// Sets the process ID
    pub fn with_pid(mut self, pid: u32) -> Self {
        self.output = self.output.with_pid(pid);
        self
    }

    /// Sets the command
    pub fn with_command(mut self, command: String) -> Self {
        self.output = self.output.with_command(command);
        self
    }

    /// Sets the start time
    pub fn with_start_time(mut self, start_time: std::time::SystemTime) -> Self {
        self.output = self.output.with_start_time(start_time);
        self
    }

    /// Captures the output from a pipe
    pub fn capture_output(&mut self, read_handle: HANDLE) -> Result<()> {
        // Read the output from the pipe
        let output = Pipe::read(read_handle);
        
        // Set the output
        self.output = self.output.with_stdout(output);
        
        Ok(())
    }

    /// Captures the error output from a pipe
    pub fn capture_error(&mut self, read_handle: HANDLE) -> Result<()> {
        // Read the error output from the pipe
        let error = Pipe::read(read_handle);
        
        // Set the error output
        self.output = self.output.with_stderr(error);
        
        Ok(())
    }

    /// Waits for the process to complete
    pub fn wait_for_completion(&mut self) -> Result<()> {
        if let Some(handle) = self.process_handle {
            unsafe {
                // Wait for the process to complete
                if WaitForSingleObject(handle, INFINITE) != 0 {
                    return Err(anyhow::anyhow!("Failed to wait for process completion"));
                }
                
                // Get the exit code
                let mut exit_code = 0;
                if windows_sys::Win32::System::Threading::GetExitCodeProcess(handle, &mut exit_code) == 0 {
                    return Err(anyhow::anyhow!("Failed to get exit code"));
                }
                
                // Set the exit code
                self.output = self.output.with_exit_code(exit_code);
                
                // Set the end time
                self.output = self.output.with_end_time(std::time::SystemTime::now());
            }
        }
        
        Ok(())
    }

    /// Gets the formatted output
    pub fn get_formatted_output(&self) -> String {
        self.output.format(self.options.format)
    }

    /// Writes the output to the specified destination
    pub fn write_output(&self, writer: &mut dyn Write) -> io::Result<()> {
        let output = self.get_formatted_output();
        
        match self.options.destination {
            OutputDestination::String => {
                // For string output, we just return the formatted output
                // This is handled by get_formatted_output
                Ok(())
            },
            OutputDestination::File => {
                // For file output, we write to the provided writer
                writer.write_all(output.as_bytes())?;
                Ok(())
            },
            OutputDestination::Stdout => {
                // For stdout output, we write to stdout
                io::stdout().write_all(output.as_bytes())?;
                Ok(())
            },
            OutputDestination::Stderr => {
                // For stderr output, we write to stderr
                io::stderr().write_all(output.as_bytes())?;
                Ok(())
            },
            OutputDestination::Both => {
                // For both stdout and stderr output, we write to both
                io::stdout().write_all(output.as_bytes())?;
                io::stderr().write_all(output.as_bytes())?;
                Ok(())
            },
        }
    }

    /// Gets the raw output
    pub fn get_raw_output(&self) -> &ProcessOutput {
        &self.output
    }
} 