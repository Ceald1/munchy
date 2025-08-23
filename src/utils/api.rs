use std::any::Any;
use std::ptr;

use windows::Win32::Security::Authentication::Identity::{
    AcquireCredentialsHandleA,
    LsaCallAuthenticationPackage,
    LsaConnectUntrusted,
    LsaFreeReturnBuffer,
    LsaEnumerateLogonSessions,
    LsaGetLogonSessionData,
    LsaLookupAuthenticationPackage,
    InitializeSecurityContextA,

    KERB_CRYPTO_KEY_TYPE, KERB_PROTOCOL_MESSAGE_TYPE, KERB_QUERY_TKT_CACHE_REQUEST,
	    KERB_QUERY_TKT_CACHE_RESPONSE, KERB_RETRIEVE_TKT_REQUEST, KERB_RETRIEVE_TKT_RESPONSE, KERB_SUBMIT_TKT_REQUEST,
		KERB_TICKET_CACHE_INFO_EX, LSA_STRING, SECURITY_LOGON_SESSION_DATA,
        KERB_REQUEST_FLAGS, ISC_REQ_FLAGS, SECURITY_NATIVE_DREP, SECBUFFER_TOKEN, SECBUFFER_VERSION,

    SECPKG_CRED_OUTBOUND,ISC_REQ_MUTUAL_AUTH, SecBuffer, SecBufferDesc,

};
use windows::Win32::Security::Credentials::SecHandle;
use windows::Win32::Foundation::LocalFree;

use windows::Win32::Security::ImpersonateLoggedOnUser;
use windows::Win32::Foundation::{HANDLE, LUID, NTSTATUS};

use windows_core::{Error, PSTR, PWSTR, PCSTR};

const MAX_TOKEN_SIZE: usize = 48 * 1024;

// LSA Stuff, public functions
pub unsafe fn cred_handle<T>(pre_auth: Option<T>,user_principal_name: Option<String>) -> Option<SecHandle>{
    // make a Cred Handle, user_principal_name is which UPN to use, None will be the current user
    unsafe{
        // convert upn to bytes array pointer
        let upn: PCSTR = user_principal_name.as_ref().map(|s| {
            // Convert to bytes and null-terminate
            let mut upn_vec = s.clone().into_bytes();
            upn_vec.push(0);
            PCSTR(upn_vec.as_ptr())
        }).unwrap();
        
        

        let resp = initHandle(); // initialize a handle for looking up the kerberos package
        let pkg_name = b"Kerberos\0"; // package name

        if resp == None {
            return None;
        }
        let lsa_handle = resp.unwrap();
        
        let pkg_found = lookup_kerb(lsa_handle); // lookup  kerberos package
        if pkg_found == false{
            return None;
        }
        let pauth_ptr: Option<*const std::ffi::c_void> = pre_auth.as_ref().map(|v| v as *const T as *const std::ffi::c_void);
        let mut credHandle: SecHandle = SecHandle::default();
        let mut lifetime = 0;
        let status = AcquireCredentialsHandleA(
                upn,
                // PCSTR(upn.as_ptr()), // user principal name goes in as the first argument
                PCSTR(pkg_name.as_ptr()), // package name
                SECPKG_CRED_OUTBOUND, // user flags
                None, // logonID (None for current user)
                pauth_ptr, // Pre Authentication data
                None, // function for callback to retrieve creds
                None, // argument for callback function
                &mut credHandle, // output handle
                Some(ptr::addr_of_mut!(lifetime)), // lifetime of the credentials

            );
        
        match status { // check if ok
            Ok(()) => return Some(credHandle),
            Err(e) => {
                eprintln!("AcquireCredentialsHandleA failed: {:?}", e);
                return None;
            },
        }
    }
}

pub unsafe fn NewSecurityContext(flags: ISC_REQ_FLAGS, mut credHandle: SecHandle, service_principal_name: String) -> Option<SecBufferDesc> {
    unsafe {
        // convert spn to bytes array pointer
        let mut spn = service_principal_name.as_ptr() as *const i8;
        let mut lifetime = 0;


        //context crap, it just gets the output structure ready for the function.
        let mut buf = Vec::with_capacity(MAX_TOKEN_SIZE);
        buf.resize(MAX_TOKEN_SIZE, 0);
        let mut cx: SecHandle = SecHandle::default();
        let mut cx_attrs = 0u32;
        let mut sec_buffer = [SecBuffer {
            BufferType: SECBUFFER_TOKEN,
            cbBuffer: MAX_TOKEN_SIZE as u32,
            pvBuffer: buf.as_mut_ptr() as *mut std::ffi::c_void,
        }];
        let mut buffer_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: sec_buffer.len() as u32,
            pBuffers: sec_buffer.as_mut_ptr(),
        };



        
        // initialize security context
        let status = InitializeSecurityContextA(
            Some(&mut credHandle),
            None,
            Some(spn),
            flags,
            0,
            SECURITY_NATIVE_DREP,
            None,
            0,
            Some(&mut cx),
            Some(&mut buffer_desc),
            &mut cx_attrs,
            Some(ptr::addr_of_mut!(lifetime)), // lifetime of the credentials,
        );
        match status {
            windows::Win32::Foundation::SEC_E_OK => {
                // Access the buffer from sec_buffer, not buffer_desc
                buf.resize(sec_buffer[0].cbBuffer as usize, 0);
                if !buf.is_empty() {
                    return Some(buffer_desc); // return the full buffer
                } else {
                    return None;
                }
            }
            windows::Win32::Foundation::SEC_I_CONTINUE_NEEDED => {
                // Handle the case where more data is needed
                println!("more data is needed! This is Normal and NOT an error!");
                buf.resize(sec_buffer[0].cbBuffer as usize, 0);
                return Some(buffer_desc); // return the full buffer
            }
            error_code => {
                eprintln!("InitializeSecurityContextA failed with error: 0x{:X}", error_code.0);
                return None;
            }
        }
    }
    
}








// private functions
unsafe fn initHandle() -> Option<HANDLE> {
    // helper functions for prep
    unsafe{
        let mut lsa_handle:HANDLE = HANDLE(std::ptr::null_mut()); // initialize handle
        let ntstatus:NTSTATUS = LsaConnectUntrusted(
            &mut lsa_handle as *mut HANDLE,
        ); // establish untrusted connection
        if ntstatus.0 != 0 {
            println!("NTSTATUS initHandle (hex): 0x{:08X}", ntstatus.0 as u32);
            return None;
        }
        return Some(lsa_handle);
    }
}


unsafe fn lookup_kerb(lsa_handle: HANDLE)-> bool {
    // lookup kerberos package (just for error checking, don't really NEED this)
    unsafe{
        let pkg_name = b"Kerberos\0";
        let mut pkg_name_struct = LSA_STRING {
            Length: (pkg_name.len() - 1) as u16,
            MaximumLength: pkg_name.len() as u16,
            Buffer: PSTR(pkg_name.as_ptr() as *mut u8),
        };

        let mut pkg_handle: u32 = 0;

        // This will fail with STATUS_INVALID_HANDLE unless lsa_handle is valid
        let ntstatus: NTSTATUS = LsaLookupAuthenticationPackage(
            lsa_handle,
            &mut pkg_name_struct,
            &mut pkg_handle
        );

        

        // Typically, you'd check for success before returning a handle
        if ntstatus.0 == 0 {
            return true; // found kerberos package.
        } else {
            println!("NTSTATUS (hex): 0x{:08X}", ntstatus.0 as u32);
            return false; // can't find it.
        }
    }
}