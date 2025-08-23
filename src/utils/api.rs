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

};
use windows::Win32::Security::Credentials::SecHandle;
use windows::Win32::Foundation::LocalFree;

use windows::Win32::Security::ImpersonateLoggedOnUser;
use windows::Win32::Foundation::{HANDLE, LUID, NTSTATUS};

use windows_core::{Error, PSTR, PWSTR, PCSTR};


// LSA Stuff
pub unsafe fn init_kerberos_cred_handle(service_principal_name: String) -> Option<HANDLE>{
    unsafe{
        // initialize credential handle
        let spn_vec = service_principal_name.into_bytes();
        spn_vec.push(0);
        let mut spn: &'static [u8] = &spn_vec;
        let resp = unsafe { initHandle() };
        let pkg_name = b"Kerberos\0";

        if resp == None {
            return None;
        }
        let lsa_handle = resp.unwrap();
        
        let pkg_found = unsafe { lookup_kerb(lsa_handle) };
        if pkg_found == false{
            return None;
        }
        let ntstatus = AcquireCredentialsHandleA(
            PCSTR(spn.as_ptr()),
            PCSTR(pkg_name.as_ptr()),
        );

        return None;
    }
}

unsafe fn initHandle() -> Option<HANDLE> {
    unsafe{
        let mut lsa_handle:HANDLE = HANDLE(std::ptr::null_mut());
        let ntstatus:NTSTATUS = LsaConnectUntrusted(
            &mut lsa_handle as *mut HANDLE,
        );
        if ntstatus.0 != 0 {
            println!("NTSTATUS initHandle (hex): 0x{:08X}", ntstatus.0 as u32);
            return None;
        }
        return Some(lsa_handle);
    }
}


unsafe fn lookup_kerb(lsa_handle: HANDLE)-> bool {
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
            return true;
        } else {
            println!("NTSTATUS (hex): 0x{:08X}", ntstatus.0 as u32);
            return false;
        }
    }
}