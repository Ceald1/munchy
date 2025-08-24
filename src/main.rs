use clap::Parser;
use windows::Win32::Foundation::HANDLE;
mod utils;

// initialize struct for commandline app
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)] // Reads version from Cargo.toml, uses doc comment for about
struct CLI {
    #[arg(num_args(0..))]
    op: Vec<String>,
    #[arg(short, long, action = clap::ArgAction::SetTrue)] // Defines -v/--verbose flag
   verbose: bool,
}
const ART:&str = r#"
_____________,-.___     _
|____        { {]_]_]   [_]
|___ `-----.__\ \_]_]_    . `
|   `-----.____} }]_]_]_   ,
|_____________/ {_]_]_]_] , `
            `-'
"#; // art

fn main() {
    let cli = CLI::parse(); // initialize cli variable for parsing
    println!("{}", ART); // print art
    let op:Vec<String> = cli.op; // convert ops to a Vc<String> to loop through.
    for o in op{
        match o.as_str(){ // match case statements (rust's version of case switch statements)
            "test" => { 
                unsafe{
                    println!("Starting test...");
                    let a_data: Option<*const std::ffi::c_void> = None;
                    let a = utils::api::cred_handle(a_data, Some("Administrator@TEST.LOCAL".to_string()), false);
                    let secHandle = a.unwrap();
                    println!("Got secHandle");
                    
                    let flags = windows::Win32::Security::Authentication::Identity::ISC_REQ_MUTUAL_AUTH | windows::Win32::Security::Authentication::Identity::ISC_REQ_INTEGRITY | windows::Win32::Security::Authentication::Identity::ISC_REQ_CONNECTION;
                    const SPN: &str = "HTTP/WIN-OBNU3U147RE.TEST.LOCAL";
                    let b = utils::api::NewSecurityContext(flags, secHandle, SPN.to_string());
                    println!("NewSecurityContext completed: b={:?}", b.unwrap());
                    
                    let inCred = utils::api::cred_handle(a_data, Some("Administrator@TEST.LOCAL".to_string()), true).unwrap();
                    // println!("Got inCred, about to call UpdateSecurityContext");
                    
                    // let d = utils::api::UpdateSecurityContext(flags, inCred, SPN.to_string(), b.unwrap(), c.unwrap());
                    // println!("UpdateSecurityContext completed: {:?}", d.is_some());
                }
            }
            "elevate" => { // elevate token (might be needed later)
                let sysPID: u32 = utils::token::getSysProcess();
                let woot: Option<HANDLE> = utils::token::get_system(sysPID);
                println!("{:?}", woot)
            }
            _ => {
                todo!("") // default
            }
        }
    }
}
