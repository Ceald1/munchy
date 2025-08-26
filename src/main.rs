use clap::{Parser, command};
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
    // args
    #[arg(short, long, default_value = "")]
    upn: String,

    #[arg(short, long, default_value = "")]
    spn: String,

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

                }
            }
            "elevate" => { // elevate token (might be needed later)
                let sysPID: u32 = utils::token::getSysProcess();
                let woot: Option<HANDLE> = utils::token::get_system(sysPID);
                println!("{:?}", woot)
            }
            
            "tgs" => {
                unsafe {

                    let cred_data: Option<*const std::ffi::c_void> = None;
                    let secHandle = utils::api::cred_handle(cred_data, Some(cli.upn.clone()), false).unwrap();
                    let flags = windows::Win32::Security::Authentication::Identity::ISC_REQ_INTEGRITY | windows::Win32::Security::Authentication::Identity::ISC_REQ_CONNECTION;

                    let securityContext = utils::api::NewSecurityContext(flags, secHandle, cli.spn.clone());
                    println!("got TGS for user: {:?} for service: {:?}", cli.upn, cli.spn)

                }
            }
            _ => {
                todo!("") // default
            }
        }
    }
}
