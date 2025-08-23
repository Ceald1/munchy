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
            "test" => { // testing
                unsafe{
                    let a_data: Option<*const std::ffi::c_void> = None;
                    let a = utils::api::ap_req(a_data, "krbtgt/TEST.LOCAL".to_string());
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
