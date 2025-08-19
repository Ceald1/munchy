use clap::Parser;
use windows::Win32::Foundation::HANDLE;
mod utils;

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
"#;

fn main() {
    let cli = CLI::parse();
    println!("{}", ART);
    let op:Vec<String> = cli.op;
    for o in op{
        match o.as_str(){
            "test" => {
                let sysPID: u32 = utils::token::getSysProcess();
                let woot: Option<HANDLE> = utils::token::get_system(sysPID);
                println!("{:?}", woot)
            }
            _ => {
                todo!("")
            }
        }
    }
}
