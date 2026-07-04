use std::process::ExitCode;

use batman::App;

fn main() -> ExitCode {
    match App::from_env().and_then(|app| app.run()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}
