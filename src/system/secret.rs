use std::io::{self, IsTerminal, Write};

use crate::errors::{BatmanError, BatmanResult};

pub fn read_secret(prompt: &str) -> BatmanResult<String> {
    if !io::stdin().is_terminal() {
        return Err(BatmanError::Config(
            "private key prompt requires an interactive terminal".to_string(),
        ));
    }
    eprint!("{prompt}");
    io::stderr()
        .flush()
        .map_err(|error| BatmanError::io("flush private key prompt", error))?;
    let result = read_line_without_echo();
    eprintln!();
    result.map(|value| value.trim().to_string())
}

#[cfg(unix)]
fn read_line_without_echo() -> BatmanResult<String> {
    use std::os::fd::AsRawFd;

    let stdin = io::stdin();
    let fd = stdin.as_raw_fd();
    let mut termios = unsafe {
        let mut termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut termios) != 0 {
            return Err(BatmanError::io(
                "read terminal settings",
                io::Error::last_os_error(),
            ));
        }
        termios
    };
    let original = termios;
    termios.c_lflag &= !libc::ECHO;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) } != 0 {
        return Err(BatmanError::io(
            "disable terminal echo",
            io::Error::last_os_error(),
        ));
    }
    let mut line = String::new();
    let read_result = stdin.read_line(&mut line);
    let restore_result = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &original) };
    if restore_result != 0 {
        return Err(BatmanError::io(
            "restore terminal echo",
            io::Error::last_os_error(),
        ));
    }
    read_result.map_err(|error| BatmanError::io("read private key", error))?;
    Ok(line)
}

#[cfg(windows)]
fn read_line_without_echo() -> BatmanResult<String> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
    };

    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(BatmanError::io(
            "open console input",
            io::Error::last_os_error(),
        ));
    }
    let mut mode = 0_u32;
    if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
        return Err(BatmanError::io(
            "read console mode",
            io::Error::last_os_error(),
        ));
    }
    let new_mode = mode & !ENABLE_ECHO_INPUT;
    if unsafe { SetConsoleMode(handle, new_mode) } == 0 {
        return Err(BatmanError::io(
            "disable console echo",
            io::Error::last_os_error(),
        ));
    }
    let mut line = String::new();
    let read_result = io::stdin().read_line(&mut line);
    let restore_result = unsafe { SetConsoleMode(handle, mode) };
    if restore_result == 0 {
        return Err(BatmanError::io(
            "restore console echo",
            io::Error::last_os_error(),
        ));
    }
    read_result.map_err(|error| BatmanError::io("read private key", error))?;
    Ok(line)
}

#[cfg(not(any(unix, windows)))]
fn read_line_without_echo() -> BatmanResult<String> {
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|error| BatmanError::io("read private key", error))?;
    Ok(line)
}
