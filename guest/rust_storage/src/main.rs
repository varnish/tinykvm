extern "C" { fn remote_function(arg: extern "C" fn(i32) -> i32, value: i32) -> i32; }
use std::process::ExitCode;

#[no_mangle]
extern "C" fn do_calculation(input: i32) -> i32 {
    return unsafe { remote_function(double_int, input) };
}

extern "C" fn double_int(input: i32) -> i32 {
    return input * 2;
}

fn main() -> ExitCode
{
	println!("Hello, world!");
	let result = unsafe { remote_function(double_int, 21) };
	println!("Result from remote function: {}", result);
	return ExitCode::from(result as u8);
}
