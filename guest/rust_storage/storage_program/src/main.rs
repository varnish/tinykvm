use std::process::ExitCode;

#[no_mangle]
extern "C" fn remote_function(arg: fn(i32) -> i32, value: i32) -> i32 {
	return arg(value);
}

fn main() -> ExitCode
{
	println!("Hello, Storage World!");
	return ExitCode::from(123);
}
