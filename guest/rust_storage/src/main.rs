use std::arch::asm;
extern "C" { fn remote_function(arg: extern "C" fn(i32) -> i32, value: i32) -> i32; }
use std::process::ExitCode;

extern "C" fn do_calculation(input: i32) -> i32 {
    return unsafe { remote_function(double_int, input) };
}

extern "C" fn double_int(input: i32) -> i32 {
    return input * 2;
}

// Don't exactly know how else to call a named function
// in a dynamic ELF w/interpreter. We don't know the
// base address of the binary, so we can't adjust the
// symbol address.
fn set_callback(_cb: extern "C" fn(i32) -> i32) {
	let sysnum = 0x10001; // Set callback syscall
	unsafe {
		asm!(
			"out 0, eax",
			in("eax") sysnum,
			in("rdi") _cb
		);
	}
}

fn main() -> ExitCode
{
	println!("Hello, world!");
	let result = unsafe { remote_function(double_int, 21) };
	println!("Result from remote function: {}", result);
	set_callback(do_calculation);
	return ExitCode::from(result as u8);
}
