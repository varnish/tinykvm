use std::arch::asm;
extern "C" { fn remote_function(arg: fn(i32) -> i32, value: i32) -> i32; }
use std::process::ExitCode;

fn double_int(input: i32) -> i32 {
    return input * 2;
}

extern "C" fn do_calculation(input: i32) -> i32 {
    return unsafe { remote_function(double_int, input) };
}
extern "C" fn do_nothing(_input: i32) -> i32 {
	return 42;
}

// Don't exactly know how else to call a named function
// in a dynamic ELF w/interpreter. We don't know the
// base address of the binary, so we can't adjust the
// symbol address.
fn set_callback(name: &str, cb: extern "C" fn(i32) -> i32) {
	let sysnum = 0x10001; // Set callback syscall
	unsafe {
		asm!(
			"out 0, eax",
			in("eax") sysnum,
			in("rdi") cb,
			in("rsi") name.as_ptr(),
			in("rdx") name.len()
		);
	}
}

fn main() -> ExitCode
{
	println!("Hello, world!");
	let result = unsafe { remote_function(double_int, 21) };
	println!("Result from remote function: {}", result);
	set_callback("do_calculation", do_calculation);
	set_callback("do_nothing", do_nothing);
	return ExitCode::from(result as u8);
}
