use std::process::ExitCode;
use std::sync::{LazyLock, Mutex};
use std::arch::asm;
static ARRAY: LazyLock<Mutex<Vec<i32>>> = LazyLock::new(|| Mutex::new(vec![]));

#[no_mangle]
extern "C" fn remote_function(arg: fn(i32) -> i32, value: i32) -> i32 {
	// Locked reference to avoid data race issues
	ARRAY.lock().unwrap().push(value);
	//println!("In remote_function with vec: {:?}", *ARRAY.lock().unwrap());
	return arg(value);
}

fn set_fsbase(fsbase: u64) {
	unsafe {
		asm!(
			"wrfsbase {}",
			in(reg) fsbase,
		);
	}
}

#[no_mangle]
extern "C" fn remote_allocation(fsbase: u64, alloc: fn() -> Vec<i32>) -> Vec<i32> {
	// Set the FSBASE to the provided value
	set_fsbase(fsbase);
	// Call the allocator function
	return alloc();
	//return vec![42, 43, 44];
}

fn main() -> ExitCode
{
	println!("Hello, Storage World!");
	return ExitCode::from(123);
}
