use std::process::ExitCode;
use std::sync::{LazyLock, Mutex};
static ARRAY: LazyLock<Mutex<Vec<i32>>> = LazyLock::new(|| Mutex::new(vec![]));

#[no_mangle]
extern "C" fn remote_function(arg: fn(i32) -> i32, value: i32) -> i32 {
	// Locked reference to avoid data race issues
	ARRAY.lock().unwrap().push(value);
	//println!("In remote_function with vec: {:?}", *ARRAY.lock().unwrap());
	return arg(value);
}

fn main() -> ExitCode
{
	println!("Hello, Storage World!");
	return ExitCode::from(123);
}
