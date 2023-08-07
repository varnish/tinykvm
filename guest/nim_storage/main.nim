proc quick_exit(code: int) {.importc.}
proc remote_calc(v: int): int {.importc.}
proc remote_string(): string {.importc.}
proc do_calculation() {.cdecl, exportc.}
import json

var j = %* {
    "name": "Hello",
    "email": "World",
    "books": ["Foundation"]
}

# Executed by fork of master VM
proc do_calculation() =
    echo "Hello Nim World!\n" & j.pretty()
    echo "Remote calculation of 21 is " & $remote_calc(21)

# Executed by master VM
echo "Remote calculation of 21 is " & $remote_calc(21)
echo "Remote string is " & remote_string()
quick_exit(remote_calc(21))
