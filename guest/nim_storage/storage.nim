proc quick_exit(code: int) {.importc.}
proc remote_calc(v: int): int {.cdecl, exportc.}
proc remote_string(): string {.cdecl, exportc.}
import json

var jj = %* {
    "name": "Hello",
    "email": "World",
    "books": ["Foundation"]
}

proc remote_calc(v: int): int =
    echo "Nim calculation!"
    return v * 2

proc remote_string(): string =
    return jj.pretty()

echo "Hello Nim Storage World!\njj: " & jj.pretty()
quick_exit(0)
