proc remote_calc(v: int): int {.cdecl, exportc.}
import json

var jj = %* {
    "name": "Hello",
    "email": "World",
    "books": ["Foundation"]
}

proc remote_calc(v: int): int =
    #echo "Hello Nim Storage World!\n" & jj.pretty()
    echo "Hello Nim Storage World!"
    return v * 2
