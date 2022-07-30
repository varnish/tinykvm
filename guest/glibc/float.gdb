file float
layout prev
layout next
target remote localhost:2159

set debug remote 1

break takes_float
continue
