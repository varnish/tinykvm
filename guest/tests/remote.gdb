file glibc_test
target remote localhost:2159
layout next
layout next
#set debug remote 1
break test.c:32
cont
