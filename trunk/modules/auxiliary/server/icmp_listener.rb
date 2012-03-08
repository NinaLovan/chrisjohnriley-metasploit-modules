##
# $Id:$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

    include Msf::Exploit::Remote::Capture
    include Msf::Auxiliary::Report

    def initialize
        super(
            'Name'        => 'ICMP Responder',
            'Version'     => '$Revision: $',
            'Description' => %q{
                Waits for ICMP packet containing set data payload and responds.
            },
            'Author'      =>     'Chris John Riley',
            'License'     =>     MSF_LICENSE,
            'References'    =>
                [
                    ['URL', 'http://blog.c22.cc']
                ],
            'DisclosureDate' => ''
        )

        register_options([
            OptString.new('TRIGGER',      [true, 'Trigger to listen for (data payload)']),
            OptString.new('RESPONSE',        [true, 'Data to respond when trigger matches']),
            OptString.new('BPF_FILTER',      [true, 'BFP format filter to listen for', 'icmp']),
            OptString.new('INTERFACE',     [false, 'The name of the interface']),
            OptBool.new('PROMISC',         [true, 'Enable/Disable promiscuous mode', false]),
        ], self.class)

        deregister_options('SNAPLEN', 'FILTER', 'PCAPFILE','RHOST','UDP_SECRET','GATEWAY','NETMASK', 'TIMEOUT')
    end

    def run
        begin
            @interface = datastore['INTERFACE'] || Pcap.lookupdev
            @interface = get_interface_guid(@interface)

            if datastore['BPF_FILTER']
                @filter = datastore['BPF_FILTER'] 
            else
                @filter = 'icmp' #set filter to icmp by default    
            end

            @trigger = datastore['TRIGGER']
            @response = datastore['RESPONSE']
            @promisc = datastore['PROMISC']

            icmplistener # start listener

        rescue  =>  ex
            print_error( ex.message)
        ensure
            print_status "Stopping ICMP listener on %s" % @interface
        end
    end

    def icmplistener
        print_good "ICMP Listener started on %s. Monitoring for packets containing %s" % [@interface, @trigger]
        cap = PacketFu::Capture.new(:iface => @interface, :start => true, :filter => @filter, :promisc => @promisc)
        loop {
            cap.stream.each do |pkt| 
                packet = PacketFu::Packet.parse(pkt)
                data = packet.payload[4..-1]
                if packet.is_icmp? and data =~ /#{@trigger}/
                    if datastore['VERBOSE']
                        print_status "#{Time.now}: %s ICMP (type %d code %d) %s" % [packet.ip_saddr, packet.icmp_type, packet.icmp_code, packet.ip_daddr]
                    end

                    # detect and warn if system is responding to ICMP echo requests
                    # suggested fix: (linux) echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
                    if packet.icmp_type == 0 and packet.icmp_code == 0
                        print_error('Dectected ICMP echo response. The client may receive multiple repsonses')
                    end
                
                    @src_ip = packet.ip_daddr
                    @dst_ip = packet.ip_saddr
                    @icmp_id = packet.payload[0,2]
                    @icmp_seq = packet.payload[2,2]
                    @resp_payload = @icmp_id + @icmp_seq + @response # create payload with matching id/seq
                
                    icmp_packet # create response packet icmp_pkt

                    if not @icmp_response
                        raise RuntimeError ,'Could not build a ICMP resonse'
                    else
                        send_icmp # send response packet icmp_pkt
                    end
                end
            end
        }
    end

    def icmp_packet
        icmp_pkt = PacketFu::ICMPPacket.new(:flavor => "Windows")
        icmp_pkt.icmp_type = 0
        icmp_pkt.icmp_code = 0
        icmp_pkt.payload = @resp_payload
        icmp_pkt.ip_saddr = @src_ip
        icmp_pkt.ip_daddr = @dst_ip
        icmp_pkt.recalc
        @icmp_response = icmp_pkt
    end

    def send_icmp
        @icmp_response.to_w(iface = @interface)
        print_good "Response sent to %s containing %d bytes of data" % [@dst_ip, @response.length]
    end

end