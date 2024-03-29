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
                Basic functionality --> listens for ICMP echo request and responds with designated
                response.
            },
            'Author'      =>     'Chris John Riley',
            'License'     =>     MSF_LICENSE,
            'References'    =>
                [
                    # general
                    ['URL', 'http://blog.c22.cc']
                ]
        )

        register_options([
            OptString.new('TRIGGER',      [true, 'Trigger to listen for (data payload)']),
            OptString.new('RESPONSE',        [true, 'Data to respond when trigger matches']),
            OptString.new('BPF_FILTER',      [true, 'BFP format filter to listen for', 'icmp']),
            OptString.new('INTERFACE',     [false, 'The name of the interface']),
        ], self.class)

        register_advanced_options([
            OptString.new('CLOAK',    	[false, 'Create the response packet using a specific OS fingerprint (windows, linux, freebsd)', 'linux']),
            OptBool.new('PROMISC',         [true, 'Enable/Disable promiscuous mode', false]),
        ], self.class)

        deregister_options('SNAPLEN','FILTER','PCAPFILE','RHOST','UDP_SECRET','GATEWAY','NETMASK', 'TIMEOUT')
    end

    def run
        begin
            @interface = datastore['INTERFACE'] || Pcap.lookupdev
            @interface = get_interface_guid(@interface)
            @iface_ip = Pcap.lookupaddrs(@interface)[0]

            @filter = datastore['BPF_FILTER']
            @trigger = datastore['TRIGGER']
            @response = datastore['RESPONSE']
            @promisc = datastore['PROMISC']
            @cloak = datastore['CLOAK'].downcase

            if @promisc
                 print_status "Warning: Promiscuous mode enabled"
            end

            # start listner
            icmplistener

        rescue  =>  ex
            print_error(ex.message)
        ensure
            print_status "Stopping ICMP listener on %s (%s)" % [@interface, @iface_ip]
        end
    end

    def icmplistener
        # start listener

        print_good "ICMP Listener started on %s (%s). Monitoring for packets containing %s" % [@interface, @iface_ip, @trigger]
        cap = PacketFu::Capture.new(:iface => @interface, :start => true, :filter => @filter, :promisc => @promisc)
        loop {
            cap.stream.each do |pkt|
                packet = PacketFu::Packet.parse(pkt)
                data = packet.payload[4..-1]

                if packet.is_icmp? and data =~ /#{@trigger}/
                    print_status "#{Time.now}: SRC:%s ICMP (type %d code %d) DST:%s" % [packet.ip_saddr, packet.icmp_type, packet.icmp_code, packet.ip_daddr]

                    # detect and warn if system is responding to ICMP echo requests
                    # suggested fixes:
                    #
                    # (linux) echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
                    # (Windows) netsh firewall set icmpsetting 8 disable
                    # (Windows cont.) netsh firewall set opmode mode = ENABLE

                    if packet.icmp_type == 0 and packet.icmp_code == 0 and packet.ip_saddr == @iface_ip
                        print_error "Dectected ICMP echo response. The client may receive multiple repsonses"
                    end

                    @src_ip = packet.ip_daddr
                    @src_mac = packet.eth_daddr
                    @dst_ip = packet.ip_saddr
                    @dst_mac = packet.eth_saddr
                    @icmp_id = packet.payload[0,2]
                    @icmp_seq = packet.payload[2,2]
                    # create payload with matching id/seq
                    @resp_payload = @icmp_id + @icmp_seq + @response

                    # create response packet icmp_pkt
                    icmp_packet

                    if not @icmp_response
                        raise RuntimeError ,"Could not build a ICMP resonse"
                    else
                        # send response packet icmp_pkt
                        send_icmp
                    end
                end
            end
        }
    end

    def icmp_packet
        # create icmp response

        begin
            icmp_pkt = PacketFu::ICMPPacket.new(:flavor => @cloak)
            icmp_pkt.eth_saddr = @src_mac
            icmp_pkt.eth_daddr = @dst_mac
            icmp_pkt.icmp_type = 0
            icmp_pkt.icmp_code = 0
            icmp_pkt.payload = @resp_payload
            icmp_pkt.ip_saddr = @src_ip
            icmp_pkt.ip_daddr = @dst_ip
            icmp_pkt.recalc
            @icmp_response = icmp_pkt
        rescue  =>  ex
            print_error(ex.message)
        end
    end

    def send_icmp
        # send icmp response

        begin
            @icmp_response.to_w(iface = @interface)
            print_good "Response sent to %s containing %d bytes of data" % [@dst_ip, @response.length]
        rescue  =>  ex
            print_error(ex.message)
        end
    end

end