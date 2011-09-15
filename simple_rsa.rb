require "openssl"
require "zlib"
require "base64"

=begin
  Author: Gustavo Anatoly F. V. Solís
  This is a simple RSA algorithm implementation.  
=end

module SimpleRSA
	
	DEFAULT_KEY_SIZE = 1024
	PRIVATE_KEY_FILE = "private_key.key"
	PUBLIC_KEY_FILE = "public_key.key"
	
	class RSA
	
		# Default key size is 1024
		def generate_key_pair(size)
			private_key = generate_private_key(size)
			generate_public_key(private_key)
		end
		
		def encrypt(content, public_key_file_path)
			
			if not File.exist?(public_key_file_path) then
				return "Public key file not found"
			end
			
			file_content = File.read(public_key_file_path).to_s 
			pkey = OpenSSL::PKey::RSA.new(file_content)
			encoded_base64 = Base64.encode64(pkey.public_encrypt(content))
			
			return encoded_base64
		end
		
		def decrypt(content_encrypted, private_key_file_path)
			
			if not File.exist?(private_key_file_path) then
				return "Private key file not found"
			end
			
			file_content = File.read(private_key_file_path).to_s
			pkey = OpenSSL::PKey::RSA.new(file_content)
			decoded_base64 = Base64.decode64(content_encrypted)
			
			return pkey.private_decrypt(decoded_base64)
		end
		
		private
		def generate_private_key(size)
			
			private_key = nil
			
			if size != DEFAULT_KEY_SIZE then
				private_key = OpenSSL::PKey::RSA.new(size)
			else
				private_key = OpenSSL::PKey::RSA.new(DEFAULT_KEY_SIZE)
			end
			
			# Saving in the file
			File.open(PRIVATE_KEY_FILE, "w") do |f|
				f.write(private_key)
			end
			
			return private_key
		end
		
		# Remember, private_key is an object RSA
		# so now, we can access the public key. 
		def generate_public_key(private_key)
			
			public_key = private_key.public_key
			
			# Save
			File.open(PUBLIC_KEY_FILE, "w") do |f|
				f.write(public_key)
			end
			
			return public_key
		end

	end
end

rsa = SimpleRSA::RSA.new
rsa.generate_key_pair(SimpleRSA::DEFAULT_KEY_SIZE)

encrypted = rsa.encrypt("Secret message here", SimpleRSA::PUBLIC_KEY_FILE)
decrypted = rsa.decrypt(encrypted, SimpleRSA::PRIVATE_KEY_FILE)

puts encrypted
puts "\n\n======================================================\n\n"
puts decrypted