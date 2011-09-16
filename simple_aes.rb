require "openssl"
require "digest/sha1"
require "base64"

=begin
  Author: Gustavo Anatoly F. V. Solís
  Demonstration how to use AES to 
  encrypt and decrypt.
=end

module SimpleAES 
  
  IV = "1234567890ABCDFEFGHIJ"
  ALGO = "aes-128-cbc"
  DEFAULT_KEY_SIZE = 16
    
  class AES
  
    def encrypt(content, key)
      aes = OpenSSL::Cipher::Cipher.new(ALGO)
      aes.encrypt
      aes.key = fix_key_size(key)
      aes.iv = IV
      data = aes.update(content)
      data << aes.final
      return Base64.encode64(data)
    end
    
    def decrypt(content, key)
      aes = OpenSSL::Cipher::Cipher.new(ALGO)
      aes.decrypt
      aes.key = fix_key_size(key)
      aes.padding = 0
      aes.iv = IV
      decode = Base64.decode64(content)
      data = aes.update(decode)
      data << aes.final
      return data
    end
    
    private
    def fix_key_size(key)
      complement = 0
      fixed_key = key
      if key.size < DEFAULT_KEY_SIZE then
        complement = DEFAULT_KEY_SIZE - key.size
        for i in (1..complement)
          fixed_key += "0"
        end
      end
      return fixed_key
    end 
  end
end

aes = SimpleAES::AES.new
encrypt = aes.encrypt("Test AES", "my password")
decrypt = aes.decrypt(encrypt, "my password")
puts encrypt
puts "\n\n============================\n\n"
puts decrypt