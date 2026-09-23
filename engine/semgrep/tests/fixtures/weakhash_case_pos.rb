require "openssl"

def hashers
  a = OpenSSL::Digest.new("md5")
  b = OpenSSL::Digest.new("sha1")
  c = OpenSSL::Digest.new("MD5")
end
