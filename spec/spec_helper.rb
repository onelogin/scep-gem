require 'rubygems'
require 'bundler'

Bundler.require :default

require 'pry'
require 'webmock/rspec'
require 'scep'

if RUBY_VERSION > '1.8.7'
  require 'codeclimate-test-reporter'
  WebMock.disable_net_connect!(:allow => 'codeclimate.com')
  CodeClimate::TestReporter.start
end

def read_fixture(path)
  File.open(fixture_path path).read
end

def fixture_path(path)
  "spec/fixtures/#{path}"
end


def next_serial
  @serial ||= 0
  @serial += 1
  @serial
end

# Helper to generate a self-signed certificate
# @param [SCEP::Keypair] signer
# @return [SCEP::Keypair]
# @see http://stackoverflow.com/questions/2381394/ruby-generate-self-signed-certificate
def generate_keypair(signer = nil, serial = nil)
  serial ||= next_serial

  private_key = OpenSSL::PKey::RSA.new(1024)
  subject = '/C=BE/O=Test/OU=Test/CN=Test'

  signer_private_key = signer ? signer.private_key : private_key
  signer_name        = signer ? signer.certificate.subject : OpenSSL::X509::Name.parse(subject)

  cert = OpenSSL::X509::Certificate.new
  cert.subject    = OpenSSL::X509::Name.parse(subject)
  cert.issuer     = signer_name
  cert.not_before = Time.now
  cert.not_after  = Time.now + 365 * 24 * 360
  cert.public_key = private_key.public_key
  cert.serial     = serial
  cert.version    = 3

  ef = OpenSSL::X509::ExtensionFactory.new
  ef.subject_certificate = cert
  ef.issuer_certificate  = cert
  cert.extensions = [
    ef.create_extension('basicConstraints', 'CA:TRUE', true),
    ef.create_extension('subjectKeyIdentifier', 'hash')
  ]
  cert.add_extension ef.create_extension(
    'authorityKeyIdentifier',
    'keyid:alyways,issuer:always')


  cert.sign signer_private_key, OpenSSL::Digest::SHA1.new


  return SCEP::Keypair.new(cert, private_key)
end
