require 'spec_helper'

describe SCEP::PKCS7CertOnly do
  let(:certificate1) { generate_keypair.certificate }
  let(:certificate2) { generate_keypair.certificate }
  let(:certs)    { [certificate1, certificate2] }
  let(:p7certs)  { SCEP::PKCS7CertOnly.new(certs) }

  describe '#initialize' do
    it 'creates an object with certificates' do
      p7certs = SCEP::PKCS7CertOnly.new(certs)
      expect(p7certs.certificates).to eql(certs)
    end
  end

  # Sufficiently tests #to_asn1
  describe '#to_der' do
    it 'encodes correctly such that it can be read by OpenSSL' do
      expect {
        der = p7certs.to_der
        OpenSSL::PKCS7.new(der)
      }.to_not raise_error
    end

    it 'encodes certificates in the correct order' do
      der = p7certs.to_der
      decoded_certs = OpenSSL::PKCS7.new(der).certificates
      expect(decoded_certs[0].serial).to eql(certificate1.serial)
      expect(decoded_certs[1].serial).to eql(certificate2.serial)
    end
  end

  describe '#decode' do
    it 'takes a PKCS7 cert-only der and creates a new PKCS7CertOnly' do
      der = p7certs.to_der
      decoded_p7certs = SCEP::PKCS7CertOnly.decode(der)
      decoded_certs   = decoded_p7certs.certificates
      expect(decoded_certs[0].serial).to eql(certificate1.serial)
      expect(decoded_certs[1].serial).to eql(certificate2.serial)
    end
  end
end
