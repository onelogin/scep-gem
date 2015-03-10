require 'spec_helper'

describe SCEP::PKIOperation::Response do

  let(:ra_keypair)    { generate_keypair }
  let(:our_keypair)   { generate_keypair}
  let(:response_cert) { generate_keypair.cert }

  let(:payload) { SCEP::PKCS7CertOnly.new([response_cert]).to_der }
  let(:p7enc)   { OpenSSL::PKCS7.encrypt([our_keypair.certificate], payload, SCEP::PKIOperation::Base.create_default_cipher, OpenSSL::PKCS7::BINARY) }
  let(:p7sign)  { OpenSSL::PKCS7.sign(ra_keypair.certificate, ra_keypair.private_key, p7enc.to_der, [ra_keypair.certificate], OpenSSL::PKCS7::BINARY) }


  describe '#decrypt' do
    it 'assigns #signed_certificates correctly' do
      response = SCEP::PKIOperation::Response.new(our_keypair)
      response.verify_against ra_keypair.certificate
      response.decrypt(p7sign.to_der)
      expect(response.signed_certificates.first.to_pem).to eql(response_cert.to_pem)
    end
  end

  describe '#encrypt' do
    it 'successfully encrypts a PKCS7 payload' do
      first_response = SCEP::PKIOperation::Response.new(ra_keypair)
      first_response.signed_certificates = [response_cert]
      encrypted = first_response.encrypt(our_keypair.certificate)

      final_response = SCEP::PKIOperation::Response.new(our_keypair)
      final_response.verify_against ra_keypair.cert
      final_response.decrypt(encrypted)
      expect(final_response.signed_certificates.first.to_pem).to eql(response_cert.to_pem)
    end
  end

end
