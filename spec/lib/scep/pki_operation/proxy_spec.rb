require 'spec_helper'

describe SCEP::PKIOperation::Proxy do

  let(:endpoint)         { SCEP::Endpoint.new('https://scep.com') }
  let(:our_ra_keypair)   { generate_keypair }
  let(:their_ca_keypair) { generate_keypair }
  let(:original_keypair) { generate_keypair }
  let(:proxy)            { SCEP::PKIOperation::Proxy.new(endpoint, our_ra_keypair) }
  let(:csr)              { OpenSSL::X509::Request.new read_fixture('self-signed.csr') }
  let(:original_request) { SCEP::PKIOperation::Request.new(original_keypair)}

  before do
    proxy.add_response_verification_certificate(their_ca_keypair.cert)
    proxy.add_request_verification_certificate(original_keypair.cert)
    original_request.csr = csr
  end

  describe '#forward_pki_request' do
    let(:signed_keypair) { generate_keypair(their_ca_keypair) }

    let(:stubbed_response) do
      response = SCEP::PKIOperation::Response.new(their_ca_keypair)
      response.signed_certificates = signed_keypair.cert
      response
    end

    let(:stubbed_response_der) { stubbed_response.encrypt(our_ra_keypair.cert) }

    before do
      allow(endpoint).to receive(:pki_operation).and_return(stubbed_response_der)

      allow(endpoint).to receive(:ca_certificate).and_return(their_ca_keypair.cert)
    end

    it 'returns a correctly formatted response' do
      der_original_request = original_request.encrypt(our_ra_keypair.cert)
      result = proxy.forward_pki_request(der_original_request)

      expect(result.csr.to_pem).to eql(csr.to_pem)
      expect(result.signed_certificates.first.to_pem).to eql(signed_keypair.cert.to_pem)
      expect(result.p7enc_response.to_der.length).to_not eql(0)
    end
  end
end
