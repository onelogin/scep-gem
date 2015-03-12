require 'spec_helper'

describe 'SCEP and EJBCA' do
  before do
    WebMock.allow_net_connect!
  end

  let(:ejbca_scep_url) { 'http://172.16.2.132:8080/ejbca/publicweb/apply/scep/scep2/pkiclient.exe' }
  let(:endpoint)       { SCEP::Endpoint.new(ejbca_scep_url) }

  describe 'GetCACaps' do
    it 'supports the POSTPKIOperation' do
      expect(endpoint.capabilities).to include('POSTPKIOperation')
    end
  end

  describe 'GetCACert' do
    context 'CA certificate' do
      it 'successfully downloads the CA certificate' do
        expect(endpoint.ca_certificate).to be_a(OpenSSL::X509::Certificate)
      end
    end

    context 'RA certificate' do
      it 'successfully downloads the RA certificate' do
        expect(endpoint.ra_certificate).to be_a(OpenSSL::X509::Certificate)
      end
    end
  end

  describe 'PostPKIOperation' do
    let(:ra_cert)     { endpoint.ra_certificate }
    let(:our_keypair) { generate_keypair }
    let(:csr)         { OpenSSL::X509::Request.new read_fixture('self-signed.csr') }
    let(:request) do
      req = SCEP::PKIOperation::Request.new(our_keypair)
      req.csr = csr
      req
    end



    it 'signs a CSR' do
      encrypted = request.encrypt(ra_cert)

      asn1 = OpenSSL::ASN1.decode(encrypted.to_der)

      pkcs_cert_resp_signed = asn1.value[1].value[0]
      signer_info = pkcs_cert_resp_signed.value[4].value[0]
      authenticated_attributes = signer_info.value[3]

      #digest =

      # binding.pry

      endpoint.pki_operation(encrypted.to_der)
    end
  end


end
