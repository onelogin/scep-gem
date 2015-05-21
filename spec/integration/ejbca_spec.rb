require 'spec_helper'

describe 'SCEP and EJBCA' do
  before do
    WebMock.allow_net_connect!
  end

  let(:ejbca_scep_url) { 'http://172.16.2.132:8080/ejbca/publicweb/apply/scep/scep/pkiclient.exe' }
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
        puts endpoint.ca_certificate.subject
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
      req.challenge_password = '123456'
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

  describe 'unpacking sample request' do
    let(:ca_keypair) { SCEP::Keypair.read fixture_path('ejbca/ca.crt'), fixture_path('ejbca/ca.key') }
    let(:request)    { SCEP::PKIOperation::Request.new(ca_keypair) }
    let(:enc_req)    { read_fixture('ejbca/sample-scep-request.pkcs7') }

    before { request.decrypt(enc_req, false) }

    it 'foos' do

      puts :foo
    end


  end


end
