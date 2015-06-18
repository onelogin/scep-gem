require 'spec_helper'

describe SCEP::JSCEPCli do
  let(:cli) { SCEP::JSCEPCli.new }
  let(:private_key) { OpenSSL::PKey::RSA.new read_fixture('ejbca/sample-request.key') }
  let(:csr) { OpenSSL::X509::Request.new read_fixture('ejbca/sample-request.csr') }
  let(:challenge) { 'foo123' }
  let(:dn) { 'CN=user'}
  let(:url) { 'http://172.16.2.132:8080/ejbca/publicweb/apply/scep/scep/pkiclient.exe' }
  let(:ca_identifier) { 'ManagementCA' }

  let(:request) { SCEP::JSCEPCli::Request.new(csr, private_key, ca_identifier, dn, challenge, url) }

  describe 'certificate generation' do
    it 'generates a valid cert' do
      cli.forward(request)

    end
  end

end
