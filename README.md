SCEP Gem
========

Libraries that allow you to be a SCEP server, be a SCEP proxy, etc.

**Work in progress**

## Example

Easily be a SCEP proxy (psuedo sinatra syntax):

```ruby
require 'scep'

ra_keypair = SCEP::Keypair.read('certs/ra.crt', 'certs/ra.key')
scep_server = SCEP::Server.new 'https://some-final-endpoint.com'

post '/scep?operation=PKIOperation' do
  proxy = SCEP::PKIOperation::Proxy.new(server, ra_keypair)
  result = proxy.forward_pki_request(request.raw_post)

  puts result.csr # The CSR they sent
  puts result.signed_certificates # Returned signed certs from the SCEP server

  headers['content-type'] = 'application/x-pki-message'
  render results.p7enc_response.to_der
end
```
