# -*- coding: utf-8 -*-
from odoo import http

import requests
import werkzeug
import base64
#from werkzeug.urls import url_encode
#from werkzeug.urls import url_join

import logging
_logger = logging.getLogger(__name__)

class AuthSaml(http.Controller):

    @http.route('/auth_saml/acs/', auth='public', methods=['GET', 'POST'],csrf=False )
    def index(self, **kw):
        _logger.info("16====DEB AUTHSAML INICIO\n")

        saml_endpoint = "https://avalantec-dev.onelogin.com/trust/saml2/http-post/sso/6d8b170b-b1e9-494f-8caf-92f878ec79d3"
        
        if http.request.httprequest.method == 'POST':
            _logger.info("19====DEB AUTHSAML POST %s", kw)
            
            saml_response = kw.get('SAMLResponse')
            
            response1 = base64.b64decode( saml_response ).decode('utf-8')
            _logger.info("26==RESPONSE\n%s\n", response1 )
            
            return response1

        if http.request.httprequest.method == 'GET':
            _logger.info("22====DEB AUTHSAML GET %s", kw)
            
            soap_header = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:mer="http://www.mercurypay.com"><soapenv:Header/><soapenv:Body><mer:CreditTransaction><mer:tran>'
            soap_footer = '</mer:tran><mer:pw>' + '</mer:pw></mer:CreditTransaction></soapenv:Body></soapenv:Envelope>'
            #xml_transaction = soap_header + misc.html_escape(xml_transaction) + soap_footer
            #xml_transaction = soap_header +  soap_footer
            
            xml_transaction = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"  ID="ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24" Version="2.0" ProviderName="SP test" IssueInstant="2021-07-14T15:31:45Z" Destination="https://avalantec-dev.onelogin.com/trust/saml2/http-post/sso/6d8b170b-b1e9-494f-8caf-92f878ec79d3" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="https://stefanjaw-demomedia2-stag-saml-2871507.dev.odoo.com/auth_saml/acs"><saml:Issuer>https://stefanjaw-demomedia2-stag-saml-2871507.dev.odoo.com/auth_saml/acs</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/><samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>'
            
            
            headers = {
                'Content-Type': 'text/xml',
            }
            
            #test_url = 'https://httpbin.org/anything'
            
            url = "https://avalantec-dev.onelogin.com/trust/saml2/http-post/sso/6d8b170b-b1e9-494f-8caf-92f878ec79d3"
            #url = test_url
            
            r = requests.post(url, data=xml_transaction, headers=headers, timeout=65)
            r.raise_for_status()
            response = werkzeug.utils.unescape(r.content.decode())
            
            _logger.info("48== R %s", r)
            _logger.info("49== RESPONSE %s", response)
            #_logger.info("46== RESPONSE %s", r.json())
            
            
            #return werkzeug.utils.redirect(saml_endpoint)
            #return werkzeug.utils.redirect(url)
            #return "<html><body>PRUEBA<p></p></body></html>"
            #return http.request.render("auth_saml.listing", {response})
            
            return response
            

        return "NO POST OR GET"
    
    
    
    
    
    
    
    
    
    
    
    
    ''' Example Code
    
    
    return werkzeug.utils.redirect('/payment/process')
    '''
    
    '''
    @http.route('/auth_saml/auth_saml/', auth='public')
    def index(self, **kw):
        console.log("8====DEB AUTHSAML %s", kw)
        return "Hello, world"

    @http.route('/auth_saml/auth_saml/objects/', auth='public')
    def list(self, **kw):
        console.log("13====DEB AUTHSAML %s", kw)
        return http.request.render('auth_saml.listing', {
            'root': '/auth_saml/auth_saml',
            'objects': http.request.env['auth_saml.auth_saml'].search([]),
        })

    @http.route('/auth_saml/auth_saml/objects/<model("auth_saml.auth_saml"):obj>/', auth='public')
    def object(self, obj, **kw):
        console.log("21====DEB AUTHSAML %s", kw)
        return http.request.render('auth_saml.object', {
            'object': obj
        })
    '''