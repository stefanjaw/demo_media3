# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

import functools
import logging

import json

import werkzeug.urls
import werkzeug.utils
from werkzeug.exceptions import BadRequest

from odoo import api, http, SUPERUSER_ID, _
from odoo.exceptions import AccessDenied
from odoo.http import request
from odoo import registry as registry_get

from odoo.addons.auth_signup.controllers.main import AuthSignupHome as Home
from odoo.addons.web.controllers.main import db_monodb, ensure_db, set_cookie_and_redirect, login_and_redirect


_logger = logging.getLogger(__name__)

#----------------------------------------------------------
# helpers
#----------------------------------------------------------
def fragment_to_query_string(func):
    @functools.wraps(func)
    def wrapper(self, *a, **kw):
        _logger.info("31====DEB SAML def wrapper\n")
        kw.pop('debug', False)
        if not kw:
            return """<html><head><script>
                var l = window.location;
                var q = l.hash.substring(1);
                var r = l.pathname + l.search;
                if(q.length !== 0) {
                    var s = l.search ? (l.search === '?' ? '' : '&') : '?';
                    r = l.pathname + l.search + s + q;
                }
                if (r == l.pathname) {
                    r = '/';
                }
                window.location = r;
            </script></head><body></body></html>"""
        return func(self, *a, **kw)
    return wrapper


#----------------------------------------------------------
# SAML Controller
#----------------------------------------------------------
class SamlLogin(Home):
    def list_saml_providers(self):
        _logger.info("31====DEB SAML def list_saml_providers\n")
        try:
            saml_providers = request.env['auth.saml.provider'].sudo().search_read([('enabled', '=', True)])
        except Exception:
            saml_providers = []
        _logger.info("36====DEB SAML def list_saml_providers\n%s,\n", saml_providers)
        for saml_provider in saml_providers:
            return_url = request.httprequest.url_root + 'auth_saml/signin'
            state = self.get_state(saml_provider)
            params = dict(
                response_type='token',
                client_id=saml_provider['client_id'],
                redirect_uri=return_url,
                scope=saml_provider['scope'],
                state=json.dumps(state),
            )
            saml_provider['auth_link'] = "%s?%s" % (saml_provider['auth_endpoint'], werkzeug.urls.url_encode(params))
        return saml_providers

    def get_state(self, saml_provider):
        _logger.info("75====DEB OAUTH def get_state\n")
        redirect = request.params.get('redirect') or 'web'
        if not redirect.startswith(('//', 'http://', 'https://')):
            redirect = '%s%s' % (request.httprequest.url_root, redirect[1:] if redirect[0] == '/' else redirect)
        state = dict(
            d=request.session.db,
            p=saml_provider['id'],
            r=werkzeug.urls.url_quote_plus(redirect),
        )
        token = request.params.get('token')
        if token:
            state['t'] = token
        return state
    
    @http.route()
    def web_login(self, *args, **kw):
        _logger.info("91=====DEB SAML controller web_login\n")
        ensure_db()
        if request.httprequest.method == 'GET' and request.session.uid and request.params.get('redirect'):
            # Redirect if already logged in and redirect param is present
            return http.redirect_with_hash(request.params.get('redirect'))
        saml_providers = self.list_saml_providers()

        response = super(SamlLogin, self).web_login(*args, **kw)
        if response.is_qweb:
            error = request.params.get('oauth_errorxxxxx')
            if error == '1':
                error = _("Sign up is not allowed on this database.")
            elif error == '2':
                error = _("Access Denied")
            elif error == '3':
                error = _("You do not have access to this database or your invitation has expired. Please ask for an invitation and be sure to follow the link in your invitation email.")
            else:
                error = None

            response.qcontext['saml_providers'] = saml_providers
            if error:
                response.qcontext['error'] = error

        return response
    
    
    
    def get_auth_signup_qcontext(self):
        _logger.info("51====DEB SAML def get_auth_signup_qcontext\n")
        result = super(SamlLogin, self).get_auth_signup_qcontext()
        result["saml_providers"] = self.list_saml_providers()
        _logger.info("54====DEB SAML def get_auth_signup_qcontext list_providers\n%s\n",self.list_providers() )
        _logger.info("55====DEB SAML def get_auth_signup_qcontext result \n%s\n", result )
        return result
    

    
class SamlController(http.Controller):

    @http.route('/auth_saml/signin', type='http', auth='none')
    @fragment_to_query_string
    def signin(self, **kw):
        _logger.info("128====DEB SAML def signin\n")
        state = json.loads(kw['state'])
        dbname = state['d']
        if not http.db_filter([dbname]):
            return BadRequest()
        provider = state['p']
        context = state.get('c', {})
        registry = registry_get(dbname)
        with registry.cursor() as cr:
            try:
                env = api.Environment(cr, SUPERUSER_ID, context)
                credentials = env['res.users'].sudo().auth_saml(saml_provider, kw)
                cr.commit()
                action = state.get('a')
                menu = state.get('m')
                redirect = werkzeug.urls.url_unquote_plus(state['r']) if state.get('r') else False
                url = '/web'
                if redirect:
                    url = redirect
                elif action:
                    url = '/web#action=%s' % action
                elif menu:
                    url = '/web#menu_id=%s' % menu
                resp = login_and_redirect(*credentials, redirect_url=url)
                # Since /web is hardcoded, verify user has right to land on it
                if werkzeug.urls.url_parse(resp.location).path == '/web' and not request.env.user.has_group('base.group_user'):
                    resp.location = '/'
                return resp
            except AttributeError:
                # saml_signup is not installed
                _logger.error("saml_signup not installed on database %s: oauth sign up cancelled." % (dbname,))
                url = "/web/login?saml_error=1"
            except AccessDenied:
                # saml credentials not valid, user could be on a temporary session
                _logger.info('Saml2: access denied, redirect to main page in case a valid session exists, without setting cookies')
                url = "/web/login?saml_error=3"
                redirect = werkzeug.utils.redirect(url, 303)
                redirect.autocorrect_location_header = False
                return redirect
            except Exception as e:
                # signup error
                _logger.exception("Saml2: %s" % str(e))
                url = "/web/login?saml_error=2"

        return set_cookie_and_redirect(url)
    
