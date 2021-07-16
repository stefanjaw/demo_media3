# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

from odoo import fields, models


class AuthSamlProvider(models.Model):
    """Class defining the configuration values of an Saml2 provider"""

    _name = 'auth.saml.provider'
    _description = 'Saml2 provider'
    _order = 'sequence, name'

    name = fields.Char(string='Provider name', required=False)  # Name of the Saml2 entity, Google, etc
    client_id = fields.Char(string='Client ID')  # Our identifier
    auth_endpoint = fields.Char(string='Authentication URL', required=False)  # Saml provider URL to authenticate users
    scope = fields.Char()  # Saml user data desired to access
    validation_endpoint = fields.Char(string='Validation URL', required=False)  # Saml provider URL to validate tokens
    data_endpoint = fields.Char(string='Data URL')
    enabled = fields.Boolean(string='Allowed')
    css_class = fields.Char(string='CSS class', default='fa fa-fw fa-sign-in text-primary')
    body = fields.Char(help='Link text in Login Dialog', translate=True,required=False)
    sequence = fields.Integer(default=10)
    image = fields.Binary()