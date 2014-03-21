#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_api
----------------------------------

Tests for `api` module.
"""

import base64
import binascii
import requests
import unittest

from keybaseclient import raw_api


class MockResponse(object):

    def __init__(self, url, params, status_code, text, json):
        self.request_url = url
        self.request_params = params
        self.status_code = status_code
        self.text = text
        self.json = lambda: json


class TestMakeRequest(unittest.TestCase):

    def test_successful_request_returns_response(self):
        url = 'some_url'
        params = 'some_params'
        status_code = 200
        text = None
        json = {'status': {'code': 0}}

        response = raw_api._make_request(lambda *args, **kwargs:
                                     MockResponse(args[0],
                                                  kwargs['params'],
                                                  status_code,
                                                  text,
                                                  json),
                                     url, params)

        self.assertEquals(url, response.request_url)
        self.assertEquals(params, response.request_params)
        self.assertEquals(status_code, response.status_code)
        self.assertEquals(json, response.json())

    def test_404_throws_exception(self):
        url = 'some_url'
        params = 'some_params'
        status_code = 404
        text = 'Some error message'
        json = {'status': {'code': 0}}

        try:
            raw_api._make_request(lambda *args, **kwargs:
                              MockResponse(args[0],
                                           kwargs['params'],
                                           status_code,
                                           text,
                                           json),
                              url, params)
        except raw_api.InvalidRequestException as e:
            self.assertIsNone(e.status)
            self.assertEquals(text, e.args[0])
            return

        self.fail('Proper exception not thrown')

    def test_non_zero_code_throws_exception(self):
        url = 'some_url'
        params = 'some_params'
        status_code = 200
        text = 'Some error message'
        json = {'status': {'code': 1, 'desc': 'some desc'}}

        try:
            raw_api._make_request(lambda *args, **kwargs:
                              MockResponse(args[0],
                                           kwargs['params'],
                                           status_code,
                                           text,
                                           json),
                              url, params)
        except raw_api.InvalidRequestException as e:
            self.assertEquals(json['status'], e.status)
            self.assertEquals(json['status']['desc'], e.args[0])
            return

        self.fail('Proper exception not thrown')


class MockMakeRequest(object):

    def __init__(self, method, url, params, json):
        MockMakeRequest.method = method
        MockMakeRequest.url = url
        MockMakeRequest.params = params
        self.json = lambda: json


class TestGetSalt(unittest.TestCase):

    def setUp(self):
        self.original_make_request = raw_api._make_request

    def tearDown(self):
        raw_api._make_request = self.original_make_request

    def test_get_salt_processed_properly(self):
        username = 'test_user'
        json = {'salt': 'some_salt',
                'csrf_token': 'some_token',
                'login_session': 'some_session'}

        raw_api._make_request = lambda *args, **kwargs: \
            MockMakeRequest(args[0],
                            args[1],
                            kwargs['params'],
                            json)

        salt, csrf_token, login_session = raw_api.get_salt(username)

        self.assertEquals(requests.get, MockMakeRequest.method)
        self.assertEquals('https://keybase.io/_/api/1.0/getsalt.json',
                          MockMakeRequest.url)
        self.assertEquals(username,
                          MockMakeRequest.params['email_or_username'])
        self.assertEquals(json['salt'], salt)
        self.assertEquals(json['csrf_token'], csrf_token)
        self.assertEquals(json['login_session'], login_session)


class TestGenerateHmacPwh(unittest.TestCase):

    def test_successful_hash(self):
        password = 'password'
        salt = '37a94e'
        login_session = base64.b64encode('login_session'.encode('utf-8'))

        hmac_pwh = raw_api._generate_hmac_pwh(password, salt, login_session)

        self.assertEqual('4d5a48e17d54a4c1464bda2aad1237ab4f94cd0a2c2100884'
                         '8906bd0971a67a49e3c520a71790717023d03c4db0372250d'
                         'b62f2f3ec0d5325d95b182a99aa439',
                         hmac_pwh)

    def test_salt_must_be_hex(self):
        salt = 'salt'

        try:
            raw_api._generate_hmac_pwh(None, salt, None)
        except binascii.Error as e:
            self.assertEqual('Non-hexadecimal digit found', e.args[0])
            return

        self.fail('Proper exception not thrown')

    def test_login_session_must_be_base64(self):
        password = 'password'
        salt = '37a94e'
        login_session = 'foo'

        try:
            raw_api._generate_hmac_pwh(password, salt, login_session)
        except binascii.Error as e:
            self.assertEqual('Incorrect padding', e.args[0])
            return

        self.fail('Proper exception not thrown')


class TestLogin(unittest.TestCase):

    def setUp(self):
        self.original_get_salt = raw_api.get_salt
        self.original_generate_hmac_pwh = raw_api._generate_hmac_pwh
        self.original_make_request = raw_api._make_request

    def tearDown(self):
        raw_api.get_salt = self.original_get_salt
        raw_api._generate_hmac_pwh = self.original_generate_hmac_pwh
        raw_api._make_request = self.original_make_request

    def test_login_processed_properly(self):
        username = 'test_user'
        password = 'some_password'
        json = {'session': 'some_session',
                'me': 'some_me'}

        # Return dynamic values based on username
        raw_api.get_salt = lambda username: ('salt_{0}'.format(username),
                                         'token_{0}'.format(username),
                                         'session_{0}'.format(username))

        # Merge all values into a single response value
        raw_api._generate_hmac_pwh = lambda *args: ''.join(args)

        # Use MockMakeRequest which saves off the parameters
        raw_api._make_request = lambda *args, **kwargs: \
            MockMakeRequest(args[0],
                            args[1],
                            kwargs['params'],
                            json)

        session, me = raw_api.login(username, password)

        self.assertEquals(requests.post, MockMakeRequest.method)
        self.assertEquals('https://keybase.io/_/api/1.0/login.json',
                          MockMakeRequest.url)
        self.assertEquals(username,
                          MockMakeRequest.params['email_or_username'])
        self.assertEquals('token_{0}'.format(username),
                          MockMakeRequest.params['csrf_token'])
        self.assertEquals('{0}salt_{1}session_{1}'.format(password, username),
                          MockMakeRequest.params['hmac_pwh'])
        self.assertEquals('session_{0}'.format(username),
                          MockMakeRequest.params['login_session'])
        self.assertEquals(json['session'], session)
        self.assertEquals(json['me'], me)


if __name__ == '__main__':
    unittest.main()
