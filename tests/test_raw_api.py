#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_api
----------------------------------

Tests for `api` module.
"""

import base64
import binascii
import mock
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
        json = {'status': {'code': 0}}

        mock_response = mock.Mock()
        mock_response.json.return_value = json
        mock_response.status_code = 200
        mock_method = mock.Mock(return_value=mock_response)

        response = raw_api._make_request(mock_method, url, params)

        mock_method.assert_called_once_with(url, params=params)

        self.assertEqual(mock_response, response)

    def test_404_throws_exception(self):
        url = 'some_url'
        params = 'some_params'
        json = {'status': {'code': 0}}

        mock_response = mock.Mock()
        mock_response.json.return_value = json
        mock_response.status_code = 404
        mock_response.text = 'Some error message'
        mock_method = mock.Mock(return_value=mock_response)

        try:
            raw_api._make_request(mock_method, url, params)
        except raw_api.InvalidRequestException as e:
            mock_method.assert_called_once_with(url, params=params)

            self.assertIsNone(e.status)
            self.assertEqual(mock_response.text, e.args[0])
            return

        self.fail('Proper exception not thrown')

    def test_non_zero_code_throws_exception(self):
        url = 'some_url'
        params = 'some_params'
        json = {'status': {'code': 1, 'desc': 'some desc'}}

        mock_response = mock.Mock()
        mock_response.json.return_value = json
        mock_response.status_code = 200
        mock_response.text = 'Some error message'
        mock_method = mock.Mock(return_value=mock_response)

        try:
            raw_api._make_request(mock_method, url, params)
        except raw_api.InvalidRequestException as e:
            mock_method.assert_called_once_with(url, params=params)

            self.assertEqual(json['status'], e.status)
            self.assertEqual(json['status']['desc'], e.args[0])
            return

        self.fail('Proper exception not thrown')


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

        mock_response = mock.Mock()
        mock_response.json.return_value = json
        raw_api._make_request = mock.Mock(return_value=mock_response)

        salt, csrf_token, login_session = raw_api.get_salt(username)

        url = 'https://keybase.io/_/api/1.0/getsalt.json'
        params = {'email_or_username': username}
        raw_api._make_request.assert_called_once_with(requests.get,
                                                      url,
                                                      params=params)

        self.assertEqual(json['salt'], salt)
        self.assertEqual(json['csrf_token'], csrf_token)
        self.assertEqual(json['login_session'], login_session)


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
        except (binascii.Error, TypeError) as e:
            self.assertEqual('Non-hexadecimal digit found', e.args[0])
            return

        self.fail('Proper exception not thrown')

    def test_login_session_must_be_base64(self):
        password = 'password'
        salt = '37a94e'
        login_session = 'foo'

        try:
            raw_api._generate_hmac_pwh(password, salt, login_session)
        except (binascii.Error, TypeError) as e:
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

        salt_response = ('some_salt',
                         'some_token',
                         'some_session')
        raw_api.get_salt = mock.Mock(return_value=salt_response)

        raw_api._generate_hmac_pwh = mock.Mock(return_value='some_hmac')

        mock_response = mock.Mock()
        mock_response.json.return_value = json
        raw_api._make_request = mock.Mock(return_value=mock_response)

        session, me = raw_api.login(username, password)

        raw_api.get_salt.assert_called_once_with(username)

        raw_api._generate_hmac_pwh.assert_called_once_with(password,
                                                           salt_response[0],
                                                           salt_response[2])

        url = 'https://keybase.io/_/api/1.0/login.json'
        params = {'email_or_username': username,
                  'csrf_token': salt_response[1],
                  'hmac_pwh': 'some_hmac',
                  'login_session': salt_response[2]}
        raw_api._make_request.assert_called_once_with(requests.post,
                                                      url,
                                                      params=params)

        self.assertEqual(json['session'], session)
        self.assertEqual(json['me'], me)


if __name__ == '__main__':
    unittest.main()
