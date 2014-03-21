import base64
import binascii
import hashlib
import hmac
import requests
import scrypt


class InvalidRequestException(Exception):
    """Exception containing information about failed request."""

    def __init__(self, message, status=None):
        """Instantiate exception with message and (optional) status object.

        Arguments:
        message -- error message
        status -- keybase.io status object (default None)
        """

        super(InvalidRequestException, self).__init__(message)

        self.status = status


def _make_request(method, url, params):
    """Send and process an API call to keybase.io.

    Arguments:
    method -- requests method to use for the call
    url -- full URL to call
    params -- request parameters to send with the call

    Returns:
    If successful, full response object
    If failed, InvalidRequestException with an error message and potentially
        the keybase.io status object
    """
    response = method(url, params=params)

    if response.status_code != 200:
        raise InvalidRequestException(response.text)

    response_json = response.json()

    if response_json['status']['code'] != 0:
        raise InvalidRequestException(response_json['status']['desc'],
                                      response_json['status'])

    return response


def get_salt(username):
    """Retrieve salt, token, and session for user with provided username.

    Arguments:
    username -- username for the desired user

    Returns:
    If successful, tuple with salt, csrf token and login session
    If failed, InvalidRequestException
    """
    salt_obj = _make_request(requests.get,
                             'https://keybase.io/_/api/1.0/getsalt.json',
                             params={'email_or_username': username}).json()

    salt = salt_obj['salt']
    csrf_token = salt_obj['csrf_token']
    login_session = salt_obj['login_session']

    return salt, csrf_token, login_session


def _generate_hmac_pwh(password, salt, login_session):
    """Generate password hash consisting of the password, salt, and session.

    Arguments:
    password -- password to use as hash key
    salt -- hex encoded salt to use as hash key
    login_session -- base64 encoded session to hash

    Returns:
    Hashed login session
    """

    pwh = scrypt.hash(password, binascii.unhexlify(salt),
                      1 << 15, 8, 1, 224)[192:224]
    hmac_pwh = hmac.new(pwh, base64.b64decode(login_session),
                        hashlib.sha512).hexdigest()
    return hmac_pwh


def login(username, password):
    """Login user with the given username and password.

    Arguments:
    username -- username for the user to login
    password -- password for the user to login

    Returns:
    If successful, tuple containing session and user object
    If failed, InvalidRequestException
    """

    salt, csrf_token, login_session = get_salt(username)

    hmac_pwh = _generate_hmac_pwh(password, salt, login_session)

    login_obj = _make_request(requests.post,
                              'https://keybase.io/_/api/1.0/login.json',
                              params={'email_or_username': username,
                                      'csrf_token': csrf_token,
                                      'hmac_pwh': hmac_pwh,
                                      'login_session': login_session}).json()

    return login_obj['session'], login_obj['me']


name = 'adamdoyle'
password = 'cX5FdGrysVnDaHL'

#print(login(name, password))
