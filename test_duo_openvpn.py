import email.utils
import json
import tempfile
import unittest

import unittest.mock
from unittest.mock import MagicMock
import io

import duo_openvpn

def mock_client_factory(mock):
    """
    Return a Client-alike that uses a mock instead of an HTTP
    connection. Special case: Client.__init__() and set_proxy()
    arguments are verified by calling mock.duo_client_init() and
    mock.duo_client_set_proxy(), respectively.
    """
    class MockClient(duo_openvpn.Client):
        def __init__(self, *args, **kwargs):
            mock.duo_client_init(*args, **kwargs)
            super().__init__(*args, **kwargs)

        def set_proxy(self, *args, **kwargs):
            mock.duo_client_set_proxy(*args, **kwargs)
            return super().set_proxy(*args, **kwargs)

        def _connect(self):
            return mock

    return MockClient

class MockResponse(io.StringIO):
    def __init__(self, status, body, reason='some reason'):
        self.status = status
        self.reason = reason
        super().__init__(body)

class TestIntegration(unittest.TestCase):
    IKEY = 'expected ikey'
    SKEY = 'expected skey'
    HOST = 'expected hostname'
    USERNAME = 'expected username'
    PASSCODE = 'expected passcode'
    IPADDR = 'expected_ipaddr'
    PROXY_HOST = 'expected proxy host'
    PROXY_PORT = 'expected proxy port'
    EXPECTED_USER_AGENT = 'duo_openvpn/' + duo_openvpn.__version__
    EXPECTED_PREAUTH_PARAMS = (
        'ipaddr=expected_ipaddr'
        '&user=expected+username'
    )
    EXPECTED_AUTH_PATH = '/rest/v1/auth'
    EXPECTED_PREAUTH_PATH = '/rest/v1/preauth'
    EXPECTED_AUTH_PARAMS = (
        'auto=expected+passcode'
        '&ipaddr=expected_ipaddr'
        '&user=expected+username'
        '&factor=auto'
    )

    def setUp(self):
        self.expected_calls = MagicMock()

    def assert_auth(self, environ, expected_control, send_control=True):
        with tempfile.NamedTemporaryFile() as control:
            if send_control:
                environ['control'] = control.name

            with self.assertRaises(SystemExit) as cm:
                duo_openvpn.main(
                    environ=environ,
                    Client=mock_client_factory(self.expected_calls),
                )

            control.seek(0)
            output = control.read().decode('utf-8')
            self.assertEqual(expected_control, output)
            if expected_control == '1':
                self.assertEqual(0, cm.exception.args[0])
            else:
                self.assertEqual(1, cm.exception.args[0])

    def normal_environ(self):
        environ = {
            'ikey': self.IKEY,
            'skey': self.SKEY,
            'host': self.HOST,
            'username': self.USERNAME,
            'password': self.PASSCODE,
            'ipaddr': self.IPADDR,
        }
        self.expected_calls.duo_client_init(
            ikey=self.IKEY,
            skey=self.SKEY,
            host=self.HOST,
            user_agent=self.EXPECTED_USER_AGENT,
        )
        self.expected_calls.duo_client_set_proxy(
            host=None,
            proxy_type=None,
        )
        return environ

    def compare_params(self, recv_params, sent_params):
        stanzas = sent_params.split('&')
        return len(recv_params.split('&')) == len(stanzas) and all([s in recv_params for s in stanzas])

    def expect_request(self, method, path, params, params_func=None, response=None, raises=None):
        if params_func is None:
            params_func = lambda p: self.compare_params(p, self.EXPECTED_PREAUTH_PARAMS)

        self.expected_calls.request(
            method, path, params_func, {
                'User-Agent': self.EXPECTED_USER_AGENT,
                'Host': self.HOST,
                'Content-type': 'application/x-www-form-urlencoded',
                'Authorization': MagicMock(side_effect=lambda s: s.startswith('Basic ') and not s.startswith('Basic b\'')),
                'Date': MagicMock(side_effect=lambda s: bool(email.utils.parsedate_tz(s)))
            }
        )
        if raises:
            self.expected_calls.getresponse.side_effect = raises
        else:
            self.expected_calls.getresponse.return_value = response

    def expect_preauth(self, result, path=EXPECTED_PREAUTH_PATH, factor='push1'):
        self.expect_request(
            method='POST',
            path=path,
            params=self.EXPECTED_PREAUTH_PARAMS,
            response=MockResponse(
                status=200,
                body=json.dumps({
                    'stat': 'OK',
                    'response': {
                        'result': result,
                        'status': 'expected status',
                        'factors': {'default': factor},
                    },
                }),
            ),
        )

    def expect_auth(self, result, path=EXPECTED_AUTH_PATH):
        self.expect_request(
            method='POST',
            path=path,
            params=self.EXPECTED_AUTH_PARAMS,
            params_func = lambda p: self.compare_params(p, self.EXPECTED_AUTH_PARAMS),
            response=MockResponse(
                status=200,
                body=json.dumps({
                    'stat': 'OK',
                    'response': {
                        'result': result,
                        'status': 'expected status',
                    },
                }),
            ),
        )

    def test_preauth_allow(self):
        environ = self.normal_environ()
        self.expect_preauth('allow')
        self.assert_auth(
            environ=environ,
            expected_control='1',
        )

    def test_preauth_deny(self):
        environ = self.normal_environ()
        self.expect_preauth('deny')
        self.assert_auth(
            environ=environ,
            expected_control='0',
        )

    def test_preauth_enroll(self):
        environ = self.normal_environ()
        self.expect_preauth('enroll')
        self.assert_auth(
            environ=environ,
            expected_control='0',
        )

    def test_preauth_bogus(self):
        environ = self.normal_environ()
        self.expect_preauth('bogus')
        self.assert_auth(
            environ=environ,
            expected_control='0',
        )

    def test_preauth_missing_result(self):
        environ = self.normal_environ()
        self.expect_request(
            method='POST',
            path=self.EXPECTED_PREAUTH_PATH,
            params=self.EXPECTED_PREAUTH_PARAMS,
            response=MockResponse(
                status=200,
                body=json.dumps({
                        'stat': 'OK',
                        'response': {
                            'status': 'expected status',
                        },
                }),
            ),
        )
        self.assert_auth(
            environ=environ,
            expected_control='0',
        )

    def test_preauth_missing_status(self):
        environ = self.normal_environ()
        self.expect_request(
            method='POST',
            path=self.EXPECTED_PREAUTH_PATH,
            params=self.EXPECTED_PREAUTH_PARAMS,
            response=MockResponse(
                status=200,
                body=json.dumps({
                        'stat': 'OK',
                        'response': {
                            'result': 'deny',
                        },
                }),
            ),
        )
        self.assert_auth(
            environ=environ,
            expected_control='0',
        )

    def test_preauth_exception(self):
        environ = self.normal_environ()
        self.expect_request(
            method='POST',
            path=self.EXPECTED_PREAUTH_PATH,
            params=self.EXPECTED_PREAUTH_PARAMS,
            raises=Exception('whoops'),
        )
        self.assert_auth(
            environ=environ,
            expected_control='0',
        )

    def test_auth_allow(self):
        environ = self.normal_environ()
        self.expect_preauth('auth')
        self.expect_auth('allow')
        self.assert_auth(
            environ=environ,
            expected_control='1',
        )

    def test_auth_deny(self):
        environ = self.normal_environ()
        self.expect_preauth('auth')
        self.expect_auth('deny')
        self.assert_auth(
            environ=environ,
            expected_control='0',
        )

    def test_auth_bogus(self):
        environ = self.normal_environ()
        self.expect_preauth('auth')
        self.expect_auth('bogus')
        self.assert_auth(
            environ=environ,
            expected_control='0',
        )

    def test_auth_missing_reason(self):
        environ = self.normal_environ()
        self.expect_preauth('auth')
        self.expect_request(
            method='POST',
            path=self.EXPECTED_AUTH_PATH,
            params=self.EXPECTED_AUTH_PARAMS,
            params_func = lambda p: self.compare_params(p, self.EXPECTED_AUTH_PARAMS),
            response=MockResponse(
                status=200,
                body=json.dumps({
                        'stat': 'OK',
                        'response': {
                            'status': 'expected status',
                        },
                }),
            ),
        )
        self.assert_auth(
            environ=environ,
            expected_control='0',
        )

    def test_auth_missing_status(self):
        environ = self.normal_environ()
        self.expect_preauth('auth')
        self.expect_request(
            method='POST',
            path=self.EXPECTED_AUTH_PATH,
            params=self.EXPECTED_AUTH_PARAMS,
            params_func = lambda p: self.compare_params(p, self.EXPECTED_AUTH_PARAMS),
            response=MockResponse(
                status=200,
                body=json.dumps({
                        'stat': 'OK',
                        'response': {
                            'result': 'allow',
                        },
                }),
            ),
        )
        self.assert_auth(
            environ=environ,
            expected_control='0',
        )

    def test_auth_exception(self):
        environ = self.normal_environ()
        self.expect_preauth('auth')
        self.expect_request(
            method='POST',
            path=self.EXPECTED_AUTH_PATH,
            params=self.EXPECTED_AUTH_PARAMS,
            params_func = lambda p: self.compare_params(p, self.EXPECTED_AUTH_PARAMS),
            raises=Exception('whoops'),
        )
        self.assert_auth(
            environ=environ,
            expected_control='0',
        )

    def test_auth_no_ipaddr(self):
        preauth_noip_params='ipaddr=0.0.0.0' \
            '&user=expected+username'
        environ = self.normal_environ()
        environ.pop('ipaddr')
        self.expect_request(
            method='POST',
            path=self.EXPECTED_PREAUTH_PATH,
            params=preauth_noip_params,
            params_func = lambda p: self.compare_params(p, preauth_noip_params),
            response=MockResponse(
                status=200,
                body=json.dumps({
                        'stat': 'OK',
                        'response': {
                            'result': 'auth',
                            'status': 'expected status',
                            'factors': {'default': 'push1'},
                        },
                }),
            ),
        )
        auth_noip_params='auto=expected+passcode' \
            '&ipaddr=0.0.0.0' \
            '&user=expected+username' \
            '&factor=auto'
        self.expect_request(
            method='POST',
            path=self.EXPECTED_AUTH_PATH,
            params=auth_noip_params,
            params_func = lambda p: self.compare_params(p, auth_noip_params),
            response=MockResponse(
                status=200,
                body=json.dumps({
                        'stat': 'OK',
                        'response': {
                            'result': 'allow',
                            'status': 'expected status',
                        },
                }),
            ),
        )
        self.assert_auth(
            environ=environ,
            expected_control='1',
        )

    def test_missing_control(self):
        environ = {
            'ikey': self.IKEY,
            'skey': self.SKEY,
            'host': self.HOST,
            'password': self.PASSCODE,
            'username': self.USERNAME,
            'ipaddr': self.IPADDR,
        }
        self.assert_auth(
            environ=environ,
            send_control=False,
            expected_control='',
        )

    def test_missing_username(self):
        environ = {
            'ikey': self.IKEY,
            'skey': self.SKEY,
            'host': self.HOST,
            'password': self.PASSCODE,
            'ipaddr': self.IPADDR,
        }
        self.assert_auth(
            environ=environ,
            expected_control='',
        )

    def test_missing_password(self):
        environ = self.normal_environ()
        del environ['password']
        self.expect_preauth('auth', factor=None)
        self.assert_auth(
            environ=environ,
            expected_control='0',
        )

    def test_missing_ikey(self):
        environ = {
            'skey': self.SKEY,
            'host': self.HOST,
            'password': self.PASSCODE,
            'username': self.USERNAME,
            'ipaddr': self.IPADDR,
        }
        self.assert_auth(
            environ=environ,
            expected_control='0',
        )

    def test_missing_skey(self):
        environ = {
            'ikey': self.IKEY,
            'host': self.HOST,
            'password': self.PASSCODE,
            'username': self.USERNAME,
            'ipaddr': self.IPADDR,
        }
        self.assert_auth(
            environ=environ,
            expected_control='0',
        )

    def test_missing_host(self):
        environ = {
            'ikey': self.IKEY,
            'skey': self.SKEY,
            'password': self.PASSCODE,
            'username': self.USERNAME,
            'ipaddr': self.IPADDR,
        }
        self.assert_auth(
            environ=environ,
            expected_control='0',
        )

    def test_proxy_success(self):
        environ = self.normal_environ()
        environ['proxy_host'] = self.PROXY_HOST
        environ['proxy_port'] = self.PROXY_PORT
        self.expected_calls.duo_client_set_proxy(
            host=self.PROXY_HOST,
            port=self.PROXY_PORT,
        )
        self.expect_preauth(
            result='auth',
            path=('https://' + self.HOST + self.EXPECTED_PREAUTH_PATH),
        )
        self.expect_auth(
            result='allow',
            path=('https://' + self.HOST + self.EXPECTED_AUTH_PATH),
        )
        self.assert_auth(
            environ=environ,
            expected_control='1',
        )

    def test_proxy_missing_port(self):
        environ = self.normal_environ()
        environ['proxy_host'] = self.PROXY_HOST
        self.assert_auth(
            environ=environ,
            expected_control='0',
        )

    def test_proxy_missing_host(self):
        environ = self.normal_environ()
        # proxy_port is ignored if proxy_host isn't present.
        environ['proxy_port'] = self.PROXY_PORT
        self.expect_preauth('auth')
        self.expect_auth('allow')
        self.assert_auth(
            environ=environ,
            expected_control='1',
        )

class TestCertValidatingHTTPSConnection(unittest.TestCase):
    """Tests for CertValidatingHTTPSConnection.connect() SNI hostname logic."""

    def _make_connection(self, host, ca_certs='/path/to/ca.pem', tunnel_host=None):
        from https_wrapper import CertValidatingHTTPSConnection
        conn = CertValidatingHTTPSConnection(host, ca_certs=ca_certs)
        if tunnel_host:
            conn.set_tunnel(tunnel_host)
        return conn

    def test_connect_direct_uses_host_for_sni(self):
        """Without a proxy, wrap_socket should use self.host as server_hostname."""
        from https_wrapper import CertValidatingHTTPSConnection
        conn = self._make_connection('api-host.duosecurity.com')

        mock_sock = MagicMock()
        mock_context = MagicMock()
        mock_wrapped = MagicMock()
        mock_context.wrap_socket.return_value = mock_wrapped
        mock_wrapped.getpeercert.return_value = {
            'subjectAltName': [('DNS', '*.duosecurity.com')],
        }

        with unittest.mock.patch('socket.create_connection', return_value=mock_sock), \
             unittest.mock.patch('ssl.create_default_context', return_value=mock_context):
            conn.connect()

        mock_context.wrap_socket.assert_called_once_with(
            mock_sock, server_hostname='api-host.duosecurity.com',
        )

    def test_connect_proxy_uses_tunnel_host_for_sni(self):
        """With a proxy (set_tunnel), wrap_socket should use the tunnel host, not the proxy IP."""
        conn = self._make_connection('10.0.0.1', tunnel_host='api-host.duosecurity.com')

        mock_sock = MagicMock()
        mock_context = MagicMock()
        mock_wrapped = MagicMock()
        mock_context.wrap_socket.return_value = mock_wrapped
        mock_wrapped.getpeercert.return_value = {
            'subjectAltName': [('DNS', '*.duosecurity.com')],
        }

        with unittest.mock.patch('socket.create_connection', return_value=mock_sock), \
             unittest.mock.patch('ssl.create_default_context', return_value=mock_context):
            # Bypass the actual HTTP CONNECT tunnel
            with unittest.mock.patch.object(conn, '_tunnel'):
                conn.connect()

        mock_context.wrap_socket.assert_called_once_with(
            mock_sock, server_hostname='api-host.duosecurity.com',
        )


if __name__ == '__main__':
    unittest.main()
