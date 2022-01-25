# -*- coding: utf-8 -*-
#
# Copyright (C) 2016, 2017 Red Hat, Inc.
# Red Hat Author: Patrick Uiterwijk <puiterwijk@redhat.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

""" Test the OpenIDCClient. """


from base64 import urlsafe_b64encode
from hashlib import sha256
import shutil
import tempfile
import urllib.parse
import unittest

try:
    from mock import MagicMock, patch
except ImportError:
    from unittest.mock import MagicMock, patch

import openidc_client as openidcclient

BASE_URL = "http://app/"
IDP_URL = "https://idp/"


def set_token(client, toreturn):
    """Mock helper for _get_server to set a retrieved token."""

    def setter(app):
        client._retrieved_code = toreturn
        return MagicMock()

    return setter


def mock_request(responses):
    """Mock helper for responding to HTTP requests."""

    def perform(method, url, **extra):
        def rfs(toret):
            """Helper for Raise For Status."""

            def call():
                if toret.status_code != 200:
                    raise Exception("Mocked response %s" % toret.status_code)

            return call

        toreturn = MagicMock()
        if url in responses:
            if len(responses[url]) == 0:
                raise Exception("Unhandled requested to %s (extra %s)" % (url, extra))
            retval = responses[url][0]
            responses[url] = responses[url][1:]
            toreturn.status_code = 200
            if "_code" in retval:
                toreturn.status_code = retval["_code"]
                del retval["_code"]
            toreturn.json = MagicMock(return_value=retval)
            toreturn.raise_for_status = rfs(toreturn)
            return toreturn
        else:
            raise Exception("Unhandled mocked URL: %s (extra: %s)" % (url, extra))

    return perform


class OpenIdBaseClientTest(unittest.TestCase):

    """Test the OpenId Base Client."""

    def setUp(self):
        self.cachedir = tempfile.mkdtemp("oidcclient")
        openidcclient.webbrowser = MagicMock()
        self.client = openidcclient.OpenIDCClient(
            "myapp",
            id_provider=IDP_URL,
            id_provider_mapping={"Token": "Token", "Authorization": "Authorization"},
            client_id="testclient",
            client_secret="notsecret",
            cachedir=self.cachedir,
        )

    def tearDown(self):
        shutil.rmtree(self.cachedir)

    def test_cachefile(self):
        """Test that the cachefile name is set by app id."""
        with self.client._cache_lock:
            self.assertEqual(
                "oidc_myapp.json", self.client._cachefile.rsplit("/", 1)[1]
            )

    def test_get_new_token_cancel(self):
        """Test that we handle it correctly if the user cancels."""
        with patch.object(
            self.client, "_get_server", side_effect=set_token(self.client, False)
        ) as gsmock:
            with patch.object(
                openidcclient.httpx, "request", side_effect=mock_request({})
            ) as postmock:
                result = self.client._get_new_token(["test_get_new_token_cancel"])
                self.assertEqual(result, None)
                assert gsmock.call_count == 1
                postmock.assert_not_called()

    def test_get_new_token_error(self):
        """Test that we handle errors correctly."""
        postresp = {
            "https://idp/Token": [
                {"error": "some_error", "error_description": "Some error occured"}
            ]
        }

        with patch.object(
            self.client, "_get_server", side_effect=set_token(self.client, "authz")
        ) as gsm:
            with patch.object(
                openidcclient.httpx, "request", side_effect=mock_request(postresp)
            ) as postmock:
                result = self.client._get_new_token(["test_get_new_token_error"])
                self.assertEqual(result, None)
                assert gsm.call_count == 1
                postmock.assert_called_once_with(
                    "POST",
                    "https://idp/Token",
                    data={
                        "code": "authz",
                        "client_secret": "notsecret",
                        "grant_type": "authorization_code",
                        "client_id": "testclient",
                        "redirect_uri": "http://localhost:1/",
                    },
                )

    def test_get_new_token_working(self):
        """Test for a completely succesful case."""
        postresp = {
            "https://idp/Token": [
                {
                    "access_token": "testtoken",
                    "refresh_token": "refreshtoken",
                    "expires_in": 600,
                    "token_type": "Bearer",
                }
            ]
        }

        with patch.object(
            self.client, "_get_server", side_effect=set_token(self.client, "authz")
        ) as gsm:
            with patch.object(
                openidcclient.httpx, "request", side_effect=mock_request(postresp)
            ) as postmock:
                result = self.client._get_new_token(["test_get_new_token_working"])
                self.assertNotEqual(result, None)
                assert gsm.call_count == 1
                postmock.assert_called_once_with(
                    "POST",
                    "https://idp/Token",
                    data={
                        "code": "authz",
                        "client_secret": "notsecret",
                        "grant_type": "authorization_code",
                        "client_id": "testclient",
                        "redirect_uri": "http://localhost:1/",
                    },
                )

    def test_get_new_token_pkce_working(self):
        """Test for a completely succesful case with PKCE."""
        postresp = {
            "https://idp/Token": [
                {
                    "access_token": "testtoken",
                    "refresh_token": "refreshtoken",
                    "expires_in": 600,
                    "token_type": "Bearer",
                }
            ]
        }

        with patch.object(
            self.client, "_get_server", side_effect=set_token(self.client, "authz")
        ) as gsm:
            with patch.object(
                openidcclient.httpx, "request", side_effect=mock_request(postresp)
            ) as postmock:
                with patch.object(openidcclient.webbrowser, "open") as wb:
                    self.client._use_pkce = True
                    result = self.client._get_new_token(
                        ["test_get_new_token_pkce_working"]
                    )
                    self.client._use_pkce = False
                    self.assertNotEqual(result, None)
                    assert gsm.call_count == 1

                    # Check that the PKCE code was sent to the browser
                    (wbargs, _) = wb.call_args
                    auth_url = urllib.parse.urlparse(wbargs[0])
                    auth_params = urllib.parse.parse_qs(auth_url.query)
                    assert auth_params["code_challenge_method"] == ["S256"]
                    assert "code_challenge" in auth_params
                    code_challenge = auth_params["code_challenge"][0]

                    (args, kwargs) = postmock.call_args
                    assert args[0] == "POST"
                    assert args[1] == "https://idp/Token"
                    assert kwargs["data"]["code"] == "authz"
                    assert kwargs["data"]["client_id"] == "testclient"
                    assert kwargs["data"]["client_secret"] == "notsecret"
                    assert kwargs["data"]["grant_type"] == "authorization_code"
                    assert kwargs["data"]["redirect_uri"] == "http://localhost:1/"
                    code_verifier = kwargs["data"]["code_verifier"]
                    assert len(code_verifier) >= 43
                    assert len(code_verifier) <= 128

                    correct_challenge = urlsafe_b64encode(
                        sha256(code_verifier.encode()).digest()
                    )
                    correct_challenge = correct_challenge.decode().rstrip("=")

                    assert correct_challenge == code_challenge

    def test_get_token_no_new(self):
        """Test that if we don't have a token we can skip getting a new oen."""
        self.assertEqual(
            self.client.get_token(["test_get_token_no_new"], new_token=False), None
        )

    def test_get_token_from_cache(self):
        """Test that if we have a cached token, that gets returned."""
        postresp = {
            "https://idp/Token": [
                {
                    "access_token": "testtoken",
                    "refresh_token": "refreshtoken",
                    "expires_in": 600,
                    "token_type": "Bearer",
                }
            ]
        }

        with patch.object(
            self.client, "_get_server", side_effect=set_token(self.client, "authz")
        ) as gsm:
            with patch.object(
                openidcclient.httpx, "request", side_effect=mock_request(postresp)
            ) as postmock:
                result = self.client._get_new_token(["test_get_token_from_cache"])
                self.assertNotEqual(result, None)
                assert gsm.call_count == 1
                postmock.assert_called_once_with(
                    "POST",
                    "https://idp/Token",
                    data={
                        "code": "authz",
                        "client_secret": "notsecret",
                        "grant_type": "authorization_code",
                        "client_id": "testclient",
                        "redirect_uri": "http://localhost:1/",
                    },
                )

        self.assertNotEqual(
            self.client.get_token(["test_get_token_from_cache"], new_token=False), None
        )

    def test_get_token_new(self):
        """Test that get_token can get a new token."""
        postresp = {
            "https://idp/Token": [
                {
                    "access_token": "testtoken",
                    "refresh_token": "refreshtoken",
                    "expires_in": 600,
                    "token_type": "Bearer",
                }
            ]
        }

        with patch.object(
            self.client, "_get_server", side_effect=set_token(self.client, "authz")
        ) as gsm:
            with patch.object(
                openidcclient.httpx, "request", side_effect=mock_request(postresp)
            ) as postmock:
                self.assertNotEqual(
                    self.client.get_token(["test_get_token_new"], new_token=True), None
                )
                assert gsm.call_count == 1
                postmock.assert_called_once_with(
                    "POST",
                    "https://idp/Token",
                    data={
                        "code": "authz",
                        "client_secret": "notsecret",
                        "grant_type": "authorization_code",
                        "client_id": "testclient",
                        "redirect_uri": "http://localhost:1/",
                    },
                )

    def test_report_token_issue_refreshable(self):
        """Test that we refresh a token if problems are reported."""
        postresp = {
            "https://idp/Token": [
                {
                    "access_token": "testtoken",
                    "refresh_token": "refreshtoken",
                    "expires_in": 600,
                    "token_type": "Bearer",
                },
                {
                    "access_token": "refreshedtoken",
                    "refresh_token": "refreshtoken2",
                    "expires_in": 600,
                    "token_type": "Bearer",
                },
            ]
        }

        with patch.object(
            self.client, "_get_server", side_effect=set_token(self.client, "authz")
        ) as gsm:
            with patch.object(
                openidcclient.httpx, "request", side_effect=mock_request(postresp)
            ) as postmock:
                self.assertNotEqual(
                    self.client.get_token(
                        ["test_report_token_issue_refreshable"], new_token=True
                    ),
                    None,
                )
                assert gsm.call_count == 1
                postmock.assert_called_with(
                    "POST",
                    "https://idp/Token",
                    data={
                        "code": "authz",
                        "client_secret": "notsecret",
                        "grant_type": "authorization_code",
                        "client_id": "testclient",
                        "redirect_uri": "http://localhost:1/",
                    },
                )
                postmock.reset_mock()
                self.assertNotEqual(self.client.report_token_issue(), None)
                postmock.assert_called_once_with(
                    "POST",
                    "https://idp/Token",
                    data={
                        "client_id": "testclient",
                        "client_secret": "notsecret",
                        "grant_type": "refresh_token",
                        "refresh_token": "refreshtoken",
                    },
                )

    def test_report_token_issue_revoked(self):
        """Test that we only try to refresh once."""
        postresp = {
            "https://idp/Token": [
                {
                    "access_token": "testtoken",
                    "refresh_token": "refreshtoken",
                    "expires_in": 600,
                    "token_type": "Bearer",
                },
                {
                    "error": "invalid_token",
                    "error_description": "This token is not valid",
                },
            ]
        }

        with patch.object(
            self.client, "_get_server", side_effect=set_token(self.client, "authz")
        ) as gsm:
            with patch.object(
                openidcclient.httpx, "request", side_effect=mock_request(postresp)
            ) as postmock:
                self.assertNotEqual(
                    self.client.get_token(
                        ["test_report_token_issue_revoked"], new_token=True
                    ),
                    None,
                )
                assert gsm.call_count == 1
                postmock.assert_called_with(
                    "POST",
                    "https://idp/Token",
                    data={
                        "code": "authz",
                        "client_secret": "notsecret",
                        "grant_type": "authorization_code",
                        "client_id": "testclient",
                        "redirect_uri": "http://localhost:1/",
                    },
                )
                postmock.reset_mock()
                self.assertEqual(self.client.report_token_issue(), None)
                postmock.assert_called_once_with(
                    "POST",
                    "https://idp/Token",
                    data={
                        "client_id": "testclient",
                        "client_secret": "notsecret",
                        "grant_type": "refresh_token",
                        "refresh_token": "refreshtoken",
                    },
                )

    def test_report_token_issue_no_refresh(self):
        """Test that we don't try to refresh if there's no refresh token."""
        postresp = {
            "https://idp/Token": [
                {
                    "access_token": "testtoken",
                    "expires_in": 600,
                    "token_type": "Bearer",
                },
                {
                    "error": "invalid_token",
                    "error_description": "This token is not valid",
                },
            ]
        }

        with patch.object(
            self.client, "_get_server", side_effect=set_token(self.client, "authz")
        ) as gsm:
            with patch.object(
                openidcclient.httpx, "request", side_effect=mock_request(postresp)
            ) as postmock:
                self.assertNotEqual(
                    self.client.get_token(
                        ["test_report_token_issue_rno_refresh"], new_token=True
                    ),
                    None,
                )
                assert gsm.call_count == 1
                postmock.assert_called_with(
                    "POST",
                    "https://idp/Token",
                    data={
                        "code": "authz",
                        "client_secret": "notsecret",
                        "grant_type": "authorization_code",
                        "client_id": "testclient",
                        "redirect_uri": "http://localhost:1/",
                    },
                )
                postmock.reset_mock()
                self.assertEqual(self.client.report_token_issue(), None)
                postmock.assert_not_called()

    def test_send_request_valid_token(self):
        """Test that we send the token."""
        postresp = {
            "https://idp/Token": [
                {
                    "access_token": "testtoken",
                    "refresh_token": "refreshtoken",
                    "expires_in": 600,
                    "token_type": "Bearer",
                }
            ],
            "http://app/test": [{}],
        }

        with patch.object(
            self.client, "_get_server", side_effect=set_token(self.client, "authz")
        ) as gsm:
            with patch.object(
                openidcclient.httpx, "request", side_effect=mock_request(postresp)
            ) as postmock:
                result = self.client.send_request(
                    "http://app/test", scopes=["test_send_request_valid_token"]
                )
                assert gsm.call_count == 1
                self.assertEqual(result.json(), {})
                postmock.assert_called_with(
                    "POST",
                    "http://app/test",
                    headers={"Authorization": "Bearer testtoken"},
                )

    def test_send_request_valid_token_PATH(self):
        """Test that we send the token with a PATCH request."""
        postresp = {
            "https://idp/Token": [
                {
                    "access_token": "testtoken",
                    "refresh_token": "refreshtoken",
                    "expires_in": 600,
                    "token_type": "Bearer",
                }
            ],
            "http://app/test": [{}],
        }

        with patch.object(
            self.client, "_get_server", side_effect=set_token(self.client, "authz")
        ) as gsm:
            with patch.object(
                openidcclient.httpx, "request", side_effect=mock_request(postresp)
            ) as postmock:
                result = self.client.send_request(
                    "http://app/test",
                    scopes=["test_send_request_valid_token"],
                    http_method="PATCH",
                )
                assert gsm.call_count == 1
                self.assertEqual(result.json(), {})
                postmock.assert_called_with(
                    "PATCH",
                    "http://app/test",
                    headers={"Authorization": "Bearer testtoken"},
                )

    def test_send_request_not_valid_token_500(self):
        """Test that we don't refresh if we get a server error."""
        postresp = {
            "https://idp/Token": [
                {
                    "access_token": "testtoken",
                    "refresh_token": "refreshtoken",
                    "expires_in": 600,
                    "token_type": "Bearer",
                }
            ],
            "http://app/test": [
                {"_code": 500},
            ],
        }

        with patch.object(
            self.client, "_get_server", side_effect=set_token(self.client, "authz")
        ) as gsm:
            with patch.object(
                openidcclient.httpx, "request", side_effect=mock_request(postresp)
            ) as postmock:
                result = self.client.send_request(
                    "http://app/test", scopes=["test_send_request_not_valid_token_500"]
                )
                assert gsm.call_count == 1
                self.assertEqual(result.status_code, 500)
                self.assertEqual(result.json(), {})
                postmock.assert_called_with(
                    "POST",
                    "http://app/test",
                    headers={"Authorization": "Bearer testtoken"},
                )

    def test_send_request_not_valid_token_403(self):
        """Test that we don't refresh if the app returns a 403 (forbidden)"""
        postresp = {
            "https://idp/Token": [
                {
                    "access_token": "testtoken",
                    "refresh_token": "refreshtoken",
                    "expires_in": 600,
                    "token_type": "Bearer",
                }
            ],
            "http://app/test": [
                {"_code": 403},
            ],
        }

        with patch.object(
            self.client, "_get_server", side_effect=set_token(self.client, "authz")
        ) as gsm:
            with patch.object(
                openidcclient.httpx, "request", side_effect=mock_request(postresp)
            ) as postmock:
                result = self.client.send_request(
                    "http://app/test", scopes=["test_send_request_not_valid_token_403"]
                )
                assert gsm.call_count == 1
                self.assertEqual(result.status_code, 403)
                self.assertEqual(result.json(), {})
                postmock.assert_called_with(
                    "POST",
                    "http://app/test",
                    headers={"Authorization": "Bearer testtoken"},
                )

    def test_send_request_not_valid_token_401_refreshable(self):
        """Test that we do refresh with a 401."""
        postresp = {
            "https://idp/Token": [
                {
                    "access_token": "testtoken",
                    "refresh_token": "refreshtoken",
                    "expires_in": 600,
                    "token_type": "Bearer",
                },
                {
                    "access_token": "refreshedtoken",
                    "refresh_token": "refreshtoken2",
                    "expires_in": 600,
                    "token_type": "Bearer",
                },
            ],
            "http://app/test": [{"_code": 401}, {}, {}],
        }

        with patch.object(
            self.client, "_get_server", side_effect=set_token(self.client, "authz")
        ) as gsm:
            with patch.object(
                openidcclient.httpx, "request", side_effect=mock_request(postresp)
            ) as postmock:
                result = self.client.send_request(
                    "http://app/test",
                    scopes=["test_send_request_not_valid_token_401_" + "refreshable"],
                    json={"foo": "bar"},
                )
                assert gsm.call_count == 1
                self.assertEqual(result.json(), {})
                postmock.assert_called_with(
                    "POST",
                    "http://app/test",
                    json={"foo": "bar"},
                    headers={"Authorization": "Bearer refreshedtoken"},
                )
                postmock.reset_mock()
                self.client._refresh_cache()
                result = self.client.send_request(
                    "http://app/test",
                    scopes=["test_send_request_not_valid_token_401_" + "refreshable"],
                    json={"foo": "bar"},
                )
                self.assertEqual(result.json(), {})
                postmock.assert_called_with(
                    "POST",
                    "http://app/test",
                    json={"foo": "bar"},
                    headers={"Authorization": "Bearer refreshedtoken"},
                )

    def test_send_request_not_valid_token_401_not_refreshable(self):
        """Test that we only try to refresh once and then throw away."""
        postresp = {
            "https://idp/Token": [
                {
                    "access_token": "testtoken",
                    "refresh_token": "refreshtoken",
                    "expires_in": 600,
                    "token_type": "Bearer",
                },
                {"error": "invalid_token", "error_description": "Could not refresh"},
            ],
            "http://app/test": [
                {"_code": 401},
            ],
        }

        with patch.object(
            self.client, "_get_server", side_effect=set_token(self.client, "authz")
        ) as gsm:
            with patch.object(
                openidcclient.httpx, "request", side_effect=mock_request(postresp)
            ):
                result = self.client.send_request(
                    "http://app/test",
                    scopes=[
                        "test_send_request_not_valid_token_401_not_" + "refreshable"
                    ],
                )
                assert gsm.call_count == 1
                self.assertEqual(result.status_code, 401)
                self.assertEqual(result.json(), {})
                # Make sure that if there was an error, the token is cleared
                self.assertEqual(
                    self.client.get_token(
                        ["test_send_request_not_valid_token_401_not_refreshable"],
                        new_token=False,
                    ),
                    None,
                )
