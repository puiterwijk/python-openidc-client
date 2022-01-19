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

"""Client for applications relying on OpenID Connect for authentication."""

from __future__ import print_function

from base64 import urlsafe_b64encode
from copy import copy
from hashlib import sha256
import json
import logging
from threading import Lock
import time
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
import secrets
import socket
import os
try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode
from uuid import uuid4 as uuidgen
import webbrowser
from wsgiref import simple_server

import requests
import sys

from openidc_client import release

# The ports that we will try to use for our webserver
WEB_PORTS = [12345, 23456]
# Length of the PKCE code verifier
PKCE_CODE_VERIFIER_LENGTH = 64


class OpenIDCClient(object):
    # Internal implementation of tokens:
    #  Every app id has its own token cache
    #  The token cache is a json serialized dict
    #  This dict contains uuid: token pairs
    #  Every "token" object is a json dict with the following keys:
    #   idp: The URL of the idp that issued the token
    #   sub: The subject that owns the token
    #   access_token: Token value
    #   token_type: Token type. Currently supported: "Bearer"
    #   expires_at: Token expiration UTC time. NOTE: Even if the expires_at
    #    indicates the token should still be valid, it may have been revoked by
    #    the user! Also, even if it has expired, we might still be able to
    #    refresh the token.
    #   refresh_token: The token we can use to refresh the access token
    #   scopes: A list of scopes that we had requested with the token
    def __init__(self, app_identifier, id_provider, id_provider_mapping,
                 client_id, client_secret=None, use_post=False, useragent=None,
                 cachedir=None, printfd=sys.stdout, use_pkce=False):
        """Client for interacting with web services relying on OpenID Connect.

        :param app_identifier: Identifier for storage of retrieved tokens
        :param id_provider: URL of the identity provider to get tokens from
        :param id_provider_mapping: Mapping with URLs to use for specific
            endpoints on the IdP.
        :kwarg use_post: Whether to use POST submission of client secrets
            rather than Authorization header
        :kwarg client_id: The Client Identifier used to request credentials
        :kwarg client_secret: The client "secret" that goes with the client_id.
            May be None if your IdP does not require you to use a secret.
        :kwarg useragent: Useragent string to use. If not provided, defaults to
            "python-openidc-client/VERSION"
        :kwarg cachedir: The directory in which to store the token caches. Will
            be put through expanduer. Default is ~/.openidc. If this does not
            exist and we are unable to create it, the OSError will be thrown.
        :kwargs printfd: The File object to print token instructions to.
        :kwargs use_pkce: Whether to use PKCE for token requests.
        """
        self.logger = logging.getLogger(__name__)
        self.debug = self.logger.debug

        self.app_id = app_identifier
        self.use_post = use_post
        self.idp = id_provider
        self.idp_mapping = id_provider_mapping
        self.client_id = client_id
        self.client_secret = client_secret
        self.useragent = useragent or 'python-openid-client/%s' % \
            release.VERSION
        self.cachedir = os.path.expanduser(cachedir or '~/.openidc')
        self.last_returned_uuid = None
        self.problem_reported = False
        self.token_to_try = None
        self._retrieved_code = None
        # TODO: Make cache_lock a filesystem lock so we also lock across
        # multiple invocations
        self._cache_lock = Lock()
        with self._cache_lock:
            self.__refresh_cache()
        self._valid_cache = []
        self._printfd = printfd
        self._use_pkce = use_pkce

    def get_token(self, scopes, new_token=True):
        """Function to retrieve tokens with specific scopes.

        This function will block until a token is retrieved if requested.
        It is always safe to call this though, since if we already have a token
        with the current app_identifier that has the required scopes, we will
        return it.

        This function will return a bearer token or None.
        Note that the bearer token might have been revoked by the user or
        expired.
        In that case, you will want to call report_token_issue() to try to
        renew the token or delete the token.

        :kwarg scopes: A list of scopes required for the current client.
        :kwarg new_token: If True, we will actively request the user to get a
            new token with the current scopeset if we do not already have on.
        :rtype: string or None
        :returns: String bearer token if possible or None
        """
        if not isinstance(scopes, list):
            raise ValueError('Scopes must be a list')
        token = self._get_token_with_scopes(scopes)
        if token:
            # If we had a valid token, use that
            self.last_returned_uuid = token[0]
            self.problem_reported = False
            return token[1]['access_token']
        elif not new_token:
            return None

        # We did not have a valid token, now comes the hard part...
        uuid = self._get_new_token(scopes)
        if uuid:
            self.last_returned_uuid = uuid
            self.problem_reported = False
            return self._cache[uuid]['access_token']

    def report_token_issue(self):
        """Report an error with the last token that was returned.

        This will attempt to renew the token that was last returned.
        If that worked, we will return the new access token.
        If it did not work, we will return None and remove this token from the
        cache.

        If you get an indication from your application that the token you sent
        was invalid, you should call it.
        You should explicitly NOT call this function if the token was valid but
        your request failed due to a server error or because the account or
        token was lacking specific permissions.
        """
        if not self.last_returned_uuid:
            raise Exception('Cannot report issue before requesting token')
        if self.problem_reported:
            # We were reported an issue before. Let's just remove this token.
            self._delete_token(self.last_returned_uuid)
            return None
        refresh_result = self._refresh_token(self.last_returned_uuid)
        if not refresh_result:
            self._delete_token(self.last_returned_uuid)
            return None
        else:
            self.problem_reported = True
            return self._cache[self.last_returned_uuid]['access_token']

    def send_request(self, *args, **kwargs):
        """Make an python-requests POST request.

        Allarguments and keyword arguments are like the arguments to requests,
        except for `scopes`, `new_token` and `auto_refresh`  keyword arguments.
        `scopes` is required.

        :kwarg scopes: Scopes required for this call. If a token is not present
            with this token, a new one will be requested unless nonblocking is
            True.
        :kwarg new_token: If True, we will actively request the user to get a
            new token with the current scopeset if we do not already have on.
        :kwarg auto_refresh: If False, will not try to automatically report
            token issues on 401. This helps with broken apps that may send a
            401 return code in incorrect cases.
        :kwargs http_method: The HTTP method to use, defaults to POST..
        """
        ckwargs = copy(kwargs)

        scopes = ckwargs.pop('scopes')
        new_token = ckwargs.pop('new_token', True)
        auto_refresh = ckwargs.pop('auto_refresh', True)
        method = ckwargs.pop('http_method', 'POST')

        is_retry = False
        if self.token_to_try:
            is_retry = True
            token = self.token_to_try
            self.token_to_try = None
        else:
            token = self.get_token(scopes, new_token=new_token)
            if not token:
                return None

        if self.use_post:
            if 'json' in ckwargs:
                raise ValueError('Cannot provide json in a post call')
            if method not in ['POST']:
                raise ValueError('Cannot use POST tokens in %s method' %
                                 method)

            if 'data' not in ckwargs:
                ckwargs['data'] = {}
            ckwargs['data']['access_token'] = token
        else:
            if 'headers' not in ckwargs:
                ckwargs['headers'] = {}
            ckwargs['headers']['Authorization'] = 'Bearer %s' % token

        resp = requests.request(method, *args, **ckwargs)
        if resp.status_code == 401 and not is_retry:
            if not auto_refresh:
                return resp

            self.token_to_try = self.report_token_issue()
            if not self.token_to_try:
                return resp
            return self.send_request(*args, **kwargs)
        elif resp.status_code == 401:
            # We got a 401 and this is a retry. Report error
            self.report_token_issue()
            return resp
        else:
            return resp

    @property
    def _cachefile(self):
        """Property to get the cache file name for the current client.

        This assures that whenever this file is touched, the cache lock is held
        """
        assert self._cache_lock.locked()
        return os.path.join(self.cachedir, 'oidc_%s.json' % self.app_id)

    def __refresh_cache(self):
        """Refreshes the self._cache from the cache on disk.

        Requires cache_lock to be held by caller."""
        assert self._cache_lock.locked()
        self.debug('Refreshing cache')
        if not os.path.isdir(self.cachedir):
            self.debug('Creating directory')
            os.makedirs(self.cachedir)
        if not os.path.exists(self._cachefile):
            self.debug('Creating file')
            with open(self._cachefile, 'w') as f:
                f.write(json.dumps({}))
        with open(self._cachefile, 'r') as f:
            self._cache = json.loads(f.read())
        self.debug('Loaded %i tokens', len(self._cache))

    def _refresh_cache(self):
        """Refreshes the self._cache from the cache on disk.

        cache_lock may not be held by anyone."""
        with self._cache_lock:
            self.__refresh_cache()

    def __write_cache(self):
        """Wirtes self._cache to cache on disk.

        Requires cache_lock to be held by caller."""
        assert self._cache_lock.locked()
        self.debug('Writing cache with %i tokens', len(self._cache))
        with open(self._cachefile, 'w') as f:
            f.write(json.dumps(self._cache))

    def _add_token(self, token):
        """Adds a token to the cache and writes cache to disk.

        cache_lock may not be held by anyone.

        :param token: Dict of the token to be added to the cache
        """
        uuid = uuidgen().hex
        self.debug('Adding token %s to cache', uuid)
        with self._cache_lock:
            self.__refresh_cache()
            self._cache[uuid] = token
            self.__write_cache()
        return uuid

    def _update_token(self, uuid, toupdate):
        """Updates a token in the cache.

        cache_lock may not be held by anyone.

        :param token: UUID of the token to be updated
        :param toupdate: Dict indicating which fields need to be updated
        """
        self.debug('Updating token %s in cache, fields %s',
                   uuid, toupdate.keys())
        with self._cache_lock:
            self.__refresh_cache()
            if uuid not in self._cache:
                return None
            self._cache[uuid].update(toupdate)
            self.__write_cache()
        return uuid

    def _delete_token(self, uuid):
        """Removes a token from the cache and writes cache to disk.

        cache_lock may not be held by anyone.

        :param uuid: UUID of the token to be removed from cache
        """
        self.debug('Removing token %s from cache', uuid)
        with self._cache_lock:
            self.__refresh_cache()
            if uuid in self._cache:
                self.debug('Removing token')
                del self._cache[uuid]
                self.__write_cache()
            else:
                self.debug('Token was already gone')

    def _get_token_with_scopes(self, scopes):
        """Searches the cache for any tokens that have the requested scopes.

        It will prefer to return tokens whose expires_at is still before the
        current time, but if no such tokens exist it will return the possibly
        expired token: it might be refreshable.

        :param scopes: List of scopes that need to be in the returned token
        :rtype: (string, dict)  or None
        :returns: Token UUID and contents or None if no applicable tokens were
            found
        """
        possible_token = None
        self.debug('Trying to get token with scopes %s', scopes)
        for uuid in self._cache:
            self.debug('Checking %s', uuid)
            token = self._cache[uuid]
            if token['idp'] != self.idp:
                self.debug('Incorrect idp')
                continue
            if not set(scopes).issubset(set(token['scopes'])):
                self.debug('Missing scope: %s not subset of %s',
                           set(scopes),
                           set(token['scopes']))
                continue
            if token['expires_at'] < time.time():
                # This is a token that's supposed to still be valid, prefer it
                # over any others we have
                self.debug('Not yet expired, returning')
                return uuid, token
            # This is a token that may or may not still be valid
            self.debug('Possible')
            possible_token = (uuid, token)
        if possible_token:
            self.debug('Returning possible token')
            return possible_token

    def _idp_url(self, method):
        """Returns the IdP URL for the requested method.

        :param method: The method name in the IdP mapping dict.
        :rtype: string
        :returns: The IdP URL
        """
        if method in self.idp_mapping:
            return self.idp + self.idp_mapping[method]
        else:
            return ValueError('Idp Mapping did not include path for %s'
                              % method)

    def _refresh_token(self, uuid):
        """Tries to refresh a token and put the refreshed token in self._cache

        The caller is responsible for either removing the token if it could not
        be refreshed or saving the cache if renewal was succesful.

        :param uuid: The UUID of the cached token to attempt to refresh.
        :rtype: bool
        :returns: True if the token was succesfully refreshed, False otherwise
        """
        oldtoken = self._cache[uuid]
        if not oldtoken['refresh_token']:
            self.debug("Unable to refresh: no refresh token present")
            return False
        self.debug('Refreshing token %s', uuid)
        data = {'client_id': self.client_id,
                'grant_type': 'refresh_token',
                'refresh_token': oldtoken['refresh_token']}
        if self.client_secret:
            data['client_secret'] = self.client_secret

        resp = requests.request(
            'POST',
            self._idp_url('Token'),
            data=data)
        resp.raise_for_status()
        resp = resp.json()
        if 'error' in resp:
            self.debug('Unable to refresh, error: %s', resp['error'])
            return False
        self._update_token(
            uuid,
            {'access_token': resp['access_token'],
             'token_type': resp['token_type'],
             'refresh_token': resp['refresh_token'],
             'expires_at': time.time() + resp['expires_in']})
        self.debug('Refreshed until %s', self._cache[uuid]['expires_at'])
        return True

    def _get_server(self, app):
        """This function returns a SimpleServer with an available WEB_PORT."""
        for port in WEB_PORTS:
            try:
                server = simple_server.make_server('0.0.0.0', port, app)
                return server
            except socket.error:
                # This port did not work. Switch to next one
                continue

    def _get_new_token(self, scopes):
        """This function kicks off some magic.

        We will start a new webserver on one of the WEB_PORTS, and then either
        show the user a URL, or if possible, kick off their browser.
        This URL will be the Authorization endpoint of the IdP with a request
        for our client_id to get a new token with the specified scopes.
        The webserver will then need to catch the return with either an
        Authorization Code (that we will exchange for an access token) or the
        cancellation message.

        This function will store the new token in the local cache, add it to
        the valid cache, and then return the UUID.
        If the user cancelled (or we got another error), we will return None.
        """
        def _token_app(environ, start_response):
            query = environ['QUERY_STRING']
            split = query.split('&')
            kv = dict([v.split('=', 1) for v in split])

            if 'error' in kv:
                self.debug('Error code returned: %s (%s)',
                           kv['error'], kv.get('error_description'))
                self._retrieved_code = False
            else:
                self._retrieved_code = kv['code']

            # Just return a message
            start_response('200 OK', [('Content-Type', 'text/plain')])
            return [u'You can close this window and return to the CLI'.encode('ascii')]

        self._retrieved_code = None
        server = self._get_server(_token_app)
        if not server:
            raise Exception('We were unable to instantiate a webserver')
        return_uri = 'http://localhost:%i/' % server.socket.getsockname()[1]
        rquery = {}
        rquery['scope'] = ' '.join(scopes)
        rquery['response_type'] = 'code'
        rquery['client_id'] = self.client_id
        rquery['redirect_uri'] = return_uri
        rquery['response_mode'] = 'query'

        if self._use_pkce:
            code_verifier = secrets.token_urlsafe(PKCE_CODE_VERIFIER_LENGTH)
            code_challenge = urlsafe_b64encode(
                sha256(code_verifier.encode('utf-8')).digest()
            )
            rquery['code_challenge'] = code_challenge.decode('utf-8').rstrip('=')
            rquery['code_challenge_method'] = 'S256'

        query = urlencode(rquery)
        authz_url = '%s?%s' % (self._idp_url('Authorization'), query)
        print('Please visit %s to grant authorization' % authz_url,
              file=self._printfd)
        webbrowser.open(authz_url)
        server.handle_request()
        server.server_close()

        assert self._retrieved_code is not None
        if self._retrieved_code is False:
            # The user cancelled the request
            self._retrieved_code = None
            self.debug('User cancelled')
            return None

        self.debug('We got an authorization code!')
        data = {'client_id': self.client_id,
                'grant_type': 'authorization_code',
                'redirect_uri': return_uri,
                'code': self._retrieved_code}
        if self.client_secret:
            data['client_secret'] = self.client_secret
        if self._use_pkce:
            data['code_verifier'] = code_verifier

        resp = requests.request(
            'POST',
            self._idp_url('Token'),
            data=data)
        resp.raise_for_status()
        self._retrieved_code = None
        resp = resp.json()
        if 'error' in resp:
            self.debug('Error exchanging authorization code: %s',
                       resp['error'])
            return None
        token = {'access_token': resp['access_token'],
                 'refresh_token': resp.get('refresh_token'),
                 'expires_at': time.time() + int(resp['expires_in']),
                 'idp': self.idp,
                 'token_type': resp['token_type'],
                 'scopes': scopes}
        # AND WE ARE DONE! \o/
        return self._add_token(token)
