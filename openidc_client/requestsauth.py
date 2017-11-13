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

"""Python-Requests AuthBase wrapping OpenIDCClient."""

import requests


class OpenIDCClientAuther(requests.auth.AuthBase):
    def __init__(self, oidcclient, scopes, new_token=True):
        self.client = oidcclient
        self.scopes = scopes
        self.new_token = new_token

    def handle_response(self, response, **kwargs):
        if response.status_code in [401, 403]:
            new_token = self.client.report_token_issue()
            if not new_token:
                return response
            response.request.headers['Authorization'] = 'Bearer %s' % new_token

            # Consume the content so we can reuse the connection
            response.content
            response.raw.release_conn()

            r = response.connection.send(response.request)
            r.history.append(response)

            return r
        else:
            return response

    def __call__(self, request):
        request.register_hook('response', self.handle_response)
        token = self.client.get_token(self.scopes,
                                      new_token=self.new_token)
        if token is None:
            raise RuntimeError('No token received')
        request.headers['Authorization'] = 'Bearer %s' % token
        return request
