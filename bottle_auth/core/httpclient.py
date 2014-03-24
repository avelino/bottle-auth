#
# Copyright 2008 Andi Albrecht <albrecht.andi@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Implements the URL fetch API.

http://code.google.com/appengine/docs/urlfetch/
"""

import httplib
import socket
import urlparse

# Constants
GET = 'GET'
POST = 'POST'
HEAD = 'HEAD'
PUT = 'PUT'
DELETE = 'DELETE'

MAX_REDIRECTS = 5

REDIRECT_STATUSES = frozenset([
  httplib.MOVED_PERMANENTLY,
  httplib.FOUND,
  httplib.SEE_OTHER,
  httplib.TEMPORARY_REDIRECT,
])

class SyncHTTPClient(object):
    def fetch(self, url, callback, method=GET, body=None):
        response = self._fetch(url, method=method, payload=body)
        callback(response)

    def _fetch(self, url, payload=None, method=GET, headers={}, allow_truncated=False):
        if method in [POST, PUT]:
            payload = payload or ''
            if 'Content-Type' not in headers:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
        else:
            payload = ''
        for redirect_number in xrange(MAX_REDIRECTS+1):
            scheme, host, path, params, query, fragment = urlparse.urlparse(url)
            try:
                if scheme == 'http':
                    connection = httplib.HTTPConnection(host)
                elif scheme == 'https':
                    connection = httplib.HTTPSConnection(host)
                else:
                    raise InvalidURLError('Protocol \'%s\' is not supported.')

                if query != '':
                    full_path = path + '?' + query
                else:
                    full_path = path

                adjusted_headers = {
                    'Content-Length': len(payload),
                    'Host': host,
                    'Accept': '*/*',
                }
                for header in headers:
                    adjusted_headers[header] = headers[header]

                try:
                    connection.request(method, full_path, payload,
                                       adjusted_headers)
                    http_response = connection.getresponse()
                    http_response_data = http_response.read()
                finally:
                    connection.close()

                if http_response.status in REDIRECT_STATUSES:
                    newurl = http_response.getheader('Location', None)
                    if newurl is None:
                        raise DownloadError('Redirect is missing Location header.')
                    else:
                        url = urlparse.urljoin(url, newurl)
                        method = 'GET'
                else:
                    response = Response()
                    response.body = http_response_data
                    response.status_code = http_response.status
                    response.request = Request(full_path)
                    response.headers = {}
                    for header_key, header_value in http_response.getheaders():
                        response.headers[header_key] = header_value
                    return response

            except (httplib.error, socket.error, IOError), e:
                response = Response()
                response.request = Request(full_path)
                response.error = str(e) or 'unknown error'
                return response

class Request(object):
    def __init__(self, url):
        self.url = url

class Response(object):
    body = None
    content_was_truncated = False
    error = None
    status_code = -1
    headers = None

AsyncHTTPClient = SyncHTTPClient

class Error(Exception):
    """Base class for all URL fetch exceptions."""


class InvalidURLError(Error):
    """Invalid URL."""


class DownloadError(Error):
    """Download failed."""


class ResponseTooLargeError(Error):
    """Unused."""

