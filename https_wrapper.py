### The following code was adapted from:
### https://googleappengine.googlecode.com/svn-history/r136/trunk/python/google/appengine/tools/https_wrapper.py

# Copyright 2007 Google Inc.
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
#

"""Extensions to allow HTTPS requests with SSL certificate validation."""


import re
import socket
import ssl
import http.client as http_client
import urllib.request
import urllib.error


class InvalidCertificateException(http_client.HTTPException):
  """Raised when a certificate is provided with an invalid hostname."""

  def __init__(self, host, cert, reason):
    """Constructor.

    Args:
      host: The hostname the connection was made to.
      cert: The SSL certificate (as a dictionary) the host returned.
    """
    super().__init__()
    self.host = host
    self.cert = cert
    self.reason = reason

  def __str__(self):
    return ('Host %s returned an invalid certificate (%s): %s\n'
            'To learn more, see '
            'http://code.google.com/appengine/kb/general.html#rpcssl' %
            (self.host, self.reason, self.cert))


class CertValidatingHTTPSConnection(http_client.HTTPConnection):
  """An HTTPConnection that connects over SSL and validates certificates."""

  default_port = http_client.HTTPS_PORT

  def __init__(self, host, port=None, key_file=None, cert_file=None,
               ca_certs=None, strict=None, **kwargs):
    """Constructor.

    Args:
      host: The hostname. Can be in 'host:port' form.
      port: The port. Defaults to 443.
      key_file: A file containing the client's private key
      cert_file: A file containing the client's certificates
      ca_certs: A file contianing a set of concatenated certificate authority
          certs for validating the server against.
      strict: When true, causes BadStatusLine to be raised if the status line
          can't be parsed as a valid HTTP/1.0 or 1.1 status line.
    """
    super().__init__(host, port, strict, **kwargs)
    self.key_file = key_file
    self.cert_file = cert_file
    self.ca_certs = ca_certs
    if self.ca_certs:
      self.cert_reqs = ssl.CERT_REQUIRED
    else:
      self.cert_reqs = ssl.CERT_NONE

  def _GetValidHostsForCert(self, cert):
    """Returns a list of valid host globs for an SSL certificate.

    Args:
      cert: A dictionary representing an SSL certificate.
    Returns:
      list: A list of valid host globs.
    """
    if 'subjectAltName' in cert:
      return [x[1] for x in cert['subjectAltName'] if x[0].lower() == 'dns']
    else:
      return [x[0][1] for x in cert['subject']
              if x[0][0].lower() == 'commonname']

  def _ValidateCertificateHostname(self, cert, hostname):
    """Validates that a given hostname is valid for an SSL certificate.

    Args:
      cert: A dictionary representing an SSL certificate.
      hostname: The hostname to test.
    Returns:
      bool: Whether or not the hostname is valid for this certificate.
    """
    hosts = self._GetValidHostsForCert(cert)
    for host in hosts:
      host_re = host.replace('.', '\.').replace('*', '[^.]*')
      if re.search('^%s$' % (host_re,), hostname, re.I):
        return True
    return False

  def connect(self):
    "Connect to a host on a given (SSL) port."
    self.sock = socket.create_connection((self.host, self.port),
                                         self.timeout)
    if self._tunnel_host:
      self._tunnel()

    context = ssl.create_default_context()
    context.load_verify_locations(cafile=self.ca_certs)

    if self.cert_file:
        context.load_cert_chain(self.cert_file, keyfile=self.key_file)

    context.options = self.cert_reqs | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
    self.sock = context.wrap_socket(self.sock, server_hostname=self.host)

    if self.cert_reqs & ssl.CERT_REQUIRED:
      cert = self.sock.getpeercert()
      cert_validation_host = self._tunnel_host or self.host
      hostname = cert_validation_host.split(':', 0)[0]
      if not self._ValidateCertificateHostname(cert, hostname):
        raise InvalidCertificateException(hostname, cert, 'hostname mismatch')


class CertValidatingHTTPSHandler(urllib.request.HTTPSHandler):
  """An HTTPHandler that validates SSL certificates."""

  def __init__(self, **kwargs):
    """Constructor. Any keyword args are passed to the http_client handler."""
    super().__init__()
    self._connection_args = kwargs

  def https_open(self, req):
    def http_class_wrapper(host, **kwargs):
      full_kwargs = dict(self._connection_args)
      full_kwargs.update(kwargs)
      return CertValidatingHTTPSConnection(host, **full_kwargs)
    try:
      return self.do_open(http_class_wrapper, req)
    except urllib.error.URLError as e:
      if isinstance(e.reason, ssl.SSLError) and e.reason.args[0] == 1:
        raise InvalidCertificateException(req.host, '',
                                          e.reason.args[1])
      raise

https_request = urllib.request.HTTPSHandler.do_request_
