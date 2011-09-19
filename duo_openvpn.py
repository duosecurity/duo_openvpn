#!/usr/bin/env python
#
# duo_openvpn.py
# Duo OpenVPN v1
# Copyright 2011 Duo Security, Inc.
#

import os, sys, urllib, hashlib, httplib, hmac, base64, json, syslog

IKEY = ''
SKEY = ''
HOST = ''

API_RESULT_AUTH   = 'auth'
API_RESULT_ALLOW  = 'allow'
API_RESULT_DENY   = 'deny'
API_RESULT_ENROLL = 'enroll'

def canonicalize(method, host, uri, params):
    canon = [method.upper(), host.lower(), uri]

    args = []
    for key in sorted(params.keys()):
        val = params[key]
        arg = '%s=%s' % (urllib.quote(key, '~'), urllib.quote(val, '~'))
        args.append(arg)
    canon.append('&'.join(args))

    return '\n'.join(canon)

def sign(ikey, skey, method, host, uri, params):
    sig = hmac.new(skey, canonicalize(method, host, uri, params), hashlib.sha1)
    auth = '%s:%s' % (ikey, sig.hexdigest())
    return 'Basic %s' % base64.b64encode(auth)

def call(ikey, skey, host, method, path, **kwargs):
    headers = {'Authorization':sign(ikey, skey, method, host, path, kwargs)}

    if method in [ 'POST', 'PUT' ]:
        headers['Content-type'] = 'application/x-www-form-urlencoded'
        body = urllib.urlencode(kwargs, doseq=True)
        uri = path
    else:
        body = None
        uri = path + '?' + urllib.urlencode(kwargs, doseq=True)

    conn = httplib.HTTPSConnection(host, 443)
    conn.request(method, uri, body, headers)
    response = conn.getresponse()
    data = response.read()
    conn.close()
    
    return (response.status, response.reason, data)

def api(ikey, skey, host, method, path, **kwargs):
    (status, reason, data) = call(ikey, skey, host, method, path, **kwargs)
    if status != 200:
        raise RuntimeError('Received %s %s: %s' % (status, reason, data))

    try:
        data = json.loads(data)
        if data['stat'] != 'OK':
            raise RuntimeError('Received error response: %s' % data)
        return data['response']
    except (ValueError, KeyError):
        raise RuntimeError('Received bad response: %s' % data)

def log(msg):
    msg = 'Duo OpenVPN: %s' % msg
    syslog.syslog(msg)

def preauth(username):
    log('pre-authentication for %s' % username)

    args = {
        'user': username,
    }

    response = api(IKEY, SKEY, HOST, 'POST', '/rest/v1/preauth', **args)

    result = response.get('result')

    if not result:
        log('invalid API response: %s' % response)
        sys.exit(1)

    if result == API_RESULT_AUTH:
        return

    status = response.get('status')

    if not status:
        log('invalid API response: %s' % response)
        sys.exit(1)

    if result == API_RESULT_ENROLL:
        log('user %s is not enrolled: %s' % (username, status))
        sys.exit(1)
    elif result == API_RESULT_DENY:
        log('preauth failure for %s: %s' % (username, status))
        sys.exit(1)
    elif result == API_RESULT_ALLOW:
        log('preauth success for %s: %s' % (username, status))
        sys.exit(0)
    else:
        log('unknown preauth result: %s' % result)
        sys.exit(1)

def auth(username, password, ipaddr):
    log('authentication for %s' % username)

    args = {
        'user': username,
        'factor': 'auto',
        'auto': password,
        'ipaddr': ipaddr
    }

    response = api(IKEY, SKEY, HOST, 'POST', '/rest/v1/auth', **args)

    result = response.get('result')
    status = response.get('status')

    if not result or not status:
        log('invalid API response: %s' % response)
        sys.exit(1)

    if result == API_RESULT_ALLOW:
        log('auth success for %s: %s' % (username, status))
        sys.exit(0)
    elif result == API_RESULT_DENY:
        log('auth failure for %s: %s' % (username, status))
        sys.exit(1)
    else:
        log('unknown auth result: %s' % result)
        sys.exit(1)

def main():
    username = os.environ.get('common_name')
    password = os.environ.get('password')
    ipaddr = os.environ.get('untrusted_ip', '0.0.0.0')

    if not username or not password:
        log('environment variables not found')
        sys.exit(1)

    try:
        preauth(username)
    except Exception, e:
        log(str(e))
        sys.exit(1)

    try:
        auth(username, password, ipaddr)
    except Exception, e:
        log(str(e))
        sys.exit(1)

    sys.exit(1)

if __name__ == '__main__':
    main()
