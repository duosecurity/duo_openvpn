#!/usr/bin/env python
#
# duo_openvpn.py
# Duo OpenVPN v1
# Copyright 2011 Duo Security, Inc.
#

import os, sys, urllib, hashlib, httplib, hmac, base64, json, syslog

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

def success(control):
    log('writing success code to %s' % control)

    f = open(control, 'w')
    f.write('1')
    f.close()

    sys.exit(0)

def failure(control):
    log('writing failure code to %s' % control)

    f = open(control, 'w')
    f.write('0')
    f.close()

    sys.exit(1)

def preauth(ikey, skey, host, control, username):
    log('pre-authentication for %s' % username)

    args = {
        'user': username,
    }

    response = api(ikey, skey, host, 'POST', '/rest/v1/preauth', **args)

    result = response.get('result')

    if not result:
        log('invalid API response: %s' % response)
        failure(control)

    if result == API_RESULT_AUTH:
        return

    status = response.get('status')

    if not status:
        log('invalid API response: %s' % response)
        failure(control)

    if result == API_RESULT_ENROLL:
        log('user %s is not enrolled: %s' % (username, status))
        failure(control)
    elif result == API_RESULT_DENY:
        log('preauth failure for %s: %s' % (username, status))
        failure(control)
    elif result == API_RESULT_ALLOW:
        log('preauth success for %s: %s' % (username, status))
        success(control)
    else:
        log('unknown preauth result: %s' % result)
        failure(control)

def auth(ikey, skey, host, control, username, password, ipaddr):
    log('authentication for %s' % username)

    args = {
        'user': username,
        'factor': 'auto',
        'auto': password,
        'ipaddr': ipaddr
    }

    response = api(ikey, skey, host, 'POST', '/rest/v1/auth', **args)

    result = response.get('result')
    status = response.get('status')

    if not result or not status:
        log('invalid API response: %s' % response)
        failure(control)

    if result == API_RESULT_ALLOW:
        log('auth success for %s: %s' % (username, status))
        success(control)
    elif result == API_RESULT_DENY:
        log('auth failure for %s: %s' % (username, status))
        failure(control)
    else:
        log('unknown auth result: %s' % result)
        failure(control)

def main():
    ikey = os.environ.get('ikey')
    skey = os.environ.get('skey')
    host = os.environ.get('host')

    if not ikey or not skey or not host:
        log('required ikey/skey/host configuration parameters not found')
        sys.exit(1)

    control = os.environ.get('control')
    username = os.environ.get('username')
    password = os.environ.get('password')
    ipaddr = os.environ.get('ipaddr', '0.0.0.0')

    if not control or not username or not password:
        log('required environment variables not found')
        failure(control)

    try:
        preauth(ikey, skey, host, control, username)
    except Exception, e:
        log(str(e))
        failure(control)

    try:
        auth(ikey, skey, host, control, username, password, ipaddr)
    except Exception, e:
        log(str(e))
        failure(control)

    failure(control)

if __name__ == '__main__':
    main()
