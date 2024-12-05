# Overview

[![Build Status](https://github.com/duosecurity/duo_openvpn/workflows/OpenVPN%20Python%20component%20CI/badge.svg)](https://github.com/duosecurity/duo_openvpn/actions)
[![Issues](https://img.shields.io/github/issues/duosecurity/duo_openvpn)](https://github.com/duosecurity/duo_openvpn/issues)
[![Forks](https://img.shields.io/github/forks/duosecurity/duo_openvpn)](https://github.com/duosecurity/duo_openvpn/network/members)
[![Stars](https://img.shields.io/github/stars/duosecurity/duo_openvpn)](https://github.com/duosecurity/duo_openvpn/stargazers)
[![License](https://img.shields.io/badge/License-View%20License-orange)](https://github.com/duosecurity/duo_openvpn/blob/master/LICENSE)

**duo_openvpn** - Duo two-factor authentication for OpenVPN

# Installing

Python 3 or 2.7 needs to be installed on your OpenVPN server.

Currently, this plugin is not compatible with Python 3.12.  Note that this is the default Python version for Ubuntu 24.04.

## TLS 1.2 and 1.3 Support

The OpenVPN plugin uses Python's ssl module and OpenSSL for TLS operations. Python versions 2.7 (and higher) and 3.5 (and higher) have both TLS 1.2 and TLS 1.3 support.

## Development:

Download the [Duo OpenVPN v2.4 plugin](https://github.com/duosecurity/duo_openvpn/archive/2.4.tar.gz) by clicking this link or by downloading the ZIP for this repository. Then extract it, build, and install the plugin.

```
$ cd duo_openvpn-2.4 OR cd duo_openvpn-master
$ make && sudo make install
```

Note the duo_openvpn.so plugin and duo_openvpn.py Python helper script will be installed into /opt/duo.

# Usage

## Configuring the Server

Make sure you have your OpenVPN's integration key, secret key, and API hostname. You can find these in your Duo Admin Panel under the Applications tab.

Open your OpenVPN server configuration file. It could either be:
- /etc/openvpn/openvpn.conf OR
- /etc/openvpn/server.conf
- 

For OpenVPN 2.4 and later, append the following line to it:
```
plugin /opt/duo/duo_openvpn.so 'IKEY SKEY HOST'
```
For OpenVPN 2.3 or earlier, append the following line to it:
```
plugin /opt/duo/duo_openvpn.so IKEY SKEY HOST
```

We recommend setting the reneg-sec option in the server configuration file. This option will determine how often OpenVPN forces a renegotiation, requiring the user to reauthenticate with Duo every hour. If your user's VPN client saves the password and automatically reauthenticates with it, this may cause issues. Therefore, we recommend disabling reneg-sec by setting it to 0:

```
reneg-sec 0
```

## Configure the Client
Ensure the following line is present in the OpenVPN client configuration file of all of your users:
```
auth-user-pass
```
If you specified the reneg-sec option in the server configuration, also include it in your client configuration file:
```
reneg-sec 0
```
You may also need to enable the dynamic challenge-response mechanism in your OpenVPN client. The mechanism is supported in the open-source client starting with version 2.2, but you usually must enable it explicitly.

Check if you're running version 2.2 or later of the OpenVPN client:
```
$ openvpn --version
```
Set the auth-retry option to a value of interact when running the client. For example:
```
$ openvpn --config client.ovpn --auth-retry interact
```

# Testing

When OpenVPN is configured with certificate authentication as the primary authentication factor, Duo uses the OpenVPN password field as the input mechanism for the secondary authentication factor.

When you authenticate, your OpenVPN client will prompt you to provide an additional username and password. The username field can usually be ignored since Duo will pull the real username from the common name field of the provided certificate. In the case that your OpenVPN clients won't let you submit a blank username, type something in that field.

In the password field of the client, you can enter the name of a Duo authentication method. Choose from "phone", "push", "sms", or with a passcode from a hardwork token or a bypass code. Adding a number following the factor identifier to choose which enrolled device you want to use. Ex: "phone2", "push2" if you want to use your second provisioned phone.

Ex: If you want to use Duo Push to authenticate:
```
username: <ignored>
password: push
```

Ex: If you want to use a Duo passcode (eg. "123456"):
```
username: <ignored>
password: 123456
```

# Support
The full documentation for OpenVPN can be found at https://duo.com/docs/openvpn.

Report any bugs, feature requests, etc. to us directly:
support@duosecurity.com

Have fun!

<http://www.duosecurity.com>
