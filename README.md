# Prox-Ez

The easy proxy to handle your NTLM EPA authentication against webservers.

## Installation

1. Install the dependancies
```
$ # In a venv
$ python3 -m venv venv
$ source venv/bin/activate
$ python3 -m pip install -r requirements.txt
```
2. Enjoy.

## Usage

### Quickstart

Run like that, it will try to authenticate with the credentials `default_user:default_password`:
```
python3 proxy.py -du default_user -dp default_password
```

### With BurpSuite

In order to work with burpsuite, disable HTTP/2 support (`Project options` -> `HTTP` -> `HTTP/2` -> uncheck `Enable HTTP/2`) and uncheck `Set "Connection close" on incoming requests` as NTLM authenticate a TCP connection.
Afterwards, you just have to specify an upstream proxy in burp, so that it uses this proxy for the host you cannot authenticate with (in `Project options` -> `Connections` -> `Upstream Proxy Servers` -> click `Add` -> specify the remote hostname that is causing problems with NTLM authentication, the proxy host and port configured in the tool and leave the `Authentication type` to `None`).
You may also need to disable the socks proxy if enabled.

### Help

```
$ python3 proxy.py -h
usage: proxy.py [-h] [--listen-address LISTEN_ADDRESS] [--listen-port LISTEN_PORT] [--cacert CACERT] [--cakey CAKEY]
                [--cakey-pass CAKEY_PASS] [--certsdir CERTSDIR] [--singleprocess] [--debug] [--creds CREDS]
                [--default_username DEFAULT_USERNAME] [--default_password DEFAULT_PASSWORD]

Simple HTTP proxy that support NTLM EPA.

optional arguments:
  -h, --help            show this help message and exit
  --listen-address LISTEN_ADDRESS, -l LISTEN_ADDRESS
                        Address the proxy will be listening on, defaults to 127.0.0.1.
  --listen-port LISTEN_PORT, -p LISTEN_PORT
                        Port the proxy will be listening on, defaults to 3128.
  --cacert CACERT       Filepath to the CA certificate, defaults to ./cacert.pem. Will be created if it does not
                        exists.
  --cakey CAKEY         Filepath to the CA private key, defaults to ./cakey.pem. Will be created if it does not
                        exists.
  --cakey-pass CAKEY_PASS
                        CA private key passphrase.
  --certsdir CERTSDIR   Path to the directory the generated certificates will be stored in, defaults to /tmp/Prox-Ez.
                        Will be created if it does not exists.
  --singleprocess, -sp  Do you want to be slowwwww ?! Actually useful during debug.
  --debug, -d           Increase debug output.
  --creds CREDS         Path to the credentials file, for instance: { "my.hostname.com": { "username": "domain/user",
                        "password": "password" }, "my.second.hostname.com": { "username": "domain1/user1",
                        "password": "password1" } }
  --default_username DEFAULT_USERNAME, -du DEFAULT_USERNAME
                        Default username to use. In the form domain/user.
  --default_password DEFAULT_PASSWORD, -dp DEFAULT_PASSWORD
                        Default password to use.
```

### Known issues

- No support for websocket. It will yield assertion errors such as:
```
DEBUG:Proxy.ProxyToServerHelper:Our state: MIGHT_SWITCH_PROTOCOL; their state: SEND_RESPONSE
[...]
    assert self.conn.our_state in [h11.DONE, h11.MUST_CLOSE, h11.CLOSED] and self.conn.their_state is h11.SEND_RESPONSE
AssertionError
```
