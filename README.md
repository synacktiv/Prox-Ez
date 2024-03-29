# Prox-Ez: The Swiss Army Knife of HTTP auth

This HTTP proxy handles all HTTP authentications on your behalf.

It supports NTLM EPA (channel binding and service binding), kerberos, pass-the-hash, overpass-the-hash (pass-the-key) and pass-the-ticket (TGT and TGS).

Related articles:
- [Dissecting NTLM EPA with love & building a MitM proxy](https://www.synacktiv.com/publications/dissecting-ntlm-epa-with-love-building-a-mitm-proxy.html)
- [A study on Windows HTTP authentication (Part II)](https://www.synacktiv.com/publications/a-study-on-windows-http-authentication-part-ii.html)

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

Run like that, it will try to authenticate with the credentials `mydomain/myusername:mypassword` on any website that requires authentication:
```
python3 proxy.py -dc mydomain/myusername:mypassword
```

Same but using NT hash instead of password:
```
python3 proxy.py -dc mydomain/myusername --hashes :31d6cfe0d16ae931b73c59d7e0c089c0
```

### With BurpSuite

In order to work with burpsuite:
* Disable HTTP/2 support: `Project options` -> `HTTP` -> `HTTP/2` -> uncheck `Enable HTTP/2`
* Uncheck `Set response header "Connection: close"` as NTLM authenticate a TCP connection: `Proxy` -> `Options` -> `Miscellaneous` -> uncheck `Set response header "Connection: close"`.
* Uncheck `Set "Connection" header on incoming requests when using HTTP/1`: `Proxy` -> `Options` -> `Miscellaneous` -> uncheck `Set "Connection" header on incoming requests when using HTTP/1`

Afterwards, you just have to specify an upstream proxy in burp, so that it uses this proxy for the host you cannot authenticate with:
- In `Project options` -> `Connections` -> `Upstream Proxy Servers` -> click `Add` -> specify the remote hostname that is causing problems with NTLM authentication, the proxy host and port configured in the tool and leave the `Authentication type` to `None`.
- You may also need to disable the socks proxy if enabled.

### Help

```
$ python3 proxy.py -h
usage: proxy.py [-h] [--listen-address LISTEN_ADDRESS] [--listen-port LISTEN_PORT] [--cacert CACERT] [--cakey CAKEY] [--cakey-pass CAKEY_PASS] [--certsdir CERTSDIR] [--singleprocess] [--debug] [--dump-keys DUMP_KEYS] [--creds CREDS]
                [--default-creds DEFAULT_CREDS] [--hashes HASHES] [--kerberos] [--dcip DCIP] [--spn SPN] [--spn-force-fqdn] [--no-epa]

Prox-Ez: The Swiss Army Knife of HTTP auth.

optional arguments:
  -h, --help            show this help message and exit
  --listen-address LISTEN_ADDRESS, -l LISTEN_ADDRESS
                        Address the proxy will be listening on, defaults to 127.0.0.1.
  --listen-port LISTEN_PORT, -p LISTEN_PORT
                        Port the proxy will be listening on, defaults to 3128.
  --cacert CACERT       Filepath to the CA certificate, defaults to ./cacert.pem. Will be created if it does not exists.
  --cakey CAKEY         Filepath to the CA private key, defaults to ./cakey.pem. Will be created if it does not exists.
  --cakey-pass CAKEY_PASS
                        CA private key passphrase.
  --certsdir CERTSDIR   Path to the directory the generated certificates will be stored in, defaults to /tmp/Prox-Ez. Will be created if it does not exists.
  --singleprocess, -sp  Do you want to be slowwwww ?! Actually useful during debug.
  --debug, -d           Increase debug output.
  --dump-keys DUMP_KEYS, -dk DUMP_KEYS
                        File to dump the SSL/TLS keys to. Useful when trying to debug. When this option is specified, --singleprocess is implied.
  --creds CREDS         Path to the credentials file, for instance: { "my.hostname.com": { "creds": "domain/user:password", "spn": "HTTP/anothername" }, "my.second.hostname.com": { "creds": "domain1/user1", "hashes": ":nthash1" } }
  --default-creds DEFAULT_CREDS, -dc DEFAULT_CREDS
                        Default credentials that will be used to authenticate.
  --hashes HASHES       Could be used instead of password. It is associated with the domain and username given via --default_creds. format: lmhash:nthash or :nthash.
  --kerberos, -k        Enable kerberos authentication instead of NTLM.
  --dcip DCIP           IP Address of the domain controller (only for kerberos).
  --spn SPN             Use the provided SPN when an SPN is needed. More details in the article.
  --spn-force-fqdn      Force the usage of the FQDN as the SPN instead of what was specified in the URL.
  --no-epa              Deactivate the NTLM EPA feature.
```

### Known issues

- No support for websocket. It will yield assertion errors such as:
```
DEBUG:Proxy.ProxyToServerHelper:Our state: MIGHT_SWITCH_PROTOCOL; their state: SEND_RESPONSE
[...]
    assert self.conn.our_state in [h11.DONE, h11.MUST_CLOSE, h11.CLOSED] and self.conn.their_state is h11.SEND_RESPONSE
AssertionError
```

