#!/bin/bash

# Provides an easy way to analyse a GSS-API formatted
# message in wireshark.

# Usage example:
# ./analyze_message.sh 'Negotiate YIIEoQYGKwYBBQUCoIIElTCCBJGg...'
# See the results on wireshark by looking at the loopback interface.

port=$2
if [ -z "$2" ]; then
	port=8080
fi

nc -nvlp $port &
echo -ne 'GET / HTTP/1.1\r\nHost: Test\r\nAuthorization: '$1'\r\n\r\n' | timeout 1 nc -v 127.0.0.1 $port
nc -nvlp $port &
echo -ne 'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: '$1'\r\n\r\n' | timeout 1 nc -v 127.0.0.1 $port
