#!/usr/bin/env python3
"""One-shot LagoonBot bridge listener. Connects, waits for an @LagoonBot
PRIVMSG from an authorized user, prints it, and exits."""
import socket, sys

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect("/tmp/lagoon-bot.sock")

buf = b""
while True:
    data = sock.recv(4096)
    if not data:
        break
    buf += data
    while b"\n" in buf:
        line_bytes, buf = buf.split(b"\n", 1)
        line = line_bytes.decode("utf-8", errors="replace")
        if "PRIVMSG" in line and ("LagoonBot" in line or "lagoonbot" in line):
            print(line, flush=True)
            sock.close()
            sys.exit(0)
