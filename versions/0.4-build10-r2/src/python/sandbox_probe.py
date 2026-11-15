"""Synthetic, no-data-transfer observations in the exact signed inspection worker."""
import errno
import hashlib
import json
import os
import socket
import sys

path = sys.argv[1]
rows = []
for operation, flags in (("FILE_READ_OPEN", os.O_RDONLY), ("FILE_WRITE_OPEN", os.O_WRONLY)):
    try:
        fd = os.open(path, flags | os.O_NOFOLLOW)
    except OSError as error:
        rows.append({"operation": operation, "denied": error.errno in (errno.EPERM, errno.EACCES), "errno": error.errno})
    else:
        os.close(fd)
        rows.append({"operation": operation, "denied": False, "errno": 0})
for operation in ("NETWORK_LISTEN", "NETWORK_CONNECT"):
    client = None
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(0.3)
        if operation == "NETWORK_LISTEN":
            client.bind(("127.0.0.1", 0))
            client.listen(1)
        else:
            client.connect(("127.0.0.1", 9))
    except OSError as error:
        rows.append({"operation": operation, "denied": error.errno in (errno.EPERM, errno.EACCES), "errno": error.errno})
    else:
        rows.append({"operation": operation, "denied": False, "errno": 0})
    finally:
        if client:
            client.close()
print(json.dumps({"schema": "orchard-private-sandbox-observation/1", "observations": rows,
                  "script_sha256": hashlib.sha256(open(__file__, "rb").read()).hexdigest(),
                  "authorizes_actions": False}))
