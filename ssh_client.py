# -*- coding: utf-8 -*-

import StringIO
import paramiko
from spur import SshShell


class CustomSshShell(SshShell):

    def __init__(self, *args, **kwargs):
        self._pt_private_key = kwargs.pop("private_key")
        self._pt_private_key_passphrase = kwargs.pop("private_key_passphrase")
        super(CustomSshShell, self).__init__(**kwargs)

    def _connect_ssh(self):
        if self._client is None:
            if self._closed:
                raise RuntimeError("Shell is closed")
            client = paramiko.SSHClient()
            if self._load_system_host_keys:
                client.load_system_host_keys()
            client.set_missing_host_key_policy(self._missing_host_key)
            private_key = self._pt_private_key

            if private_key is not None:
                private_key = paramiko.RSAKey.from_private_key(
                    StringIO.StringIO(private_key),
                    self._pt_private_key_passphrase)

            client.connect(
                hostname=self._hostname,
                port=self._port,
                username=self._username,
                password=self._password,
                timeout=self._connect_timeout,
                sock=self._sock,
                pkey=private_key
            )
            self._client = client
        return self._client
