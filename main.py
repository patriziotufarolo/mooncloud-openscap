#!/usr/bin/env python
# -*- coding: utf-8 -*-

import spur
from test.ssh_client import CustomSshShell
import openscap_api as openscap

from driver import Driver

__author__ = "Patrizio Tufarolo"
__email__ = "patrizio@tufarolo.eu"

__description__ = "This driver controls a remote OpenSCAP instance through SSH"


class SSHConnection(object):
    def read_ssh_configuration(self, inputs):
        ssh_connection_ti = self.testinstances.get("read_ssh_configuration", None)

        assert not ssh_connection_ti is None
        hostname = ssh_connection_ti.get("hostname")
        port = ssh_connection_ti.get("port", 22)
        username = ssh_connection_ti.get("username")
        password = ssh_connection_ti.get("password", None)
        private_key = ssh_connection_ti.get("private_key", None)
        private_key_passphrase = None
        if private_key is not None:
            private_key_passphrase = ssh_connection_ti.get("private_key_passphrase", None)

        return hostname, port, username, password, private_key or None, private_key_passphrase or None

    def ssh_connection(self, inputs):
        hostname, port, username, password, private_key, private_key_passphrase = inputs
        self.ssh_client = CustomSshShell(hostname=hostname, username=username, password=password,
                       port=port, private_key=private_key,
                       private_key_passphrase=private_key_passphrase,
                       missing_host_key=spur.ssh.MissingHostKey.warn)
        return isinstance(self.ssh_client, spur.SshShell)


    def ssh_create_tmp_dir(self, ssh_client_ok):
        self.temp_dir = None
        assert ssh_client_ok and isinstance(self.ssh_client, spur.SshShell)
        self.temp_dir = self.ssh_client.run(["mktemp", "--directory"], encoding="ascii").output.strip()

    def ssh_remove_tmp_dir(self, inputs):
        assert self.temp_dir
        self.ssh_client.run(["rm", "-rf", self.temp_dir])

    def ssh_close(self, inputs):
        self.ssh_client.__exit__()


class XCCDFEvaluator(SSHConnection):
    def read_xccdf_configuration(self, inputs):
        xccdf_ti = self.testinstances.get("read_xccdf_configuration")
        xccdf = xccdf_ti.get("xccdf")
        profile = xccdf_ti.get("profile")
        return xccdf, profile

    @staticmethod
    def get_xccdf_references(xccdf):
        return openscap.xccdf.init("/usr/src/app/test/ssg/{xccdf}-xccdf.xml".format(xccdf=xccdf)).get("names",[]).keys()

    def upload_files(self, inputs):
        xccdf, profile = inputs
        with self.ssh_client._connect_sftp() as sftp:
            sftp.put("/usr/src/app/test/ssg/{xccdf}-xccdf.xml".format(xccdf=xccdf), self.temp_dir + "/" + "{xccdf}-xccdf.xml".format(xccdf=xccdf))
            for document in self.get_xccdf_references(xccdf):
                sftp.put("/usr/src/app/test/ssg/{document}".format(document=document), self.temp_dir)
        return xccdf, profile

    def evaluate_xccdf(self, inputs):
        xccdf, profile = inputs
        out = self.ssh_client.run(
            [
                "sudo oscap" if not self.verifyRoot() else "oscap",
                "oscap xccdf eval --profile {profile}".format(profile=profile),
                "--results-arf /tmp/results.arf.xml",
                "--report /tmp/report.html",
                "{temp_dir}/{xccdf}.xml".format(temp_dir=self.temp_dir, xccdf=xccdf)
            ]).output.split("\n")
        print(out)
        return False

class OpenSCAP_SSH(Driver, XCCDFEvaluator):
    def verifyOscapInstalled(self, inputs):
        """
        assert self.ssh_client.run([
            "/bin/bash", "-c" ,
            "'if [ \$(which oscap 2>/dev/null) ]; then echo true; else echo false; fi'"
            ]).output.strip() == "true"
        """
        return inputs

    def verifyRoot(self):
        return self.ssh_client.run([
            "/usr/bin/id -u"
        ]).output.strip() == "0"

    def appendAtomics(self):
        self.appendAtomic(self.read_ssh_configuration, lambda rollback: False)
        self.appendAtomic(self.ssh_connection, self.ssh_close)
        self.appendAtomic(self.ssh_create_tmp_dir, self.ssh_remove_tmp_dir)
        self.appendAtomic(self.verifyOscapInstalled, lambda rollback: None)
        self.appendAtomic(self.read_xccdf_configuration, lambda rollback: None)
        #@todo
        # Implement this rollback
        #            v
        self.appendAtomic(self.upload_files, lambda rollback: None)
        self.appendAtomic(self.evaluate_xccdf, lambda rollback: None)
        self.appendAtomic(self.ssh_remove_tmp_dir, lambda rollback: None)
        self.appendAtomic(self.ssh_close, lambda rollback: None)
