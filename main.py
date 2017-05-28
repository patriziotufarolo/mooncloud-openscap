#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import spur
from xml.etree import cElementTree as ElementTree

from driver import Driver
from test.ssh_client import CustomSshShell

__author__ = "Patrizio Tufarolo"
__email__ = "patrizio@tufarolo.eu"

__description__ = "This driver controls a remote OpenSCAP instance through SSH"

ocil_cs = "http://scap.nist.gov/schema/ocil/2"
xccdf_ns = "http://checklists.nist.gov/xccdf/1.1"


class SSHConnection(object):
    def read_ssh_configuration(self, inputs):
        ssh_connection_ti = self.testinstances.get("read_ssh_configuration",
                                                   None)

        assert ssh_connection_ti is not None
        hostname = ssh_connection_ti.get("hostname")
        port = ssh_connection_ti.get("port", 22)
        username = ssh_connection_ti.get("username")
        password = ssh_connection_ti.get("password", None)
        private_key = ssh_connection_ti.get("private_key", None)
        private_key_passphrase = None
        if private_key is not None:
            private_key_passphrase = ssh_connection_ti.get(
                "private_key_passphrase",
                None)

        return hostname, port, username, password, \
            private_key or None, private_key_passphrase or None

    def ssh_connection(self, inputs):
        hostname, port, username, password, \
            private_key, private_key_passphrase = inputs
        self.ssh_client = \
            CustomSshShell(hostname=hostname,
                           username=username,
                           password=password,
                           port=port,
                           private_key=private_key,
                           private_key_passphrase=private_key_passphrase,
                           missing_host_key=spur.ssh.MissingHostKey.warn,
                           shell_type=spur.ssh.ShellTypes.sh
                           )
        return isinstance(self.ssh_client, spur.SshShell)

    def ssh_create_tmp_dir(self, ssh_client_ok):
        self.temp_dir = None
        assert ssh_client_ok and isinstance(self.ssh_client, spur.SshShell)
        self.temp_dir = self.ssh_client.run(
            ["mktemp", "--directory"], encoding="ascii").output.strip()

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
        fetch_remote_resources = xccdf_ti.get("fetch_remote_resources", False)
        return xccdf, profile, fetch_remote_resources

    @staticmethod
    def get_xccdf_references(xccdf):
        result = []
        xccdftree = ElementTree.parse(
            "/usr/src/app/test/ssg/{xccdf}-xccdf.xml".format(xccdf=xccdf)
        )
        check_content_refs = xccdftree.findall(
            ".//{%s}check-content-ref" % xccdf_ns
        )

        for check_content_ref in check_content_refs:
            check_content_ref_href_attr = check_content_ref.get("href")
            if check_content_ref_href_attr.startswith("http://") or \
                    check_content_ref_href_attr.startswith("https://"):
                continue
            refhref = check_content_ref.get("href")
            if refhref not in result:
                result.append(refhref)

        return result

    def upload_files(self, inputs):
        xccdf, profile, fetch_remote_resources = inputs
        with self.ssh_client._connect_sftp() as sftp:
            sftp.put(
                "/usr/src/app/test/ssg/{xccdf}-xccdf.xml".format(xccdf=xccdf),
                self.temp_dir + "/" + "{xccdf}-xccdf.xml".format(xccdf=xccdf)
            )

            for document in self.get_xccdf_references(xccdf):
                sftp.put(
                    "/usr/src/app/test/ssg/{document}"
                    .format(document=document),
                    self.temp_dir + "/" + "{document}".
                    format(document=document)
                )
        return xccdf, profile, fetch_remote_resources

    def evaluate_xccdf(self, inputs):
        xccdf, profile, fetch_remote_resources = inputs
        ssh_command = [
            "oscap",
            "xccdf",
            "eval",
            "--profile", "{profile}".format(profile=profile),
            "--results-arf", "{temp_dir}/results.arf.xml".format(
                temp_dir=self.temp_dir
            ),
            "--progress",
            "--report",
            "{temp_dir}/report.html".format(
                temp_dir=self.temp_dir
            ),
            "{temp_dir}/{xccdf}-xccdf.xml".format(
                temp_dir=self.temp_dir, xccdf=xccdf
            )
        ]
        index = 7
        if not self.verifyRoot():
            ssh_command = ["sudo"] + ssh_command
            index += 1
        if fetch_remote_resources:
            ssh_command.insert(index, "--fetch-remote-resources")
        out = self.ssh_client.run(ssh_command, stdout=sys.stderr,
                                  stderr=sys.stderr,
                                  allow_error=True).output.strip().split("\n")

        initial_result = "pass"
        for line in out:
            if line.strip() == "":
                continue
            if ":" not in line:
                continue
            if line.startswith("Downloading"):
                continue

            splitted = line.split(":")
            if len(splitted) < 2:
                continue

            try:
                initial_result = initial_result and splitted[1] != "fail"
                self.result.put_value(splitted[0], splitted[1])
            except IndexError:
                continue

        return initial_result


class OpenSCAP_SSH(Driver, XCCDFEvaluator):

    def verifyOscapInstalled(self, inputs):
        try:
            assert self.ssh_client.run(["/usr/bin/which", "oscap"])
            return True
        except AssertionError:
            return False

        return inputs

    def verifyRoot(self):
        return self.ssh_client.run([
            "/usr/bin/id", "-u"
        ]).output.strip() == "0"

    def appendAtomics(self):
        self.appendAtomic(self.read_ssh_configuration, lambda rollback: False)
        self.appendAtomic(self.ssh_connection, self.ssh_close)
        self.appendAtomic(self.ssh_create_tmp_dir, self.ssh_remove_tmp_dir)
        self.appendAtomic(self.verifyOscapInstalled, lambda rollback: None)
        self.appendAtomic(self.read_xccdf_configuration, lambda rollback: None)
        self.appendAtomic(self.upload_files, lambda rollback: None)
        self.appendAtomic(self.evaluate_xccdf, lambda rollback: None)
        self.appendAtomic(self.ssh_remove_tmp_dir, lambda rollback: None)
        self.appendAtomic(self.ssh_close, lambda rollback: None)
