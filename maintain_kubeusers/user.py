import fcntl
import logging
import os
import stat

from cryptography.hazmat.primitives import serialization
import yaml


REQUIRED_CONFIG_KEYS = (
    "apiVersion",
    "kind",
    "clusters",
    "users",
    "contexts",
    "current-context",
)


class User:
    """Simple user object"""

    def __init__(
        self,
        name,
        id,
        home,
        pwdAccountLockedTime,
        pwdPolicySubentry,
        admin=False,
        project="tools",
    ):
        self.name = name
        self.id = id
        self.home = home
        self.admin = admin
        self.pk = None
        self.cert = None
        self.project = project
        self.pwdPolicySubentry = pwdPolicySubentry
        self.pwdAccountLockedTime = pwdAccountLockedTime
        self.ctx = (
            "toolforge" if self.project.startswith("tools") else self.project
        )
        self.kubeuser = (
            f"tf-{self.name}"
            if self.project.startswith("tools")
            else f"{self.project}-{self.name}"
        )
        self.ns = (
            f"tool-{self.name}"
            if self.project.startswith("tools")
            else "default"
        )

    def is_disabled(self):
        return (self.pwdPolicySubentry is not None) or (
            self.pwdAccountLockedTime is not None
        )

    def read_config_file(self):
        path = os.path.join(self.home, ".kube", "config")
        # If this is not yaml (JSON is YAML), fail with warning on this user.
        try:
            with open(path) as oldpath:
                config = yaml.safe_load(oldpath)
        except Exception:
            logging.warning("Invalid config at %s!", path)
            return {}

        # At least make sure we are using valid required keys before proceeding
        if config is not None and all(
            k in config for k in REQUIRED_CONFIG_KEYS
        ):
            return config
        else:
            # Don't touch invalid configs
            logging.warning("Invalid config at %s!", path)
            return {}

    def write_config_file(self, config):
        path = os.path.join(self.home, ".kube", "config")
        f = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW | os.O_TRUNC)
        try:
            fcntl.flock(f, fcntl.LOCK_EX)
            os.write(
                f,
                yaml.safe_dump(
                    config, encoding="utf-8", default_flow_style=False
                ),
            )
            fcntl.flock(f, fcntl.LOCK_UN)
            # uid == gid
            os.fchown(f, int(self.id), int(self.id))
            os.fchmod(f, 0o600)
            logging.info("Wrote config in %s", path)
        except os.error:
            logging.exception("Error creating %s", path)
            raise
        finally:
            os.close(f)

    def create_homedir(self):
        """
        Create homedirs for new users

        """
        mode = 0o700 if self.admin else 0o775
        if not os.path.exists(self.home):
            # Try to not touch it if it already exists
            # This prevents us from messing with permissions while also
            # not crashing if homedirs already do exist
            # This also protects against the race exploit that can be done
            # by having a symlink from /data/project/$username point as a
            # symlink to anywhere else. The ordering we have here prevents it -
            # if it already exists in the race between the 'exists' check and
            # the makedirs,
            # we will just fail. Then we switch mode but not ownership, so
            # attacker can not just delete and create a symlink to wherever.
            # The chown happens last, so should be ok.

            os.makedirs(self.home, mode=mode, exist_ok=False)
            os.chmod(self.home, mode | stat.S_ISGID)
            os.chown(self.home, int(self.id), int(self.id))

            logs_dir = os.path.join(self.home, "logs")
            os.makedirs(logs_dir, mode=mode, exist_ok=False)
            os.chmod(logs_dir, mode | stat.S_ISGID)
            os.chown(self.home, int(self.id), int(self.id))
        else:
            logging.info("Homedir already exists for %s", self.home)

    def append_config(self, config, api_server, ca_data, keyfile, certfile):
        config["clusters"].append(
            {
                "cluster": {
                    "server": api_server,
                    "certificate-authority-data": ca_data,
                },
                "name": self.ctx,
            }
        )
        config["users"].append(
            {
                "user": {"client-certificate": certfile, "client-key": keyfile},
                "name": self.kubeuser,
            }
        )
        config["contexts"].append(
            {
                "context": {
                    "cluster": self.ctx,
                    "user": self.kubeuser,
                    "namespace": self.ns,
                },
                "name": self.ctx,
            }
        )

    def merge_config(self, config, api_server, ca_data, keyfile, certfile):
        for i in range(len(config["clusters"])):
            if config["clusters"][i]["name"] == self.ctx:
                config["clusters"][i] = {
                    "cluster": {
                        "server": api_server,
                        "certificate-authority-data": ca_data,
                    },
                    "name": self.ctx,
                }
        for i in range(len(config["users"])):
            if "client-certificate" in config["users"][i]["user"]:
                config["users"][i] = {
                    "user": {
                        "client-certificate": certfile,
                        "client-key": keyfile,
                    },
                    "name": self.kubeuser,
                }
        for i in range(len(config["contexts"])):
            if config["contexts"][i]["name"] == self.ctx:
                config["contexts"][i] = {
                    "context": {
                        "cluster": self.ctx,
                        "user": self.kubeuser,
                        "namespace": self.ns,
                    },
                    "name": self.ctx,
                }

        # Remove remains of a 'toolforge' cluster if needed. Previously the
        # cluster name was hardcoded, but currently it's based on the project
        # name.
        if self.ctx != "toolforge":
            config["contexts"] = [
                context
                for context in config["contexts"]
                if context["name"] != "toolforge"
            ]

    def write_kubeconfig(self, api_server, ca_data):
        """
        Write or merge an appropriate .kube/config for given user to access
        given api server.
        """
        dirpath = os.path.join(self.home, ".kube")
        cdir_name = ".admkube" if self.admin else ".toolskube"
        # use relative paths to allow relocating the kubeconfig files and certs
        # as supported by the official libraries
        certpath = os.path.join("..", cdir_name)
        certfile = os.path.join(certpath, "client.crt")
        keyfile = os.path.join(certpath, "client.key")

        path = os.path.join(dirpath, "config")
        mode = 0o700 if self.admin else 0o775
        # If the path exists, merge the configs and do not force the switch to
        # this cluster
        if os.path.isfile(path):
            config = self.read_config_file()
            if config:
                # First check if we are using a "virgin" Toolforge 1.0 config
                is_new = True
                for i in range(len(config["clusters"])):
                    if config["clusters"][i]["name"] == self.ctx:
                        is_new = False

                if is_new:
                    # Add the new context for future use and move along
                    self.append_config(
                        config, api_server, ca_data, keyfile, certfile
                    )
                else:
                    # We need to overwrite only the "toolforge" configs
                    self.merge_config(
                        config, api_server, ca_data, keyfile, certfile
                    )
            else:
                # Don't touch invalid configs
                return

        else:
            # Declare a config, then append the new material
            config = {
                "apiVersion": "v1",
                "kind": "Config",
                "clusters": [],
                "users": [],
                "contexts": [],
                "current-context": self.ctx,
            }
            self.append_config(config, api_server, ca_data, keyfile, certfile)

        # exist_ok=True is fine here, and not a security issue (Famous
        # last words?).
        os.makedirs(dirpath, mode=mode, exist_ok=True)
        os.chown(dirpath, int(self.id), int(self.id))

        full_certpath = os.path.realpath(os.path.join(dirpath, certpath))
        os.makedirs(full_certpath, mode=mode, exist_ok=True)
        os.chown(full_certpath, int(self.id), int(self.id))

        self.write_certs()
        self.write_config_file(config)

    def write_certs(self):
        cdir_name = ".admkube" if self.admin else ".toolskube"
        location = os.path.join(self.home, cdir_name)
        try:
            # The x.509 cert is already ready to write
            crt_path = os.path.join(location, "client.crt")
            with open(crt_path, "wb") as cert_file:
                cert_file.write(self.cert)
            os.chown(crt_path, int(self.id), int(self.id))
            os.chmod(crt_path, 0o400)

            # The private key is an object and needs serialization
            key_path = os.path.join(location, "client.key")
            with open(key_path, "wb") as key_file:
                key_file.write(
                    self.pk.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )
            os.chown(key_path, int(self.id), int(self.id))
            os.chmod(key_path, 0o400)
        except Exception:
            logging.warning(
                "Path %s is not writable or failed to store certs somehow",
                location,
            )
            raise
