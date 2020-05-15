import argparse
import logging
from pathlib import Path
import sys
import time

import ldap3
import yaml
from kubernetes import config as k_config

from maintain_kubeusers.k8s_api import K8sAPI
from maintain_kubeusers.utils import (
    generate_pk,
    get_tools_from_ldap,
    get_admins_from_ldap,
    process_new_users,
)

"""
Automate the process of generating user credentials for Toolforge
Kubernetes


 - Get a list of all the users from LDAP
 - Get a list of namespaces/configmaps in k8s for each toolforge user
 - Do a diff, find new users and users with deleted configmaps
 - For each new user or removed configmap:
    - Create new namespace (only for a new user)
    - generate a CSR (including the right group for RBAC/PSP)
    - Validate and approve the CSR
    - Drop the .kube/config file in the tool directory
    - Annotate the namespace with configmap

"""


def main():
    argparser = argparse.ArgumentParser()
    group1 = argparser.add_mutually_exclusive_group()
    group2 = argparser.add_mutually_exclusive_group()
    argparser.add_argument(
        "--ldapconfig",
        help="Path to YAML LDAP config file",
        default="/etc/ldap.yaml",
    )
    argparser.add_argument(
        "--debug", help="Turn on debug logging", action="store_true"
    )
    argparser.add_argument(
        "--project",
        help="Project name to fetch LDAP users from",
        default="tools",
    )
    argparser.add_argument(
        "--admins-only",
        "-a",
        help="Only manage admin accounts for this project",
        default=False,
        action="store_true",
    )
    group1.add_argument(
        "--interval", help="Seconds between between runs", default=60
    )
    group1.add_argument("--once", help="Run once and exit", action="store_true")
    argparser.add_argument(
        "--local",
        help="Specifies this is not running in Kubernetes (for debugging)",
        action="store_true",
    )
    group2.add_argument(
        "--force-migrate",
        help=(
            "For full Kubernetes cluster change: switches every account ",
            "to use the toolforge context. Requires the --once option",
        ),
        action="store_true",
    )
    group2.add_argument(
        "--gentle-mode",
        help=(
            "Before general release, keep current context set to default "
            "while the new Kubernetes cluster is considered opt-in"
        ),
        action="store_true",
    )

    args = argparser.parse_args()
    if args.force_migrate and not args.once:
        argparser.error("--once is required when --force-migrate is set")

    loglvl = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(format="%(message)s", level=loglvl)

    with open(args.ldapconfig, encoding="utf-8") as f:
        ldapconfig = yaml.safe_load(f)

    if args.local:
        k_config.load_kube_config()
    else:
        k_config.load_incluster_config()

    k8s_api = K8sAPI()
    api_server, ca_data = k8s_api.get_cluster_info()

    while True:
        logging.info("starting a run")
        # Touch a temp file for a Kubernetes liveness check to prevent hangs
        Path("/tmp/run.check").touch()
        cur_users, expiring_users = k8s_api.get_current_users(args.admins_only)
        servers = ldap3.ServerPool(
            [ldap3.Server(s, connect_timeout=1) for s in ldapconfig["servers"]],
            ldap3.ROUND_ROBIN,
            active=True,
            exhaust=True,
        )
        with ldap3.Connection(
            servers,
            read_only=True,
            user=ldapconfig["user"],
            auto_bind=True,
            password=ldapconfig["password"],
            raise_exceptions=True,
            receive_timeout=60,
        ) as conn:
            tools = []
            if not args.admins_only:
                tools = get_tools_from_ldap(conn, args.project)

            admins = get_admins_from_ldap(conn, args.project)

        # If this is just migrating all remaining users (--force-migrate)
        # we should short-circuit the while True loop as soon as possible to
        # reduce all the churn.
        if args.force_migrate:
            for tool_name in cur_users["tools"]:
                tools[tool_name].switch_context()

            break

        if tools:
            new_tools = process_new_users(
                tools, cur_users["tools"], k8s_api, args.gentle_mode
            )
            if expiring_users["tools"]:
                for tool_name in expiring_users["tools"]:
                    tools[tool_name].pk = generate_pk()
                    k8s_api.generate_csr(tools[tool_name].pk, tool_name)
                    tools[tool_name].cert = k8s_api.approve_cert(tool_name)
                    tools[tool_name].create_homedir()
                    tools[tool_name].write_kubeconfig(
                        api_server, ca_data, args.gentle_mode
                    )
                    k8s_api.update_expired_ns(tools[tool_name])
                    logging.info("Renewed creds for tool %s", tool_name)

        if admins:
            new_admins = process_new_users(
                admins, cur_users["admins"], k8s_api, args.gentle_mode
            )
            if expiring_users["admins"]:
                for admin_name in expiring_users["admins"]:
                    admins[admin_name].pk = generate_pk()
                    k8s_api.generate_csr(admins[admin_name].pk, admin_name)
                    admins[admin_name].cert = k8s_api.approve_cert(admin_name)
                    admins[admin_name].create_homedir()
                    admins[admin_name].write_kubeconfig(
                        api_server, ca_data, args.gentle_mode
                    )
                    k8s_api.update_expired_ns(admins[admin_name])
                    logging.info("Renewed creds for admin user %s", admin_name)

        logging.info(
            "finished run, wrote %s new accounts", new_tools + new_admins
        )

        if args.once:
            break

        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
