import argparse
import logging
from pathlib import Path
import sys
import time

import ldap3
import yaml
from kubernetes import config as k_config
from prometheus_client import start_http_server, Counter, Summary, Gauge

from maintain_kubeusers.k8s_api import K8sAPI
from maintain_kubeusers.utils import (
    generate_pk,
    get_tools_from_ldap,
    get_admins_from_ldap,
    process_new_users,
    process_disabled_users,
    process_removed_users,
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


run_time = Summary(
    "maintain_kubeusers_run_seconds", "Time spent on maintain-kubeusers runs"
)
run_finished = Gauge(
    "maintain_kubeusers_run_finished",
    "Timestamp when the last maintain-kubeusers run finished",
)
accounts_created = Counter(
    "maintain_kubeusers_accounts_created",
    "Number of new accounts created",
    ["account_type"],
)
accounts_renewed = Counter(
    "maintain_kubeusers_accounts_renewed",
    "Number of new accounts whose certificates were renewed",
    ["account_type"],
)
accounts_disabled = Counter(
    "maintain_kubeusers_accounts_disabled",
    "Number of new accounts whose access was disabled pending deletion",
    ["account_type"],
)
accounts_removed = Counter(
    "maintain_kubeusers_accounts_removed",
    "Number of new accounts completely removed",
    ["account_type"],
)


@run_time.time()
def do_run(k8s_api, ldap_config, ldap_servers, project, api_server, ca_data):
    cur_users, expiring_users = k8s_api.get_current_users()
    with ldap3.Connection(
        ldap_servers,
        read_only=True,
        user=ldap_config["user"],
        auto_bind=True,
        password=ldap_config["password"],
        raise_exceptions=True,
        receive_timeout=60,
    ) as conn:
        tools = get_tools_from_ldap(conn, project)
        admins = get_admins_from_ldap(conn, project)

    # Initialize these to zero in cases where something is missing.
    new_tools = 0
    new_admins = 0

    removed_tools = process_removed_users(tools, cur_users["tools"], k8s_api)
    accounts_removed.labels(account_type="tool").inc(removed_tools)

    removed_admins = process_removed_users(
        admins, cur_users["admins"], k8s_api, admins=True
    )
    accounts_removed.labels(account_type="admin").inc(removed_admins)

    if tools:
        new_tools = process_new_users(
            tools,
            cur_users["tools"],
            k8s_api,
            admin=False,
        )
        accounts_created.labels(account_type="tool").inc(new_tools)

        if expiring_users["tools"]:
            for tool_name in expiring_users["tools"]:
                tools[tool_name].pk = generate_pk()
                k8s_api.generate_csr(tools[tool_name].pk, tool_name)
                tools[tool_name].cert = k8s_api.approve_cert(tool_name)
                tools[tool_name].create_homedir()
                tools[tool_name].write_kubeconfig(api_server, ca_data)
                k8s_api.update_expired_ns(tools[tool_name])
                logging.info("Renewed creds for tool %s", tool_name)
                accounts_renewed.labels(account_type="tool").inc()

    if admins:
        new_admins = process_new_users(
            admins,
            cur_users["admins"],
            k8s_api,
            admin=True,
        )
        accounts_created.labels(account_type="admin").inc(new_admins)

        if expiring_users["admins"]:
            for admin_name in expiring_users["admins"]:
                admins[admin_name].pk = generate_pk()
                k8s_api.generate_csr(
                    admins[admin_name].pk, admin_name, admin=True
                )
                admins[admin_name].cert = k8s_api.approve_cert(
                    admin_name, admin=True
                )
                admins[admin_name].create_homedir()
                admins[admin_name].write_kubeconfig(api_server, ca_data)
                k8s_api.update_expired_ns(admins[admin_name])
                logging.info("Renewed creds for admin user %s", admin_name)
                accounts_renewed.labels(account_type="admin").inc()

    disabled_tools = process_disabled_users(tools, cur_users["tools"], k8s_api)
    accounts_disabled.labels(account_type="tool").inc(disabled_tools)

    logging.info(
        "finished run, wrote %s new accounts, disabled %s accounts, "
        "cleaned up %s accounts",
        new_tools + new_admins,
        disabled_tools,
        removed_tools + removed_admins,
    )


def main():
    argparser = argparse.ArgumentParser()
    group1 = argparser.add_mutually_exclusive_group()
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
    group1.add_argument(
        "--interval", help="Seconds between between runs", default=60
    )
    group1.add_argument("--once", help="Run once and exit", action="store_true")
    argparser.add_argument(
        "--local",
        help="Specifies this is not running in Kubernetes (for debugging)",
        action="store_true",
    )

    args = argparser.parse_args()

    loglvl = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(format="%(message)s", level=loglvl)

    with open(args.ldapconfig, encoding="utf-8") as f:
        ldap_config = yaml.safe_load(f)

    ldap_servers = ldap3.ServerPool(
        [ldap3.Server(s, connect_timeout=1) for s in ldap_config["servers"]],
        ldap3.ROUND_ROBIN,
        active=True,
        exhaust=True,
    )

    if args.local:
        k_config.load_kube_config()
    else:
        k_config.load_incluster_config()

    k8s_api = K8sAPI()
    api_server, ca_data = k8s_api.get_cluster_info()

    start_http_server(9000)

    while True:
        logging.info("starting a run")
        # Touch a temp file for a Kubernetes liveness check to prevent hangs
        Path("/tmp/run.check").touch()

        do_run(
            k8s_api=k8s_api,
            ldap_servers=ldap_servers,
            ldap_config=ldap_config,
            project=args.project,
            api_server=api_server,
            ca_data=ca_data,
        )

        run_finished.set_to_current_time()

        if args.once:
            break

        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
