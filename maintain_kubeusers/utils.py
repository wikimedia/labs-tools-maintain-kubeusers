from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import ldap3

import re
import logging
import os
import pathlib
from typing import Dict, Set, List

from maintain_kubeusers.user import User
from maintain_kubeusers.k8s_api import K8sAPI

UserDict = Dict[str, User]


def generate_pk() -> rsa.RSAPrivateKey:
    # Simple rsa PK generation
    return rsa.generate_private_key(
        public_exponent=65537, key_size=4096, backend=default_backend()
    )


def scrub_tools(toolset: Set[str]) -> Set[str]:
    """tool names must conform to RFC 1123 as a DNS label
    For our purposes, they must also be no more than 54 characters in length.
    In some cases, dots are allowed, but it shouldn't be in the tool name.
    """
    dns_regex = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
    return set([x for x in toolset if dns_regex.match(x) and len(x) < 54])


TOOL_HOME_DIR = "/data/project/"
DISABLED_K8S_FILE = "k8s.disabled"


def process_new_users(
    user_list: UserDict, current_users: List[str], k8s_api: K8sAPI, gentle: bool
) -> int:
    api_server, ca_data = k8s_api.get_cluster_info()
    raw_new_users = set([tool.name for tool in user_list.values()]) - set(
        current_users
    )
    new_users = scrub_tools(raw_new_users)
    new_user_count = 0
    if new_users:
        for user_name in new_users:
            if not user_list[user_name].is_disabled():
                new_user_count += 1
                user_list[user_name].pk = generate_pk()
                k8s_api.generate_csr(user_list[user_name].pk, user_name)
                user_list[user_name].cert = k8s_api.approve_cert(user_name)
                user_list[user_name].create_homedir()
                user_list[user_name].write_kubeconfig(
                    api_server, ca_data, gentle
                )
                k8s_api.add_user_access(user_list[user_name])
                logging.info("Provisioned creds for user %s", user_name)

                disabled_flag = os.path.join(
                    TOOL_HOME_DIR, user_name, DISABLED_K8S_FILE
                )
                if os.path.exists(disabled_flag):
                    os.remove(disabled_flag)

    return new_user_count


def process_disabled_users(
    user_list: UserDict, current_users: List[str], k8s_api: K8sAPI
) -> int:
    disabled_users = [
        tool.name for tool in user_list.values() if tool.is_disabled()
    ]

    # Don't disable users that aren't in current_users.
    #  The & here is 'intersection'
    raw_users_to_disable = set(disabled_users) & set(current_users)

    users_to_disable = scrub_tools(raw_users_to_disable)

    for user in users_to_disable:
        k8s_api.disable_user_access(user)

        disabled_flag = os.path.join(TOOL_HOME_DIR, user, DISABLED_K8S_FILE)
        pathlib.Path(disabled_flag).touch()

    return len(users_to_disable)


def get_tools_from_ldap(conn: ldap3.Connection, projectname: str) -> UserDict:
    """
    Builds list of all tools from LDAP
    """
    tools = {}
    entries = conn.extend.standard.paged_search(
        "ou=people,ou=servicegroups,dc=wikimedia,dc=org",
        "(&(objectClass=posixAccount)(cn={}.*))".format(projectname),
        search_scope=ldap3.SUBTREE,
        get_operational_attributes=True,
        attributes=["cn", "uidNumber", "homeDirectory"],
        time_limit=5,
        paged_size=500,
    )
    for entry in entries:
        attrs = entry["attributes"]
        tool = User(
            attrs["cn"][0][len(projectname) + 1 :],
            attrs["uidNumber"],
            attrs["homeDirectory"],
            project=projectname,
            pwdAccountLockedTime=attrs.get("pwdAccountLockedTime", None),
            pwdPolicySubentry=attrs.get("pwdPolicySubentry", None),
        )
        tools[tool.name] = tool

    return tools


def get_admins_from_ldap(conn: ldap3.Connection, projectname: str) -> UserDict:
    """
    Returns a list of project admins
    """
    admins = {}
    entries = conn.extend.standard.paged_search(
        "ou=servicegroups,dc=wikimedia,dc=org",
        "(&(objectClass=posixGroup)(cn={}.admin))".format(projectname),
        search_scope=ldap3.SUBTREE,
        get_operational_attributes=True,
        attributes=["member"],
        time_limit=5,
        paged_size=500,
    )
    for entry in entries:
        for member in entry["attributes"]["member"]:
            uid = member.split(",")[0]
            admin_gen = conn.extend.standard.paged_search(
                "ou=people,dc=wikimedia,dc=org",
                "(&(objectClass=posixAccount)({}))".format(uid),
                search_scope=ldap3.SUBTREE,
                attributes=["uid", "uidNumber", "homeDirectory"],
                time_limit=5,
                paged_size=500,
            )
            attrs = next(admin_gen)["attributes"]
            admin = User(
                attrs["uid"][0],
                attrs["uidNumber"],
                attrs["homeDirectory"],
                attrs.get("pwdAccountLockedTime", None),
                attrs.get("pwdPolicySubentry", None),
                True,
                project=projectname,
            )
            admins[admin.name] = admin

    return admins
