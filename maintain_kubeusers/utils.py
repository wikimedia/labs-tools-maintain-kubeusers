from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import ldap3
import re

from maintain_kubeusers.user import User


def generate_pk():
    # Simple rsa PK generation
    return rsa.generate_private_key(
        public_exponent=65537, key_size=4096, backend=default_backend()
    )


def scrub_tools(toolset):
    """ tool names must conform to RFC 1123 as a DNS label
    For our purposes, they must also be no more than 54 characters in length.
    In some cases, dots are allowed, but it shouldn't be in the tool name.
    """
    dns_regex = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
    return set([x for x in toolset if dns_regex.match(x) and len(x) < 54])


def get_tools_from_ldap(conn, projectname):
    """
    Builds list of all tools from LDAP
    """
    tools = {}
    entries = conn.extend.standard.paged_search(
        "ou=people,ou=servicegroups,dc=wikimedia,dc=org",
        "(&(objectClass=posixAccount)(cn={}.*))".format(projectname),
        search_scope=ldap3.SUBTREE,
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
        )
        tools[tool.name] = tool

    return tools
