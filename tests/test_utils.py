import re
from .context import get_tools_from_ldap, get_admins_from_ldap


def test_tools_search(monkeypatch, ldap_conn):
    def mock_pg_search(*args, **kwargs):
        groups = [
            {
                "attributes": {
                    "cn": ["tools.example"],
                    "uidNumber": 50020,
                    "homeDirectory": "/data/project/example",
                }
            }
        ]
        for group in groups:
            yield group

    monkeypatch.setattr(
        ldap_conn.extend.standard, "paged_search", mock_pg_search
    )
    tools = get_tools_from_ldap(ldap_conn, "tools")
    assert tools["example"].id == 50020
    assert tools["example"].name == "example"
    assert tools["example"].home == "/data/project/example"


def test_admin_search(monkeypatch, ldap_conn):
    def mock_pg_search(*args, **kwargs):
        if re.search(r"objectClass\=posixGroup", args[1]):
            members = [
                "uid=testy,ou=people,dc=wikimedia,dc=org",
                "uid=larry,ou=people,dc=wikimedia,dc=org",
                "uid=curly,ou=people,dc=wikimedia,dc=org",
                "uid=moe,ou=people,dc=wikimedia,dc=org",
                "uid=shemp,ou=people,dc=wikimedia,dc=org",
            ]
            groups = [{"attributes": {"member": (mem for mem in members)}}]
            for group in groups:
                yield group

            return

        # Escaping all those parens in python sucks
        early_str = re.escape("(&(objectClass=posixAccount)(")
        regex_str = early_str + r"([\w=]+).*"
        mem_uid_raw = re.sub(regex_str, r"\1", args[1])
        mem_uid = mem_uid_raw.split("=")[1]
        member = {
            "attributes": {
                "uid": [mem_uid],
                # Generate a predicatable UID from the name :-p
                "uidNumber": sum([ord(y) for y in list(mem_uid)]),
                "homeDirectory": "/home/{}".format(mem_uid),
            }
        }

        yield member

    monkeypatch.setattr(
        ldap_conn.extend.standard, "paged_search", mock_pg_search
    )

    admins = get_admins_from_ldap(ldap_conn, "tools")
    assert admins["shemp"].id == sum([ord(y) for y in list("shemp")])
    assert admins["shemp"].name == "shemp"
    assert admins["shemp"].home == "/home/shemp"
    assert admins["shemp"].admin
