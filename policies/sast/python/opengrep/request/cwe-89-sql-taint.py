from flask import request

SORT = {"id": "id"}


def by_owner():
    owner = request.args.get("owner", "")
    # ruleid: hoplites.python.cwe-89.dynamic-sql-without-binding.request
    return conn.execute(f"SELECT * FROM t WHERE owner = '{owner}'")


def by_owner_bound():
    owner = request.args.get("owner", "")
    # ok: hoplites.python.cwe-89.dynamic-sql-without-binding.request
    return conn.execute("SELECT * FROM t WHERE owner = ?", (owner,))


def order_by():
    col = SORT.get(request.args.get("sort"))
    # ok: hoplites.python.cwe-89.dynamic-sql-without-binding.request
    return conn.execute("SELECT * FROM t ORDER BY " + col)


def find(term):
    sql = "SELECT * FROM t WHERE name LIKE '%" + term + "%'"
    # ok: hoplites.python.cwe-89.dynamic-sql-without-binding.request
    return conn.execute(sql)


def find_bound(term):
    # ok: hoplites.python.cwe-89.dynamic-sql-without-binding.request
    return conn.execute("SELECT * FROM t WHERE name LIKE ?", (f"%{term}%",))


def schema():
    # ok: hoplites.python.cwe-89.dynamic-sql-without-binding.request
    return conn.execute("SELECT 1")
