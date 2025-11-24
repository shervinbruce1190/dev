import os
import sqlite3
import pytest
from vault import (
    db, derive, get_salt, verify,
    add_entry, get_entry,
    list_entries, delete_entry
)
from cryptography.fernet import Fernet

TEST_DB = "test_vault.db"


@pytest.fixture()
def conn():
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    c = db(TEST_DB)
    yield c
    c.close()
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)


def test_salt_creation(conn):
    salt1 = get_salt(conn)
    salt2 = get_salt(conn)
    assert salt1 == salt2


def test_key_derivation():
    key1 = derive("password", b"1234567890123456")
    key2 = derive("password", b"1234567890123456")
    assert key1 == key2


def test_verifier(conn):
    key = derive("master", get_salt(conn))
    f = Fernet(key)
    assert verify(conn, f)      # creates verifier
    assert verify(conn, f)      # validates existing verifier


def test_add_and_get(conn):
    key = derive("master", get_salt(conn))
    f = Fernet(key)

    ok = add_entry(conn, f, "gmail", "user", "pass", "note")
    assert ok

    pwd, note = get_entry(conn, f, "gmail", "user")
    assert pwd == "pass"
    assert note == "note"


def test_prevent_duplicate(conn):
    key = derive("master", get_salt(conn))
    f = Fernet(key)

    assert add_entry(conn, f, "s", "u", "p")
    assert not add_entry(conn, f, "s", "u", "p")  # duplicate


def test_list_entries(conn):
    key = derive("master", get_salt(conn))
    f = Fernet(key)

    add_entry(conn, f, "a", "u1", "p")
    add_entry(conn, f, "b", "u2", "p")

    rows = list_entries(conn)
    assert len(rows) == 2
    assert rows[0][0] == "a"


def test_delete(conn):
    key = derive("master", get_salt(conn))
    f = Fernet(key)

    add_entry(conn, f, "x", "y", "p")
    assert delete_entry(conn, "x", "y")
    assert not delete_entry(conn, "x", "y")  # already gone

    assert get_entry(conn, f, "x", "y") is None
