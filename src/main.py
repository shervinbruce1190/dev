# main.py

class Vault:
    """
    A lightweight, high-performance in-memory vault.
    Stores credentials using (service, username) as keys.
    """

    __slots__ = ("_store",)

    def __init__(self) -> None:
        """Initialize an empty vault using a dictionary for O(1) operations."""
        self._store = {}

    def _make_key(self, service: str, username: str):
        """
        Create a normalized tuple key.
        This ensures consistent lookups and reduces ambiguity.
        """
        return (service.strip(), username.strip())

    def add(self, service: str, username: str, password: str) -> bool:
        """
        Add a new password entry.
        Returns False if the entry already exists.
        """
        key = self._make_key(service, username)

        if key in self._store:
            return False

        self._store[key] = password
        return True

    def get(self, service: str, username: str):
        """
        Retrieve a stored password.
        Returns None if not found.
        """
        key = self._make_key(service, username)
        return self._store.get(key)

    def delete(self, service: str, username: str) -> bool:
        """
        Delete an existing entry.
        Returns True if deletion succeeded, False if entry does not exist.
        """
        key = self._make_key(service, username)

        if key in self._store:
            del self._store[key]
            return True

        return False

    def list_entries(self):
        """
        Return a list of all stored (service, username) pairs.
        """
        return list(self._store.keys())
