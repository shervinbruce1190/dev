# main.py

from typing import Dict, Tuple, List, Optional

class Vault:
    """
    A simple in-memory password vault that stores passwords
    using (service, username) as the unique key.
    """

    def __init__(self) -> None:
        """Initialize an empty credential store."""
        self._store: Dict[Tuple[str, str], str] = {}

    def add(self, service: str, username: str, password: str) -> bool:
        """
        Add a new password entry to the vault.

        :param service: The name of the service (e.g., "gmail")
        :param username: The username for the service
        :param password: The password to store
        :return: True if added, False if entry already exists
        """
        key = (service, username)

        if key in self._store:
            return False

        self._store[key] = password
        return True

    def get(self, service: str, username: str) -> Optional[str]:
        """
        Retrieve the stored password for a given service and username.

        :param service: The name of the service
        :param username: The username
        :return: Password string if found, otherwise None
        """
        return self._store.get((service, username))

    def delete(self, service: str, username: str) -> bool:
        """
        Delete the entry for the given service and username.

        :param service: The service name
        :param username: The username
        :return: True if deleted, False if entry does not exist
        """
        key = (service, username)

        if key in self._store:
            del self._store[key]
            return True

        return False

    def list_entries(self) -> List[Tuple[str, str]]:
        """
        List all stored (service, username) pairs.

        :return: List of tuples containing service and username
        """
        return list(self._store.keys())
