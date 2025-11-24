class Vault:
    """
    A simple in-memory password manager that securely stores credentials
    using (service, username) as a unique key.
    NOTE: This version uses NO external modules as requested.
    """

    def __init__(self):
        # Internal store for credentials
        self._store = {}

    def _validate(self, service, username, password=None):
        """
        Validate inputs to avoid unexpected or unsafe values.
        """
        if not isinstance(service, str) or not service.strip():
            return False

        if not isinstance(username, str) or not username.strip():
            return False

        if password is not None:
            if not isinstance(password, str) or not password.strip():
                return False

        return True

    def add(self, service, username, password):
        """
        Add a new credential.

        Returns:
            True  -> added successfully
            False -> invalid input OR already exists
        """
        if not self._validate(service, username, password):
            return False

        key = (service, username)

        if key in self._store:
            return False

        # Store password (plain text since no modules)
        self._store[key] = password
        return True

    def get(self, service, username):
        """
        Retrieve a password.

        Returns:
            password string -> if found
            None            -> if not found OR invalid input
        """
        if not self._validate(service, username, ""):
            return None

        return self._store.get((service, username))

    def delete(self, service, username):
        """
        Delete a stored credential.

        Returns:
            True  -> deleted
            False -> invalid input OR not found
        """
        if not self._validate(service, username, ""):
            return False

        key = (service, username)

        if key in self._store:
            del self._store[key]
            return True

        return False

    def list_entries(self):
        """
        List all stored (service, username) pairs.

        Always safe and returns a new list.
        """
        return list(self._store.keys())
