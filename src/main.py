#main.py

class Vault:
    def __init__(self):
        self.store = {}

    def add(self, service: str, username: str, password: str):
        key = (service, username)
        if key in self.store:
            return False
        self.store[key] = password
        return True

    def get(self, service: str, username: str):
        return self.store.get((service, username))

    def delete(self, service: str, username: str):
        key = (service, username)
        if key in self.store:
            del self.store[key]
            return True
        return False

    def list_entries(self):
        return list(self.store.keys())
