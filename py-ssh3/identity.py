from abc import ABC, abstractmethod

class Identity(ABC):
    @abstractmethod
    def set_authorization_header(self, request, username: str, conversation):
        pass

    @abstractmethod
    def auth_hint(self) -> str:
        pass

    @abstractmethod
    def __str__(self):
        pass
