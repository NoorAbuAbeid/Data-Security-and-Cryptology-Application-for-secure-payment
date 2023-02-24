from abc import ABC, abstractmethod


class Signature(ABC):
    """
    Represents a signature generated by a signer.
    """

    @abstractmethod
    def pack(self) -> bytes:
        pass


class Signer(ABC):
    """
    Represents a signer, capable of signing on data and generating
    a signature which identifies the data.
    """

    @abstractmethod
    def sign(self, data: str) -> Signature:
        pass


class Verifier(ABC):
    """
    Represents a verifier, which can verify signature on data, ensuring
    the data originated from a trusted source and wasn't modified.
    """

    @abstractmethod
    def verify(self, data: str, signature: Signature) -> bool:
        pass