"""Opt-in object-read guard. The trusted resolver must return one DB snapshot."""
from .guard import Guard, ObjectSnapshot, AuthorizedRepresentation, ReadIdentity, ApplicationSnapshot

__all__ = ["Guard", "ObjectSnapshot", "AuthorizedRepresentation", "ReadIdentity", "ApplicationSnapshot"]
