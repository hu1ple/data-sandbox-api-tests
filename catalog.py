"""Register one implementation per Excel case ID."""
from dataclasses import dataclass

SCRIPTS = {}


@dataclass(frozen=True)
class Script:
    execute: object
    layer: str
    writes: bool
    keys: tuple
    remainder: str = ''


def case(identifier, *, layer='契约', writes=False, needs='', remainder=''):
    def register(function):
        if identifier in SCRIPTS:
            raise ValueError(f'Duplicate script {identifier}')
        SCRIPTS[identifier] = Script(function, layer, writes, tuple(needs.split()), remainder)
        return function
    return register
