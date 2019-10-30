# import Config file as the very first one (setup logging)
from .config import Config
from .identifier import MultipleRows
duplicate_row = MultipleRows.duplicate_row

__all__ = ["duplicate_row"]