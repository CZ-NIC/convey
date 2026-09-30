"""
Safe (de)serialization for convey's on-disk caches.

Background: convey restores caches with jsonpickle, which can instantiate arbitrary objects - and
thus run code - when the cache file is attacker-controlled (CWE-502; the `py/reduce` -> `os.system`
gadget). jsonpickle's `safe=True` only disables `eval()`, not that gadget, so it is not enough.

We treat the two caches differently:

* The **whois cache** is large and made of plain data (IP ranges + string tuples). We serialize it
  with the C-accelerated stdlib `json` instead of jsonpickle: it is several times faster and safe by
  construction - loading only ever rebuilds IPRange/IPNetwork from validated ints/strings, never an
  arbitrary class.

* The **parser cache** is a small but tangled object graph (cyclic Field<->Parser references, Type
  keys, merge objects, shared references). Re-implementing that faithfully would mean re-doing
  jsonpickle's reference tracking, so it stays on jsonpickle - but `assert_safe_jsonpickle()` guards
  its load by rejecting any blob that references a class/callable outside convey's own data classes.
"""

import json

from netaddr import IPRange, IPNetwork

from .aggregate import Aggregate

WHOIS_CACHE_VERSION = 1


# --- whois cache: fast, safe JSON ------------------------------------------------------------------


def _whois_default(o):
    if isinstance(o, IPRange):
        return {"!ipr": [o.first, o.last]}
    if isinstance(o, IPNetwork):
        return {"!ipn": str(o)}
    # Loud failure (not silent drop): if a new value type ever enters the whois cache, a test or the
    # first real run surfaces it immediately instead of corrupting the cache.
    raise TypeError(f"whois cache cannot serialize {type(o).__name__}: {o!r}")


def _whois_hook(d):
    r = d.get("!ipr")
    if r is not None:
        return IPRange(r[0], r[1])
    n = d.get("!ipn")
    if n is not None:
        return IPNetwork(n)
    return d


def whois_dumps(ip_seen, ranges) -> str:
    """Serialize the whois cache. ip_seen: {ip_str: IPRange}; ranges: {IPRange: value_tuple}."""
    return json.dumps(
        {
            "v": WHOIS_CACHE_VERSION,
            "ip_seen": ip_seen,
            # IPRange is not a valid JSON key, so ranges becomes a list of [first, last, value]
            "ranges": [[k.first, k.last, v] for k, v in ranges.items()],
        },
        default=_whois_default,
        separators=(",", ":"),
    )


def whois_loads(text):
    """Inverse of whois_dumps. Returns (ip_seen, ranges); raises on a foreign/garbled/legacy blob."""
    payload = json.loads(text, object_hook=_whois_hook)
    if not isinstance(payload, dict) or payload.get("v") != WHOIS_CACHE_VERSION:
        raise ValueError("unrecognised whois cache format")
    ip_seen = payload["ip_seen"]
    # json restores the value tuples as lists; the whois code hashes them (frozenset), so re-tuple.
    ranges = {IPRange(f, l): tuple(v) for f, l, v in payload["ranges"]}
    return ip_seen, ranges


# --- parser cache: jsonpickle, but validated before decoding ---------------------------------------

# Every class/callable that legitimately appears in a convey parser cache. jsonpickle can only
# instantiate or call something it names via py/object / py/type / py/function, so restricting those
# names to this set makes the `py/reduce` -> os.system gadget unreachable.
_ALLOWED = frozenset(
    {
        "convey.parser.Parser",
        "convey.parser.SendingSettings",
        "convey.field.Field",
        "convey.types.Type",
        "convey.attachment.Attachment",
        "convey.action.MergeAction",
        "convey.action.AggregateAction",
        "convey.aggregate.Aggregate",
        *(f"convey.aggregate.Aggregate.{fn.__name__}" for fn in Aggregate.all()),
        "collections.defaultdict",
        "collections.OrderedDict",
        "datetime.datetime",
        "datetime.date",
        "datetime.time",
        "datetime.timedelta",
        "pathlib.Path",
        "pathlib.PosixPath",
        "pathlib.WindowsPath",
        "pathlib.PurePosixPath",
        "pathlib.PureWindowsPath",
        "netaddr.ip.IPRange",
        "netaddr.ip.IPNetwork",
        "netaddr.ip.IPAddress",
        "jsonpickle.handlers.CloneFactory",
        "builtins.int",
        "builtins.float",
        "builtins.complex",
        "builtins.bool",
        "builtins.str",
        "builtins.bytes",
        "builtins.bytearray",
        "builtins.list",
        "builtins.tuple",
        "builtins.dict",
        "builtins.set",
        "builtins.frozenset",
    }
)


class UnsafeCache(Exception):
    """Raised when a cache file references something outside the convey data-class allow-list."""


def assert_safe_jsonpickle(text: str) -> None:
    """Reject a jsonpickle blob that could instantiate or call anything outside convey's own data
    classes. Run this before jsonpickle.decode() to neutralise the py/reduce -> os.system gadget.
    """
    parsed = json.loads(text)  # plain JSON parse runs no code

    def walk(node):
        if isinstance(node, dict):
            if "py/repr" in node:  # py/repr is eval()'d by jsonpickle
                raise UnsafeCache("py/repr")
            for tag in ("py/object", "py/type", "py/function"):
                ref = node.get(tag)
                if isinstance(ref, str) and ref not in _ALLOWED:
                    raise UnsafeCache(f"{tag}: {ref}")
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(parsed)
