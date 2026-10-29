"""Rule-based order-id extractor.

Finds order references such as ``#7110``, ``order 7110`` or ``order no. 7110``
and returns their ids in order of first appearance, deduplicated. Safety does
not depend on this code: the kernel labels its output as untrusted as its
input, validates types and caps the list, whatever it returns.
"""

import re

_ORDER_REF = re.compile(r"(?:#\s*|\border\s+(?:no\.?\s*|number\s*)?#?\s*)(\d{3,9})\b", re.I)


def extract_order_ids(text: str) -> list[object]:
    seen: list[object] = []
    for match in _ORDER_REF.finditer(text):
        value = int(match.group(1))
        if value not in seen:
            seen.append(value)
    return seen
