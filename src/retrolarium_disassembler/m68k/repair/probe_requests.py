"""Bounded decoder hypotheses, deliberately separate from trusted roots."""

from bisect import bisect_right
from dataclasses import dataclass


@dataclass(frozen=True)
class M68kProbeRequest:
    address: int
    end: int
    source_address: int | None
    reason: str
    stage: str = "hypothesis"
    confidence: str = "untrusted"


class M68kProbeRequests:
    """An image-scoped monotone plan; requesting bytes never marks code.

    A bounded number of requests may cause an extra backend pass. Repeated,
    invalid and budget-deferred requests cannot keep the loop alive forever.
    Deferred work is reported separately from code fixed-point convergence.
    """

    def __init__(self, image, *, max_requests=4096, max_bytes=2048, minimum_address=None):
        if not 1 <= max_requests <= 4096 or not 2 <= max_bytes <= 2048:
            raise ValueError("invalid M68K probe budget")
        self.image = image
        self.minimum_address = image.header.rom_start + 0x200 if minimum_address is None else minimum_address
        if self.minimum_address < image.header.rom_start:
            raise ValueError("M68K probe lower bound precedes image")
        self.max_requests, self.max_bytes = max_requests, max_bytes
        self.requests: dict[int, M68kProbeRequest] = {}
        self.deferred: set[int] = set()
        self.known, self.starts = {}, []

    def update_known(self, facts):
        self.known = {fact.cpu_address: fact for fact in facts.values()}
        self.starts = sorted(self.known)
        self.deferred.difference_update(self.known)

    def request(self, address, source_address=None, reason="structural handler decode"):
        origin = self.image.header.rom_start
        if (
            not isinstance(address, int)
            or address & 1
            or not self.minimum_address <= address < origin + len(self.image.data) - 1
            or address in self.known
            or address in self.requests
        ):
            return False
        index = bisect_right(self.starts, address)
        previous = self.known[self.starts[index - 1]] if index else None
        if previous is not None and address < previous.cpu_address + previous.length:
            return False
        if len(self.requests) >= self.max_requests:
            self.deferred.add(address)
            return False
        end = min(
            address + self.max_bytes,
            origin + len(self.image.data),
            self.starts[index] if index < len(self.starts) else origin + len(self.image.data),
        )
        self.requests[address] = M68kProbeRequest(address, end, source_address, reason)
        self.deferred.discard(address)
        return True

    def plan_text(self):
        return "".join(f"{r.address:06X}\t{r.end:06X}\n" for _, r in sorted(self.requests.items()))
