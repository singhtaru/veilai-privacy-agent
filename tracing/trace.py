import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime

# Stage statuses
PASSED = "PASSED"       # stage ran, nothing changed
MODIFIED = "MODIFIED"   # stage changed the data (masked, minimized, redacted)
BLOCKED = "BLOCKED"     # stage stopped the request
INFO = "INFO"           # informational step
VALID_STATUSES = {PASSED, MODIFIED, BLOCKED, INFO}


@dataclass
class Trace:
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    started_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    stages: list = field(default_factory=list)

    tool_requested: str | None = None
    target_reg_no: str | None = None
    permission_status: str = "NOT_REQUIRED"   # NOT_REQUIRED, GRANTED, DENIED
    llm_calls: int = 0
    output_filtered: bool = False
    pii_summary: dict = field(default_factory=dict)   # e.g. {"PERSON": 1, "VIT_REG_NO": 1}
    result: str = "SUCCESS"                           # SUCCESS, DENIED, ERROR
    duration_ms: int | None = None

    _start: float = field(default_factory=time.perf_counter, repr=False)

    def add(self, stage, status, details=None):
        if status not in VALID_STATUSES:
            raise ValueError(f"Unknown stage status '{status}'")
        self.stages.append({"stage": stage, "status": status, "details": details or {}})

    def finish(self, result=None):
        if result:
            self.result = result
        self.duration_ms = int((time.perf_counter() - self._start) * 1000)

    @property
    def llm_called(self):
        return self.llm_calls > 0

    @property
    def pii_types(self):
        return sorted(self.pii_summary)

    @property
    def pii_count(self):
        return sum(self.pii_summary.values())

    @property
    def masked(self):
        return self.pii_count > 0
