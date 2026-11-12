"""Structured logging for the relay: one event name plus key=value fields per line.

    slog(log, "c64_hello", side="c64 192.0.2.7:4096 n=1a2b")

renders as ``c64_hello side="c64 192.0.2.7:4096 n=1a2b"`` with the text formatter, or
as one JSON object per line with ``JsonFormatter`` (--log-format json).
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any


def slog(logger: logging.Logger, event: str, level: int = logging.INFO, **fields: Any) -> None:
    if logger.isEnabledFor(level):
        logger.log(level, event, extra={"relay_fields": fields})


def _fmt_value(v: Any) -> str:
    s = str(v)
    if not s or any(c in s for c in ' ="'):
        return json.dumps(s)
    return s


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        fields = getattr(record, "relay_fields", {}) or {}
        ts = time.strftime("%H:%M:%S", time.localtime(record.created))
        parts = [f"{ts}.{int(record.msecs):03d}", record.levelname.lower(), record.name,
                 record.getMessage()]
        parts += [f"{k}={_fmt_value(v)}" for k, v in fields.items()]
        line = " ".join(parts)
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        obj = {"ts": round(record.created, 6), "level": record.levelname.lower(),
               "logger": record.name, "event": record.getMessage()}
        for k, v in (getattr(record, "relay_fields", {}) or {}).items():
            obj[k] = v if isinstance(v, (int, float, bool, type(None))) else str(v)
        if record.exc_info:
            obj["exc"] = self.formatException(record.exc_info)
        return json.dumps(obj, separators=(",", ":"))
