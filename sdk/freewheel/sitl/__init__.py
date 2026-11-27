"""Minimal software-in-the-loop peer for the offline tests.

This is the test double the offline suites drive: a virtual robot speaking UCP,
zenoh-over-UCP, `/cmd` request/response, telemetry and the `md_upgrade` OTA
surface on loopback. It is a deliberately *small* slice of the research
repository's simulator — just the responder the tests need, with no web console,
no HTTP server and no browser assets.
"""
from .responder import SimResponder, synthetic_telemetry

__all__ = ["SimResponder", "synthetic_telemetry"]
