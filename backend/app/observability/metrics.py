"""
Application metrics service — thread-safe in-memory counters.

Tracks scan counts, durations, AI analysis times, and per-scanner performance.
Designed as a singleton for use across the application.
"""
import threading
from typing import Dict, List


class MetricsService:
    """
    Thread-safe in-memory metrics collector.

    Tracks:
        - Total / successful / failed scans
        - Scan durations (for averaging)
        - AI analysis durations (for averaging)
        - Per-scanner durations
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._data_lock = threading.Lock()
        self.total_scans: int = 0
        self.successful_scans: int = 0
        self.failed_scans: int = 0
        self.scan_durations: List[float] = []
        self.ai_analysis_durations: List[float] = []
        self.scanner_durations: Dict[str, List[float]] = {}
        self._initialized = True

    def record_scan(self, duration_ms: float, success: bool) -> None:
        """Record a completed scan with its duration and outcome."""
        with self._data_lock:
            self.total_scans += 1
            self.scan_durations.append(duration_ms)
            if success:
                self.successful_scans += 1
            else:
                self.failed_scans += 1

    def record_ai_analysis(self, duration_ms: float) -> None:
        """Record an AI analysis duration."""
        with self._data_lock:
            self.ai_analysis_durations.append(duration_ms)

    def record_scanner(self, scanner_name: str, duration_ms: float) -> None:
        """Record a single scanner's execution duration."""
        with self._data_lock:
            if scanner_name not in self.scanner_durations:
                self.scanner_durations[scanner_name] = []
            self.scanner_durations[scanner_name].append(duration_ms)

    def get_summary(self) -> dict:
        """
        Return a summary of all collected metrics.

        Returns:
            {
                "total_scans": int,
                "successful_scans": int,
                "failed_scans": int,
                "avg_scan_time_ms": float,
                "avg_ai_analysis_time_ms": float,
            }
        """
        with self._data_lock:
            avg_scan = (
                sum(self.scan_durations) / len(self.scan_durations)
                if self.scan_durations else 0.0
            )
            avg_ai = (
                sum(self.ai_analysis_durations) / len(self.ai_analysis_durations)
                if self.ai_analysis_durations else 0.0
            )
            return {
                "total_scans": self.total_scans,
                "successful_scans": self.successful_scans,
                "failed_scans": self.failed_scans,
                "avg_scan_time_ms": round(avg_scan, 2),
                "avg_ai_analysis_time_ms": round(avg_ai, 2),
            }

    def reset(self) -> None:
        """Reset all metrics. Intended for testing."""
        with self._data_lock:
            self.total_scans = 0
            self.successful_scans = 0
            self.failed_scans = 0
            self.scan_durations.clear()
            self.ai_analysis_durations.clear()
            self.scanner_durations.clear()
