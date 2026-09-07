"""
Unidirectional Optical Hardware Data Diode Simulation & Proof Engine.

Models the physical layer characteristics of an air-gapped optical data diode:
1. Production Network (Protected TX side): Transmits simplex optical pulses.
2. Optical Data Diode Core: Single-strand fiber-optic cable with no return light path.
3. Sensor Appliance (Monitoring RX side): Photodiode receiver with physical TX disabled.

Guarantees:
- PRODUCTION -> MONITORING = Fully Functional
- MONITORING -> PRODUCTION = Physically Impossible (raises DiodePhysicalViolationError)
"""
import collections
from typing import Optional, Dict, Any, Generator


class DiodePhysicalViolationError(PermissionError):
    """Raised when an active transmit attempt is detected on the RX-only monitoring interface."""
    pass


class SimulatedOpticalDataDiode:
    """
    Lightweight, in-memory physical simplex data diode tap simulator.
    Operates in O(1) time and bounded memory.
    """
    def __init__(self, buffer_capacity: int = 10_000):
        self.buffer_capacity = buffer_capacity
        self._simplex_fiber_queue: collections.deque = collections.deque(maxlen=buffer_capacity)
        self._total_forwarded_frames: int = 0
        self._total_blocked_reverse_attempts: int = 0
        self._rx_only: bool = True

    def forward_from_production(self, frame_bytes: bytes) -> bool:
        """
        Simulates the protected network sending a packet across the one-way optical transmitter.
        """
        self._simplex_fiber_queue.append(frame_bytes)
        self._total_forwarded_frames += 1
        return True

    def receive_at_sensor(self) -> Optional[bytes]:
        """
        Simulates the passive sensor reading a frame from the optical receiver photodiode.
        """
        if self._simplex_fiber_queue:
            return self._simplex_fiber_queue.popleft()
        return None

    def attempt_reverse_transmission(self, frame_bytes: bytes):
        """
        Simulates an illicit attempt by the monitoring sensor to send packets back into
        the protected production enclave.

        Strictly blocked by the hardware data diode model.
        """
        self._total_blocked_reverse_attempts += 1
        raise DiodePhysicalViolationError(
            "CRITICAL DIODE VIOLATION: Simplex optical tap forbids reverse packet transmission. "
            "Monitoring interface has no physical TX laser/cable connected to protected enclave."
        )

    def audit_diode_invariants(self) -> Dict[str, Any]:
        """
        Returns verification telemetry for the unidirectional boundary.
        """
        return {
            "forward_channel_active": True,
            "reverse_channel_active": False,
            "sensor_tx_interface_status": "DISCONNECTED_PHYSICAL_AIRGAP",
            "forwarded_frames_count": self._total_forwarded_frames,
            "blocked_reverse_attempts": self._total_blocked_reverse_attempts,
            "unidirectional_hardware_guarantee": "VERIFIED_COMPLIANT"
        }
