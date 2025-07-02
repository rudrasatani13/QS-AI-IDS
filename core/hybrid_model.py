import torch
import psutil
import torch.nn as nn
from core.classical_model import ClassicalAnomalyDetector
from core.quantum_model import QuantumAnomalyDetector

class HybridAnomalyDetector(nn.Module):
    def __init__(self, input_dim: int = 6, quantum_enabled: bool = True):
        super().__init__()
        self.input_dim = input_dim
        self.quantum_model = QuantumAnomalyDetector(n_qubits=input_dim)
        self.classical_model = ClassicalAnomalyDetector(input_dim=input_dim)
        self.use_quantum = quantum_enabled and self._quantum_viable()

    def predict(self, features: torch.Tensor) -> torch.Tensor:
        if self.use_quantum:
            try:
                # Quantum expects input already angle-encoded (π * x)
                return 0.5 * (1 - self.quantum_model(features))  # convert from ⟨Z⟩ to [0,1]
            except Exception as e:
                print(f"[HYBRID FALLBACK] Quantum failed: {e}")
                self.use_quantum = False  # switch off quantum until reboot
        # Classical model expects standard normalized input
        return self.classical_model(features)

    def _quantum_viable(self) -> bool:
        battery = psutil.sensors_battery()
        cpu_load = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        # Conditions for running quantum model:
        return (
            (battery is None or battery.power_plugged or battery.percent > 40) and
            cpu_load < 70.0 and
            mem.available > 512 * 1024 * 1024  # at least 512MB RAM free
        )