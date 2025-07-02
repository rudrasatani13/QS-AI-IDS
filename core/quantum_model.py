import pennylane as qml
from pennylane import numpy as np
import torch
from torch.nn import Module
from typing import List


class QuantumAnomalyDetector(Module):

    def __init__(self, n_qubits: int = 6, n_layers: int = 2):

        super().__init__()
        self.n_qubits = n_qubits
        self.n_layers = n_layers

        # Device: Use lightning.qubit for fast simulation on M2
        self.dev = qml.device("lightning.qubit", wires=n_qubits)

        # Define QNode with autograd interface (for PyTorch)
        self.qnode = qml.QNode(self._circuit, self.dev, interface="torch", diff_method="adjoint")

        # Initialize trainable weights
        weight_shapes = {"weights": (n_layers, n_qubits, 3)}
        self.qlayer = qml.qnn.TorchLayer(self.qnode, weight_shapes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:

        x = torch.stack([self.qlayer(xi) for xi in x])
        return x.view(-1, 1)

    def _circuit(self, inputs: torch.Tensor, weights: torch.Tensor) -> torch.Tensor:

        # Angle encoding of input features
        for i in range(self.n_qubits):
            qml.RY(inputs[i], wires=i)

        # Variational layers
        for layer in range(self.n_layers):
            for i in range(self.n_qubits):
                qml.RX(weights[layer][i][0], wires=i)
                qml.RY(weights[layer][i][1], wires=i)
                qml.RZ(weights[layer][i][2], wires=i)
            self._entangle_all()

        return qml.expval(qml.PauliZ(0))

    def _entangle_all(self):
        """
        Apply ring entanglement between all qubits.
        """
        for i in range(self.n_qubits):
            qml.CNOT(wires=[i, (i + 1) % self.n_qubits])
