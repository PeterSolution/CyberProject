import torch
import torch.nn as nn
import torch.optim as optim

# Dane treningowe: wejście i oczekiwane wyjście
inputs = torch.tensor([[0.0], [1.0]], dtype=torch.float32)
targets = torch.tensor([[0.0], [1.0]], dtype=torch.float32)

# Prosta sieć neuronowa: 1 neuron ukryty i 1 wyjściowy
class SimpleNet(nn.Module):
    def __init__(self):
        super(SimpleNet, self).__init__()
        self.model = nn.Sequential(
            nn.Linear(1, 5),
            nn.ReLU(),
            nn.Linear(5, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.model(x)
