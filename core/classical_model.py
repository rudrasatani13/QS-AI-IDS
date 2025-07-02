import torch
import torch.nn as nn
import torch.nn.functional as F

class ClassicalAnomalyDetector(nn.Module):

    def __init__(self, input_dim: int = 6):

        super(ClassicalAnomalyDetector, self).__init__()

        self.fc1 = nn.Linear(input_dim, 16)
        self.bn1 = nn.BatchNorm1d(16)
        self.fc2 = nn.Linear(16, 8)
        self.dropout = nn.Dropout(p=0.2)
        self.fc3 = nn.Linear(8, 1)

    def forward(self, x):

        x = F.relu(self.bn1(self.fc1(x)))
        x = self.dropout(x)
        x = F.relu(self.fc2(x))
        x = torch.sigmoid(self.fc3(x))
        return x
