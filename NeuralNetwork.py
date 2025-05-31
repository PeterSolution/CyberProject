import torch
import torch.nn as nn
import torch.optim as optim

class NeuralNetwork(nn.Module):
    def __init__(self):
        super(NeuralNetwork, self).__init__()
        self.fc1 = nn.Linear(1, 30)
        self.fc2 = nn.Linear(30, 1)

    def forward(self, x):  # DODAJ TĘ METODĘ
        x = torch.relu(self.fc1(x))
        x = self.fc2(x)
        return x

    def saveModel(self, model):
        torch.save(model.state_dict(), "model.pth")
        print("Model zapisany do model.pth")

    def LearnModelAmountOfTime(self, model, amount, connections, targetOutput):
        learning = optim.SGD(model.parameters(), lr=0.01)
        middleSqrError = nn.MSELoss()
        for epoch in range(amount):
            learning.zero_grad()
            predictions = model(connections)  # Użyj model() zamiast connections
            loss = middleSqrError(predictions, targetOutput)
            loss.backward()
            learning.step()
        torch.save(model.state_dict(), "model.pth")
        return model

    def LearnModelUntilErrorLess(self, model, lesserror, connections, targetOutput):
        learning = optim.SGD(model.parameters(), lr=0.01)
        middleSqrError = nn.MSELoss()
        loss = lesserror + 1
        while loss > lesserror:
            learning.zero_grad()
            predictions = model(connections)  # Użyj model() zamiast connections
            loss = middleSqrError(predictions, targetOutput)
            loss.backward()
            learning.step()
        torch.save(model.state_dict(), "model.pth")
        return model

    def LoadModel(self):
        model = NeuralNetwork()
        model.load_state_dict(torch.load("model.pth"))
        model.eval()
        return model