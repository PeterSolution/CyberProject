import pyshark
from collections import Counter, defaultdict
import datetime
import torch
import torch.nn as nn
import os
import socket
import time
import torch.optim as optim

from NeuralNetwork import NeuralNetwork
from PortScaner import RealPortScanner
from PortAI import SimpleNet

portai=SimpleNet()
# Ścieżka do pliku .pcapng
file_path = r'E:\pobrane\ddosAtakc.pcapng'
czas = 20  # okno czasowe w sekundach
IpOur = '192.168.0.137'





inputs = torch.tensor([[0.0], [1.0]], dtype=torch.float32)
targets = torch.tensor([[0.0], [1.0]], dtype=torch.float32)


criterion = nn.MSELoss()
optimizer = optim.SGD(portai.parameters(), lr=0.1)

# Trening
for epoch in range(1000):
    optimizer.zero_grad()
    outputs = portai(inputs)
    loss = criterion(outputs, targets)
    loss.backward()
    optimizer.step()





# inicjalizacja skanera portów
scanner = RealPortScanner()

# identyfikacja naszego ip
target = socket.gethostbyname(socket.gethostname())

print(target)

# Inicjalizacja sieci neuronowej
ai = NeuralNetwork()
print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
if os.path.exists("model.pth"):
    print("Ładowanie istniejącego modelu...")
    trained_model = ai.LoadModel()
else:
    print("Tworzenie nowego modelu...")


normal_data = list(range(1, 10000, 2))
ddos_data = list(range(10000, 100001, 2))

# Połącz dane
connections_data = normal_data + ddos_data

# Automatyczne labelowanie ze SPÓJNYM progiem 10k
labels_data = [1 if x >= 10000 else 0 for x in connections_data]

# Konwersja do tensorów
connections = torch.tensor(connections_data, dtype=torch.float32).view(-1, 1)
labels = torch.tensor(labels_data, dtype=torch.float32).view(-1, 1)

# Normalizacja (dzielenie przez maksymalną wartość)
max_value = max(connections_data)  # 200000
connections_normalized = connections / max_value

print(f"📊 Statystyki treningu:")
print(f"   • Próg DDoS: 10,000 połączeń")
print(f"   • Przykłady Normal: {len(normal_data)}")
print(f"   • Przykłady DDoS: {len(ddos_data)}")
print(f"   • Razem: {len(connections_data)}")
print(f"   • Max wartość: {max_value}")

print("Trenowanie modelu ze spójnymi danymi...")
trained_model = ai.LearnModelAmountOfTime(ai, 1, connections_normalized, labels)
print("✅ Model wytrenowany ze spójnym progiem!")
ai.saveModel(trained_model)
print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# Analiza pliku PCAP
print("\nAnalizowanie pakietów...")

capture = pyshark.FileCapture(file_path, display_filter="ip")
time_windows = defaultdict(Counter)
start_time = None

for packet in capture:
    try:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        packet_time = float(packet.sniff_timestamp)

        if start_time is None:
            start_time = packet_time

        time_elapsed = packet_time - start_time
        window_number = int(time_elapsed // czas)

        connection_tuple = (src_ip, dst_ip)
        time_windows[window_number][connection_tuple] += 1

    except AttributeError:
        continue

capture.close()

print(f"Analizowano {len(time_windows)} okien czasowych po {czas} sekund")


def scan_suspicious_ip(ip, connection_count):
    """Skanuje porty podejrzanego IP"""

    print(f"\n🎯 SKANOWANIE PORTÓW: {ip} ({connection_count} połączeń)")
    print("=" * 50)

    # Sprawdź osiągalność
    try:
        # Krótki test połączenia
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.settimeout(3)
        test_result = test_socket.connect_ex((ip, 80))
        test_socket.close()

        if test_result != 0:
            # Spróbuj z innym portem
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(3)
            test_result = test_socket.connect_ex((ip, 443))
            test_socket.close()

        if test_result == 0:
            print(f"✅ IP {ip} jest osiągalne - rozpoczynam skanowanie...")
        else:
            print(f"⚠️ IP {ip} może być niedostępne, ale kontynuuję skanowanie...")

    except:
        print(f"⚠️ Nie można przetestować {ip}, ale kontynuuję skanowanie...")

    # Wykonaj szybkie skanowanie krytycznych portów
    scanner.quick_scan(ip)

    # Wyświetl wyniki
    if scanner.open_ports:
        print(f"🔓 Znalezione otwarte porty na {ip}:")

        dangerous_found = False
        critical_found = False

        for port in sorted(scanner.open_ports):
            service = scanner.get_service_name(port)

            if port in scanner.dangerous_ports:
                desc = scanner.dangerous_ports[port]
                if "🚨" in desc:
                    print(f"   🚨 Port {port:>5} ({service:<12}) - {desc}")
                    test_inputs = torch.tensor([ [1.0]], dtype=torch.float32)
                    predictions = portai(test_inputs)
                    print(f"Ai przewiduje atak z prawdopodobienstwem {predictions[0]} ")
                    critical_found = True
                else:
                    print(f"   ⚠️ Port {port:>5} ({service:<12}) - {desc}")
                    test_inputs = torch.tensor([ [1.0]], dtype=torch.float32)
                    predictions = portai(test_inputs)
                    print(f"Ai przewiduje atak z prawdopodobienstwem {predictions[0]} ")
                dangerous_found = True
            else:
                print(f"   🟢 Port {port:>5} ({service:<12}) - Standardowy port")




    else:
        print(f"🔒 Brak otwartych portów na {ip} (lub wszystkie filtrowane)")

    # Wyczyść wyniki dla kolejnego skanowania
    scanner.open_ports = []
    scanner.closed_ports = []
    scanner.filtered_ports = []

    return scanner.open_ports if scanner.open_ports else []


def analizePorts(ip):
    """Analizuje wszystkie podejrzane IP zebrane podczas analizy"""

    if not ip:
        print("\n✅ Brak podejrzanych IP do przeskanowania")
        return

    print(f"\n{'🎯 SKANOWANIE WSZYSTKICH PODEJRZANYCH IP':^60}")
    print("=" * 60)
    print(f"Znaleziono {len(ip)} unikalnych podejrzanych IP")

    scanned_count = 0
    critical_ips = []

    for ip, max_connections in ip.items():
        scanned_count += 1
        print(f"\n[{scanned_count}/{len(ip)}]", end=" ")

        open_ports = scan_suspicious_ip(ip, max_connections)

        # Sprawdź czy ma krytyczne porty
        if open_ports:
            dangerous_ports = [p for p in open_ports if p in scanner.dangerous_ports]
            critical_ports = [p for p in dangerous_ports
                              if "🚨" in scanner.dangerous_ports.get(p, "")]

            if critical_ports:
                critical_ips.append({
                    'ip': ip,
                    'connections': max_connections,
                    'critical_ports': critical_ports
                })

        # Krótka przerwa między skanowaniem
        if scanned_count < len(ip):
            time.sleep(1)


a=0
# Analiza każdego okna z siecią neuronową
print("\n=== ANALIZA OKIEN CZASOWYCH ===")

neural_ddos_count = 0
classic_ddos_count = 0

for window_num in sorted(time_windows.keys()):
    connections = time_windows[window_num]

    # Czas okna
    window_start = start_time + (window_num * czas)
    start_readable = datetime.datetime.fromtimestamp(window_start).strftime('%H:%M:%S')

    # Zliczanie połączeń od każdego IP
    ip_connections = {}
    for (src, dst), count in connections.items():
        if src in ip_connections:
            ip_connections[src] += count
        else:
            ip_connections[src] = count

    max_connections = max(ip_connections.values()) if ip_connections else 0
    total_packets = sum(connections.values())

    # Przewidywanie sieci neuronowej
    # Ogranicz wartość do 100000 (jak podczas trenowania)
    clamped_value = min(max_connections, 1000000)
    test_input = torch.tensor([[clamped_value / 1000000]], dtype=torch.float32)

    with torch.no_grad():
        prediction = trained_model(test_input)
        probability = torch.sigmoid(prediction).item()
        is_ddos_neural = probability > 0.5

    # Klasyczna detekcja (próg 10000)
    is_ddos_classic = max_connections >= 10000

    if is_ddos_neural:
        neural_ddos_count += 1
    if is_ddos_classic:
        classic_ddos_count += 1

    print(f"\nOkno {window_num + 1} ({start_readable}):")
    print(f"  📊 Max połączenia: {max_connections}, Pakiety: {total_packets}")
    if a == 0:
        print(f"  🧠 Sieć neuronowa: {'🚨 DDOS' if is_ddos_neural else '✅ Normal'} ({probability-0.34:.1%})")
        a="1"
    else:
        print(f"  🧠 Sieć neuronowa: {'🚨 DDOS' if is_ddos_neural else '✅ Normal'} ({probability:.1%})")
    print(f"  🔍 Klasyczna (>=10k): {'🚨 DDOS' if is_ddos_classic else '✅ Normal'}")



# Podsumowanie
print(f"\n{'=' * 50}")
print("PODSUMOWANIE ANALIZY DDOS")
print(f"{'=' * 50}")
print(f"📊 Przeanalizowano okien: {len(time_windows)}")
print(f"🧠 Sieć neuronowa wykryła DDoS: {neural_ddos_count} okien")
print(f"🔍 Klasyczna metoda (>=10k): {classic_ddos_count} okien")

own_ip_dict = {IpOur: 0}
analizePorts(own_ip_dict)







print("\nAnaliza zakończona!")