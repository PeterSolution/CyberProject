# import os
# import torch
# from datetime import datetime, timedelta
# import threading
# from NeuralNetwork import NeuralNetwork
# import psutil
# # import pyshark  # Nie używamy już pyshark
# import functions
# from Analizer import ScapyAnalyzer  # Zamiast WiresharkAnalyzer
#
#
# def main():
#     print("=== ANALIZATOR RUCHU SIECIOWEGO ===")
#
#     # Inicjalizacja analizatora
#     analyzer = ScapyAnalyzer()
#
#     pcap_file = r"E:\pobrane\ddos.pcapng"
#
#     if not os.path.exists(pcap_file):
#         print(f"Błąd: Plik {pcap_file} nie istnieje!")
#         return
#
#     print(f"Analizuję plik: {pcap_file}")
#
#     # Analizuj plik PCAP
#     if analyzer.analyze_pcap_file(pcap_file):
#         # Wyświetl statystyki
#         analyzer.get_connection_statistics()
#         analyzer.detect_suspicious_activity()
#
#         # Przygotuj dane dla sieci neuronowej
#         connection_counts, ip_list = analyzer.get_connection_counts_for_ml()
#
#         if connection_counts:
#             # Konwertuj na tensor PyTorch
#             csv_data = torch.tensor(connection_counts, dtype=torch.float32)
#             print(f"Przygotowano dane dla sieci neuronowej: {csv_data.shape}")
#
#             # Przykład użycia z siecią neuronową
#             # neural_network = NeuralNetwork()
#             # model = neural_network.LoadModel()  # lub stwórz nowy model
#
#             # Przykład predykcji (dostosuj do swojego modelu)
#             # predictions = model(csv_data)
#             # print(f"Predykcje: {predictions}")
#
#             # Zapisz dane do CSV dla dalszej analizy
#             analyzer.export_to_csv('ddos_analysis.csv')
#
#         else:
#             print("Brak danych do analizy przez sieć neuronową")
#     else:
#         print("Błąd podczas analizy pliku PCAP")
#
#
# def analyze_live_traffic():
#     """Funkcja do analizy ruchu na żywo (używając psutil)"""
#     print("=== ANALIZA RUCHU NA ŻYWO ===")
#
#     EnemyIP = []
#
#     def connection_check(ip):
#         """Sprawdza IP przez 10 minut"""
#         EndTime = datetime.now() + timedelta(minutes=1)
#         while datetime.now() < EndTime:
#             pass  # Czekaj 10 minut
#         if ip in EnemyIP:
#             EnemyIP.remove(ip)
#
#     def get_incoming_connections():
#         """Pobiera połączenia przychodzące"""
#         for i in range(30):  # 30 iteracji
#             connections = psutil.net_connections(kind='inet')
#             ip_counter = {}
#
#             for conn in connections:
#                 if conn.status == 'ESTABLISHED' and conn.raddr:
#                     remote_ip = conn.raddr.ip
#
#                     if remote_ip in ip_counter:
#                         ip_counter[remote_ip] += 1
#                     else:
#                         ip_counter[remote_ip] = 1
#
#             # Zapisz podejrzane IP
#             for ip, count in ip_counter.items():
#                 if count > 1 and ip not in EnemyIP:
#                     print(f"Podejrzane IP: {ip} - {count} połączeń")
#                     EnemyIP.append(ip)
#
#                     # Uruchom wątek do sprawdzania IP
#                     ip_thread = threading.Thread(target=connection_check, args=(ip,))
#                     ip_thread.daemon = True
#                     ip_thread.start()
#
#     # Uruchom analizę połączeń w osobnym wątku
#     ddos_thread = threading.Thread(target=get_incoming_connections)
#     ddos_thread.daemon = True
#     ddos_thread.start()
#
#     return ddos_thread
#
#
# if __name__ == "__main__":
#     try:
#         main()
#
#         choice = input("\nCzy chcesz również analizować ruch na żywo? (tak/nie): ").strip().lower()
#         if choice in ['tak', 'yes', 't', 'y']:
#             live_thread = analyze_live_traffic()
#             print("Analiza ruchu na żywo uruchomiona...")
#             print("Naciśnij Enter aby zatrzymać...")
#             input()
#             print("Zatrzymywanie analizy...")
#
#     except Exception as e:
#         print(f"Błąd: {e}")
#
#     print("Program zakończony.")

import pyshark
from collections import Counter, defaultdict
import datetime
import torch
import torch.nn as nn
import os

from NeuralNetwork import NeuralNetwork

# Ścieżka do pliku .pcapng
file_path = r'E:\pobrane\ddosAtakc.pcapng'
czas = 20  # okno czasowe w sekundach
twoje_ip = '192.168.0.137'

# Inicjalizacja sieci neuronowej
ai = NeuralNetwork()

if os.path.exists("model.pth"):
    print("Ładowanie istniejącego modelu...")
    trained_model = ai.LoadModel()
else:
    print("Tworzenie nowego modelu...")

    # Dane treningowe - próg 10000 połączeń
    connections_data = [
        # Normalne (< 10000)
        100, 500, 1000, 2000, 3000, 5000, 7000, 8000, 9000, 9500,
        # DDoS (>= 10000)
        10000, 12000, 15000, 20000, 30000, 50000, 80000, 100000
    ]

connections_data = list(range(1, 1000001, 1000))  # [1, 1001, 2001, 3001, ..., 999001]

# Automatyczne labelowanie: 1 jeśli >= 10000, 0 jeśli < 10000
labels_data = [1 if x >= 100000 else 0 for x in connections_data]
connections = torch.tensor(connections_data, dtype=torch.float32).view(-1, 1)
labels = torch.tensor(labels_data, dtype=torch.float32).view(-1, 1)

# Normalizacja (dzielenie przez maksymalną wartość)
max_value = 1000000
connections_normalized = connections / max_value

print("Trenowanie modelu na milonie przykładów...")
trained_model = ai.LearnModelAmountOfTime(ai, 2400000, connections_normalized, labels)
print("Model wytrenowany na pełnym zakresie danych!")
ai.saveModel(trained_model)

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
    clamped_value = min(max_connections, 10000)
    test_input = torch.tensor([[clamped_value / 10000]], dtype=torch.float32)

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
    print(f"  🧠 Sieć neuronowa: {'🚨 DDOS' if is_ddos_neural else '✅ Normal'} ({probability:.1%})")
    print(f"  🔍 Klasyczna (>=10k): {'🚨 DDOS' if is_ddos_classic else '✅ Normal'}")

    if max_connections >= 10000:
        suspicious_ips = [(ip, count) for ip, count in ip_connections.items() if count >= 5000]
        if suspicious_ips:
            print(f"  🎯 Podejrzane IP:")
            for ip, count in suspicious_ips[:3]:
                print(f"      • {ip}: {count} połączeń")

# Podsumowanie
print(f"\n{'=' * 50}")
print("PODSUMOWANIE")
print(f"{'=' * 50}")
print(f"📊 Przeanalizowano okien: {len(time_windows)}")
print(f"🧠 Sieć neuronowa wykryła DDoS: {neural_ddos_count} okien")
print(f"🔍 Klasyczna metoda (>=10k): {classic_ddos_count} okien")

if neural_ddos_count > 0 or classic_ddos_count > 0:
    print(f"\n🚨 WYKRYTO POTENCJALNY ATAK DDOS!")
else:
    print(f"\n✅ Ruch sieciowy normalny")

print("\nAnaliza zakończona!")
#
# # Wczytanie pliku
# capture = pyshark.FileCapture(file_path, display_filter="ip")
#
# # Słownik do przechowywania połączeń w oknach czasowych
# time_windows = defaultdict(Counter)
#
# # Czas startu (będzie ustawiony na podstawie pierwszego pakietu)
# start_time = None
#
# print("Analizowanie pakietów...")
#
# for packet in capture:
#     try:
#         src_ip = packet.ip.src
#         dst_ip = packet.ip.dst
#
#         # Pobranie czasu pakietu
#         packet_time = float(packet.sniff_timestamp)
#
#         # Ustawienie czasu startu na podstawie pierwszego pakietu
#         if start_time is None:
#             start_time = packet_time
#
#         # Obliczenie, do którego okna czasowego należy pakiet
#         time_elapsed = packet_time - start_time
#         window_number = int(time_elapsed // czas)
#
#         # Dodanie połączenia do odpowiedniego okna czasowego
#         connection_tuple = (src_ip, dst_ip)
#         time_windows[window_number][connection_tuple] += 1
#
#     except AttributeError:
#         # Nie wszystkie pakiety mają IP (np. ARP, itp.)
#         continue
#
# capture.close()
#
# print(f"\nAnalizowano {len(time_windows)} okien czasowych po {czas} sekund każde\n")
#
# # Przygotowanie danych do trenowania sieci neuronowej
# connection_counts = []
# ddos_labels = []
#
# print("Przygotowywanie danych do trenowania...")
#
# for window_num in sorted(time_windows.keys()):
#     connections = time_windows[window_num]
#
#     # Zliczanie połączeń od każdego IP
#     ip_connections = {}
#     for (src, dst), count in connections.items():
#         if src in ip_connections:
#             ip_connections[src] += count
#         else:
#             ip_connections[src] = count
#
#     # Znajdowanie maksymalnej liczby połączeń w tym oknie
#     max_connections = max(ip_connections.values()) if ip_connections else 0
#     connection_counts.append(max_connections)
#
#     # Prosta heurystyka labelowania: DDoS jeśli > 1000 połączeń
#     is_ddos = 1.0 if max_connections > 1000 else 0.0
#     ddos_labels.append(is_ddos)
#
# # Konwersja do tensorów PyTorch
# connections_tensor = torch.tensor(connection_counts, dtype=torch.float32).view(-1, 1)
# labels_tensor = torch.tensor(ddos_labels, dtype=torch.float32).view(-1, 1)
#
# print(f"Dane przygotowane: {len(connection_counts)} próbek")
# print(f"Wykryto {sum(ddos_labels)} potencjalnych ataków DDoS")
#
# # Trenowanie modelu jeśli nie istnieje lub jest przestarzały
# model_exists = os.path.exists("model.pth")
#
# if not model_exists:
#     print("\nTrenowanie nowej sieci neuronowej...")
#
#     # Normalizacja danych (opcjonalnie)
#     max_connections_value = max(connection_counts) if connection_counts else 1
#     normalized_connections = connections_tensor / max_connections_value
#
#     # Trenowanie modelu z ograniczonym błędem
#     trained_model = ai.LearnModelUntilErrorLess(ai, 0.01, normalized_connections, labels_tensor)
#     print("Model wytrenowany i zapisany!")
# else:
#     print("Ładowanie istniejącego modelu...")
#     trained_model = ai.LoadModel()
#
# # Analiza każdego okna czasowego z przewidywaniami sieci neuronowej
# print("\n=== ANALIZA Z SIECIĄ NEURONOWĄ ===")
#
# for window_num in sorted(time_windows.keys()):
#     connections = time_windows[window_num]
#
#     # Czas rozpoczęcia i zakończenia okna
#     window_start = start_time + (window_num * czas)
#     start_readable = datetime.datetime.fromtimestamp(window_start).strftime('%Y-%m-%d %H:%M:%S')
#     end_readable = datetime.datetime.fromtimestamp(window_start + czas).strftime('%Y-%m-%d %H:%M:%S')
#
#     print(f"\n=== OKNO {window_num + 1} ({start_readable} - {end_readable}) ===")
#
#     # Zliczanie połączeń od każdego IP
#     ip_connections = {}
#     for (src, dst), count in connections.items():
#         if src in ip_connections:
#             ip_connections[src] += count
#         else:
#             ip_connections[src] = count
#
#     max_connections_in_window = max(ip_connections.values()) if ip_connections else 0
#
#     # Przewidywanie sieci neuronowej
#     with torch.no_grad():
#         # Normalizacja wejścia (jak podczas trenowania)
#         max_val = max(connection_counts) if connection_counts else 1
#         normalized_input = torch.tensor([[max_connections_in_window / max_val]], dtype=torch.float32)
#
#         prediction = trained_model(normalized_input)
#         ddos_probability = torch.sigmoid(prediction).item()  # Konwersja na prawdopodobieństwo 0-1
#
#         is_ddos_prediction = ddos_probability > 0.5
#
#     print(f"  Maksymalne połączenia w oknie: {max_connections_in_window}")
#     print(f"  Przewidywanie sieci neuronowej: {' DDOS' if is_ddos_prediction else 'NORMALNY'}")
#     print(f"  Prawdopodobieństwo DDoS: {ddos_probability:.2%}")
#
#     # Klasyczna analiza (dla porównania)
#     suspicious_found = False
#     suspicious_ips = []
#
#     for ip, total_count in ip_connections.items():
#         if total_count > 1000:  # Próg dla 20-sekundowego okna
#             suspicious_ips.append((ip, total_count))
#             suspicious_found = True
#
#     if suspicious_found:
#         print(f"  🔍 Klasyczna detekcja: Podejrzane IP:")
#         for ip, count in suspicious_ips:
#             print(f"      - {ip}: {count} połączeń")
#     else:
#         print(f"  🔍 Klasyczna detekcja: Brak podejrzanej aktywności")
#
#     # Porównanie metod
#     classic_detection = suspicious_found
#     neural_detection = is_ddos_prediction
#
#     if classic_detection == neural_detection:
#         print(f"  ✅ Zgodność metod: {'DDoS wykryty' if classic_detection else 'Brak zagrożenia'}")
#     else:
#         print(f"  ⚠️  Różnica w wykrywaniu!")
#         print(f"      Klasyczna: {'DDoS' if classic_detection else 'OK'}")
#         print(f"      Sieć neuronowa: {'DDoS' if neural_detection else 'OK'}")
#
# print("\n" + "=" * 50)
# print("PODSUMOWANIE ANALIZY")
# print("=" * 50)
#
# # Statystyki ogólne
# total_windows = len(time_windows)
# neural_ddos_count = 0
# classic_ddos_count = 0
#
# for window_num in sorted(time_windows.keys()):
#     connections = time_windows[window_num]
#     ip_connections = {}
#
#     for (src, dst), count in connections.items():
#         if src in ip_connections:
#             ip_connections[src] += count
#         else:
#             ip_connections[src] = count
#
#     max_connections_in_window = max(ip_connections.values()) if ip_connections else 0
#
#     # Przewidywanie sieci neuronowej
#     with torch.no_grad():
#         max_val = max(connection_counts) if connection_counts else 1
#         normalized_input = torch.tensor([[max_connections_in_window / max_val]], dtype=torch.float32)
#         prediction = trained_model(normalized_input)
#         ddos_probability = torch.sigmoid(prediction).item()
#
#         if ddos_probability > 0.5:
#             neural_ddos_count += 1
#
#     # Klasyczna detekcja
#     if max_connections_in_window > 1000:
#         classic_ddos_count += 1
#
# print(f"📊 Przeanalizowano okien: {total_windows}")
# print(f"🤖 Sieć neuronowa wykryła DDoS w: {neural_ddos_count} oknach")
# print(f"🔍 Klasyczna metoda wykryła DDoS w: {classic_ddos_count} oknach")
# print(f"📈 Procent okien z DDoS (sieć neuronowa): {neural_ddos_count / total_windows * 100:.1f}%")
# print(f"📈 Procent okien z DDoS (klasyczna): {classic_ddos_count / total_windows * 100:.1f}%")
#
# print("\nAnaliza zakończona!")




