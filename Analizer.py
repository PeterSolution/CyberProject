from scapy.all import *
from scapy.utils import rdpcap
from collections import defaultdict, Counter
from datetime import datetime
import pandas as pd


class ScapyAnalyzer:
    def __init__(self):
        self.connections = []
        self.connection_stats = defaultdict(int)
        self.ip_stats = Counter()
        self.packet_count = 0

    def analyze_pcap_file(self, pcap_file_path):
        """
        Analizuje plik PCAP używając Scapy

        Args:
            pcap_file_path: ścieżka do pliku .pcap lub .pcapng
        """
        print(f"Analizuję plik: {pcap_file_path}")

        try:
            # Wczytaj plik PCAP
            packets = rdpcap(pcap_file_path)
            print(f"Wczytano {len(packets)} pakietów")

            for packet in packets:
                try:
                    self.packet_count += 1
                    if self.packet_count % 1000 == 0:
                        print(f"Przetworzono {self.packet_count} pakietów...")

                    # Pobierz timestamp
                    timestamp = datetime.fromtimestamp(float(packet.time))

                    # Sprawdź czy pakiet ma warstwę IP
                    if packet.haslayer(IP):
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        protocol = None
                        src_port = None
                        dst_port = None
                        tcp_flags = []

                        # Sprawdź protokół transportowy
                        if packet.haslayer(TCP):
                            protocol = 'TCP'
                            src_port = packet[TCP].sport
                            dst_port = packet[TCP].dport

                            # Sprawdź flagi TCP
                            flags = packet[TCP].flags
                            if flags & 0x02:  # SYN
                                tcp_flags.append('SYN')
                            if flags & 0x10:  # ACK
                                tcp_flags.append('ACK')
                            if flags & 0x01:  # FIN
                                tcp_flags.append('FIN')
                            if flags & 0x04:  # RST
                                tcp_flags.append('RST')

                        elif packet.haslayer(UDP):
                            protocol = 'UDP'
                            src_port = packet[UDP].sport
                            dst_port = packet[UDP].dport

                        elif packet.haslayer(ICMP):
                            protocol = 'ICMP'

                        else:
                            protocol = 'OTHER'

                        # Zapisz informacje o połączeniu
                        connection_info = {
                            'timestamp': timestamp,
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'protocol': protocol,
                            'tcp_flags': tcp_flags,
                            'packet_length': len(packet)
                        }

                        self.connections.append(connection_info)

                        # Aktualizuj statystyki
                        connection_key = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol})"
                        self.connection_stats[connection_key] += 1
                        self.ip_stats[src_ip] += 1

                except Exception as e:
                    print(f"Błąd przetwarzania pakietu {self.packet_count}: {e}")
                    continue

            print(f"Analiza zakończona. Przetworzono {self.packet_count} pakietów.")

        except Exception as e:
            print(f"Błąd podczas analizy pliku: {e}")
            return False

        return True

    def get_connection_statistics(self):
        """Zwraca statystyki połączeń"""
        if not self.connections:
            print("Brak danych do analizy")
            return None

        print(f"\n=== STATYSTYKI POŁĄCZEŃ ===")
        print(f"Całkowita liczba pakietów: {len(self.connections)}")
        print(f"Unikalne połączenia: {len(self.connection_stats)}")

        # Top 10 najaktywniejszych połączeń
        print(f"\n=== TOP 10 NAJAKTYWNIEJSZYCH POŁĄCZEŃ ===")
        for connection, count in sorted(self.connection_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"{connection}: {count} pakietów")

        # Top 10 najaktywniejszych IP
        print(f"\n=== TOP 10 NAJAKTYWNIEJSZYCH ADRESÓW IP ===")
        for ip, count in self.ip_stats.most_common(10):
            print(f"{ip}: {count} pakietów")

        return {
            'total_packets': len(self.connections),
            'unique_connections': len(self.connection_stats),
            'top_connections': dict(sorted(self.connection_stats.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_ips': dict(self.ip_stats.most_common(10))
        }

    def detect_suspicious_activity(self, threshold=100):
        """Wykrywa podejrzaną aktywność sieciową"""
        print(f"\n=== ANALIZA PODEJRZANEJ AKTYWNOŚCI (próg: {threshold} pakietów) ===")

        suspicious_ips = []
        for ip, count in self.ip_stats.items():
            if count > threshold:
                suspicious_ips.append((ip, count))
                print(f"⚠️  PODEJRZANE IP: {ip} - {count} pakietów")

        # Analiza połączeń TCP SYN (możliwy SYN flood)
        syn_connections = [conn for conn in self.connections if
                           'SYN' in conn['tcp_flags'] and 'ACK' not in conn['tcp_flags']]

        if len(syn_connections) > threshold:
            print(f"⚠️  MOŻLIWY ATAK SYN FLOOD: {len(syn_connections)} pakietów SYN")

        # Analiza protokołów
        protocol_stats = Counter([conn['protocol'] for conn in self.connections])
        print(f"\n=== STATYSTYKI PROTOKOŁÓW ===")
        for protocol, count in protocol_stats.most_common():
            print(f"{protocol}: {count} pakietów")

        return suspicious_ips

    def export_to_csv(self, filename='network_analysis.csv'):
        """Eksportuje wyniki do pliku CSV"""
        if not self.connections:
            print("Brak danych do eksportu")
            return

        df = pd.DataFrame(self.connections)
        df['tcp_flags'] = df['tcp_flags'].apply(lambda x: ','.join(x) if x else '')
        df.to_csv(filename, index=False, encoding='utf-8')
        print(f"Dane wyeksportowane do pliku: {filename}")

    def get_connection_counts_for_ml(self):
        """Przygotowuje dane dla machine learning"""
        connection_counts = []
        ip_list = []

        for ip, count in self.ip_stats.items():
            connection_counts.append([count])
            ip_list.append(ip)

        print(f"Przygotowano dane ML: {len(connection_counts)} rekordów")
        return connection_counts, ip_list


# Przykład użycia
if __name__ == "__main__":
    analyzer = ScapyAnalyzer()

    # Analizuj plik
    pcap_file = input("Podaj ścieżkę do pliku PCAP: ").strip()

    if analyzer.analyze_pcap_file(pcap_file):
        analyzer.get_connection_statistics()
        analyzer.detect_suspicious_activity()

        # Przygotuj dane dla ML
        connection_counts, ip_list = analyzer.get_connection_counts_for_ml()

        export = input("\nCzy wyeksportować wyniki do CSV? (tak/nie): ").strip().lower()
        if export in ['tak', 'yes', 't', 'y']:
            analyzer.export_to_csv()