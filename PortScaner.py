import socket
import threading
import subprocess
import time
from datetime import datetime


class RealPortScanner:
    def __init__(self):
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []

        # Niebezpieczne porty z opisem zagrożeń
        self.dangerous_ports = {
            21: "🚨 FTP - Niezaszyfrowany transfer plików, możliwość pobrania/wgrania malware",
            22: "⚠️ SSH - Brute force ataki, kompromitacja systemu",
            23: "🚨 Telnet - Hasła w plain text, pełny dostęp do systemu",
            25: "⚠️ SMTP - Możliwość wysyłania spam, relay ataków",
            53: "⚠️ DNS - DNS amplification, cache poisoning",
            80: "⚠️ HTTP - Web ataki: XSS, SQLi, directory traversal",
            110: "🚨 POP3 - Niezaszyfrowane hasła email",
            135: "🚨 RPC - Buffer overflow, remote code execution",
            139: "🚨 NetBIOS - Dostęp do plików, informacji systemowych",
            143: "🚨 IMAP - Niezaszyfrowane hasła email",
            443: "⚠️ HTTPS - SSL/TLS ataki, słabe certyfikaty",
            445: "🚨 SMB - WannaCry, EternalBlue, ransomware",
            993: "⚠️ IMAPS - Sprawdź konfigurację SSL",
            995: "⚠️ POP3S - Sprawdź konfigurację SSL",
            1433: "🚨 MS SQL - SQL injection, database compromise",
            1521: "🚨 Oracle - Database ataki, privilege escalation",
            3306: "🚨 MySQL - SQL injection, data theft",
            3389: "🚨 RDP - #1 cel ataków! Brute force, ransomware",
            5432: "🚨 PostgreSQL - Database compromise",
            5900: "🚨 VNC - Często bez hasła! Pełny dostęp do ekranu",
            6379: "🚨 Redis - Często bez autentykacji, RCE możliwe",
            8080: "⚠️ HTTP Alt - Web ataki, proxy abuse",
            8443: "⚠️ HTTPS Alt - SSL ataki"
        }

    def scan_port(self, target, port, timeout=1):
        """Skanuje czy port jest OTWARTY (czy ktoś nasłuchuje)"""
        try:
            # Tworzymy socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            # PRÓBUJEMY POŁĄCZYĆ SIĘ (nie bind!)
            result = sock.connect_ex((target, port))
            sock.close()

            if result == 0:
                # Połączenie udane = PORT OTWARTY!
                self.open_ports.append(port)
                return "OPEN"
            else:
                # Połączenie nieudane = port zamknięty
                self.closed_ports.append(port)
                return "CLOSED"

        except socket.timeout:
            # Timeout = prawdopodobnie filtrowany przez firewall
            self.filtered_ports.append(port)
            return "FILTERED"
        except Exception:
            self.closed_ports.append(port)
            return "CLOSED"

    def aggressive_scan(self, target, port, timeout=3):
        """Agresywniejsze skanowanie z grabowaniem bannerów"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            result = sock.connect_ex((target, port))

            if result == 0:
                # Port otwarty - spróbuj pobrać banner
                banner = ""
                try:
                    # Wyślij podstawowe requesty zależnie od portu
                    if port == 80:
                        sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                        banner = sock.recv(512).decode('utf-8', errors='ignore')
                    elif port == 21:
                        banner = sock.recv(512).decode('utf-8', errors='ignore')
                    elif port == 22:
                        banner = sock.recv(512).decode('utf-8', errors='ignore')
                    elif port == 25:
                        banner = sock.recv(512).decode('utf-8', errors='ignore')
                except:
                    pass

                sock.close()
                self.open_ports.append(port)
                return "OPEN", banner.strip()
            else:
                sock.close()
                return "CLOSED", ""

        except Exception:
            return "CLOSED", ""

    def threaded_scan(self, target, ports, timeout=1):
        """Wielowątkowe skanowanie"""
        print(f"🎯 Skanowanie {target} - {len(ports)} portów")
        print(f"⏱️ Timeout: {timeout}s")

        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []

        def scan_worker(port):
            status = self.scan_port(target, port, timeout)
            if status == "OPEN":
                print(f"✅ Port {port:>5} - OTWARTY")

        threads = []
        start_time = time.time()

        # Ograniczenie do 100 wątków jednocześnie
        max_threads = 100
        for i in range(0, len(ports), max_threads):
            batch = ports[i:i + max_threads]

            batch_threads = []
            for port in batch:
                thread = threading.Thread(target=scan_worker, args=(port,))
                batch_threads.append(thread)
                thread.start()

            # Czekaj na zakończenie tej partii
            for thread in batch_threads:
                thread.join()

        end_time = time.time()
        print(f"⏱️ Skanowanie zakończone w {end_time - start_time:.2f}s")

    def security_analysis(self, target):
        """Analiza bezpieczeństwa otwartych portów"""
        if not self.open_ports:
            print("✅ BRAK OTWARTYCH PORTÓW - System bezpieczny!")
            return

        print(f"\n{'🚨 ANALIZA ZAGROŻEŃ BEZPIECZEŃSTWA':^60}")
        print("=" * 60)

        critical_threats = []
        high_threats = []
        medium_threats = []

        for port in sorted(self.open_ports):
            if port in self.dangerous_ports:
                threat_desc = self.dangerous_ports[port]

                if "🚨" in threat_desc:
                    critical_threats.append((port, threat_desc))
                elif "⚠️" in threat_desc:
                    high_threats.append((port, threat_desc))
            else:
                medium_threats.append((port, "Nieznana usługa - wymaga analizy"))

        # Zagrożenia krytyczne
        if critical_threats:
            print(f"\n🔴 ZAGROŻENIA KRYTYCZNE ({len(critical_threats)}):")
            for port, desc in critical_threats:
                print(f"   Port {port:>5}: {desc}")

        # Zagrożenia wysokie
        if high_threats:
            print(f"\n🟡 ZAGROŻENIA WYSOKIE ({len(high_threats)}):")
            for port, desc in high_threats:
                print(f"   Port {port:>5}: {desc}")

        # Pozostałe
        if medium_threats:
            print(f"\n🟢 DO SPRAWDZENIA ({len(medium_threats)}):")
            for port, desc in medium_threats:
                print(f"   Port {port:>5}: {desc}")

        # Rekomendacje
        print(f"\n🛡️ NATYCHMIASTOWE DZIAŁANIA:")
        if critical_threats:
            print("1. 🚨 ZAMKNIJ NATYCHMIAST porty krytyczne!")
            print("2. 🔥 Skonfiguruj firewall - zablokuj niepotrzebne porty")
            print("3. 🔐 Zmień WSZYSTKIE domyślne hasła")
            print("4. 📱 Włącz monitoring ruchu sieciowego")
            print("5. 🔄 Zaktualizuj system i wszystkie usługi")

        if len(self.open_ports) > 10:
            print(f"6. ⚠️ {len(self.open_ports)} otwartych portów to BARDZO DUŻO!")
            print("   Wyłącz niepotrzebne usługi")

    def banner_grabbing_scan(self, target, ports):
        """Skanowanie z grabowaniem bannerów"""
        print(f"🔍 SKANOWANIE Z BANNER GRABBING")
        print("=" * 50)

        self.open_ports = []

        for port in ports:
            status, banner = self.aggressive_scan(target, port, timeout=3)

            if status == "OPEN":
                service = self.get_service_name(port)
                print(f"\n✅ Port {port:>5} ({service}) - OTWARTY")

                if banner:
                    print(f"   📋 Banner: {banner[:100]}...")

                    # Sprawdź podatności w bannerach
                    self.check_banner_vulnerabilities(banner, port)

                if port in self.dangerous_ports:
                    print(f"   {self.dangerous_ports[port]}")

    def check_banner_vulnerabilities(self, banner, port):
        """Sprawdza znane podatności w bannerach"""
        vuln_signatures = {
            'Apache/2.2': '🚨 Stara wersja Apache - podatna na multiple CVE',
            'Apache/2.4.6': '🚨 Apache 2.4.6 - znane podatności',
            'Microsoft-IIS/6.0': '🚨 IIS 6.0 - WebDAV exploit',
            'OpenSSH_5': '🚨 Stara wersja OpenSSH - podatności',
            'OpenSSH_6': '⚠️ OpenSSH 6.x - sprawdź aktualizacje',
            'vsftpd 2.3.4': '🚨 vsftpd 2.3.4 - BACKDOOR!',
            'ProFTPD 1.3.3': '🚨 ProFTPD 1.3.3 - buffer overflow',
            'MySQL 5.0': '🚨 Stara wersja MySQL - multiple vulns'
        }

        for signature, description in vuln_signatures.items():
            if signature in banner:
                print(f"   🎯 PODATNOŚĆ: {description}")

    def get_service_name(self, port):
        """Zwraca nazwę usługi"""
        try:
            return socket.getservbyport(port)
        except:
            services = {
                8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 3389: "RDP",
                5900: "VNC", 1433: "MSSQL", 3306: "MySQL", 6379: "Redis"
            }
            return services.get(port, "Unknown")

    def quick_scan(self, target):
        """Szybkie skanowanie najważniejszych portów"""
        critical_ports = [21, 22, 23, 25, 53, 80, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379,
                          8080]
        self.threaded_scan(target, critical_ports, timeout=2)

    def display_results(self):
        """Wyświetla szczegółowe wyniki"""
        print(f"\n{'📊 WYNIKI SKANOWANIA':^60}")
        print("=" * 60)
        print(f"🟢 Otwarte porty: {len(self.open_ports)}")
        print(f"🔴 Zamknięte porty: {len(self.closed_ports)}")
        print(f"🟡 Filtrowane porty: {len(self.filtered_ports)}")

        if self.open_ports:
            print(f"\n🔓 OTWARTE PORTY:")
            for port in sorted(self.open_ports):
                service = self.get_service_name(port)
                risk = "🚨" if port in [21, 23, 135, 139, 445, 3389,
                                        5900] else "⚠️" if port in self.dangerous_ports else "🟢"
                print(f"   {risk} Port {port:>5} - {service}")

