import psutil
import pyshark

def show_network_interfaces():
    """Wyświetla dostępne interfejsy sieciowe"""
    print("=== INTERFEJSY SIECIOWE (psutil) ===")
    interfaces = psutil.net_if_addrs()
    for interface_name, addresses in interfaces.items():
        print(f"\nInterfejs: {interface_name}")
        for addr in addresses:
            if addr.family.name == 'AF_INET':  # IPv4
                print(f"  IPv4: {addr.address}")
            elif addr.family.name == 'AF_INET6':  # IPv6
                print(f"  IPv6: {addr.address}")

def show_wireshark_interfaces():
    """Wyświetla interfejsy dostępne dla Wireshark"""
    print("\n=== INTERFEJSY WIRESHARK ===")
    try:
        # Spróbuj uzyskać listę interfejsów z pyshark
        import subprocess
        result = subprocess.run(['tshark', '-D'], capture_output=True, text=True)
        if result.returncode == 0:
            print("Dostępne interfejsy dla Wireshark:")
            print(result.stdout)
        else:
            print("Nie można uzyskać listy interfejsów (brak tshark lub uprawnień)")
    except FileNotFoundError:
        print("tshark nie jest zainstalowany")
    except Exception as e:
        print(f"Błąd: {e}")

if __name__ == "__main__":
    show_network_interfaces()
    show_wireshark_interfaces()