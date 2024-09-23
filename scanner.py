from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    # Criar pacote ARP
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Enviar pacote e receber resposta
    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

if __name__ == "__main__":
    ip_range = input("Digite o intervalo de IPs (ex: 192.168.1.1/24): ")
    devices = scan_network(ip_range)

    print("Dispositivos encontrados na rede:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
