
import sys

grupos = ["#hiddenSSID", "Auracast", "Bitless", "Dead Net", "grupo", "LA LA LAN", "LAN-gustia", "Los Red(ondos)", "Los simuLANdores", 
        "Los-Tios-Networks", "Lost-Pointer-2.4", "MACac OS", "MiLANesas", "Netrunners", "Ping Floyd", "Red Hot Chilli Packets", 
        "TCPaniko", "WAN-Direction", "WireGuardians", "PandaBasic", "Group Not Found : (", "BitBros", "Los_CondIPcionales"]

def find_packets(data, max_len = 10):
    # Encontrar todas las secuencias de nuestro

    return data

def grupo_prefix(nombre_grupo: str):
    pref = nombre_grupo.lower()[:5]
    return pref.encode("ascii")


def extract_frame(data: bytes, nombre_grupo: str):

    grupo_bytes = grupo_prefix(nombre_grupo)
    grupo_hex = grupo_bytes.hex()

    print(f"\n Buscando grupo: {grupo_bytes}, (hex: {grupo_hex}) \n")

    frames = []
    n = len(data)
    pos = 0
    i = 0

    while True:

        idx = data.find(grupo_bytes, pos)
        if idx == -1:
            break

        # HDR completo: 5 (group) + 1 (seq) + 1 (length) = 7 bytes
        header_len = len(grupo_bytes) + 2
        if idx  + header_len > n:
            pos = idx + 1
            continue

        seq = data[idx + len(grupo_bytes)]
        length = data[idx + len(grupo_bytes) + 1]

        payload_start = idx + header_len
        payload__end = payload_start + length

        if payload__end > n:
            pos = idx + 1
            continue

        payload = data[payload_start:payload__end]

        frames.append({
            "offset": idx,
            "seq": seq,
            "length": length,
            "payload": payload
        })

        pos = payload__end
    
    return frames



def main():

    with open(sys.argv[1], "rb") as f:
        data = f.read()

    resultados = {}
    
    for group in grupos:

        grupo_bytes = grupo_prefix(group)
        frames = extract_frame(data, group)
        resultados[group] = [fr["payload"] for fr in frames]

    for payloads in resultados.items():
        #print(f"\n Nombre: {nombre}, prefix:{grupo_prefix(nombre)!r} frames: {len(payloads)}")

        for p in payloads:
            print(f"{p!r}")

    return resultados



if __name__ == "__main__":
    main()