import ipaddress
import subprocess
import requests
import getopt
import sys
from datetime import datetime
import re

def ip_pertenece_a_red(ip, ip_local="192.168.1.30", mascara="255.255.255.0"):
    try:
        # Convertir las direcciones IP y máscaras a objetos ipaddress.IPv4Address e ipaddress.IPv4Network
        direccion_ip = ipaddress.IPv4Address(ip)
        red_local = ipaddress.IPv4Network(f"{ip_local}/{mascara}", strict=False)

        # Verificar si la dirección IP pertenece a la misma red
        return direccion_ip in red_local

    except ipaddress.AddressValueError:
        print(f'Error: La dirección IP {ip} no es válida')
        return False

def medir_latencia_ping(ip):
    try:
        # Realizar un ping a la IP para medir la latencia
        proceso_ping = subprocess.Popen(['ping', '-n', '4', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        salida_ping, error_ping = proceso_ping.communicate()

        if proceso_ping.returncode == 0:
            # El ping fue exitoso, analizar la salida para obtener la latencia
            latencia = obtener_latencia_desde_salida_ping(salida_ping.decode())
            print(f'Latencia hacia {ip} (via ping): {latencia} ms')
            return latencia
        else:
            print(f'Error al realizar ping: {error_ping}')
            return None

    except Exception as e:
        print(f'Error: {e}')
        return None

def obtener_latencia_desde_salida_ping(salida_ping):
    # Analizar la salida del comando ping para obtener la latencia
    latencia_match = re.search(r'Tiempo=(\d+)ms', salida_ping)
    
    if latencia_match:
        latencia = int(latencia_match.group(1))
        return latencia
    else:
        print('Error: El comando ping no devolvió información o la latencia no pudo ser extraída')
        return None

def medir_latencia_api(uri):
    try:
        # Medir el tiempo que se demora en enviar la solicitud y recibir la respuesta
        startTime = datetime.now()
        response = requests.get(uri)
        endTime = datetime.now()

        # Determinar el tiempo correspondiente a la latencia
        elapsedTime = (endTime - startTime).microseconds / 1000  # Convertir a milisegundos
        print(f'Latencia hacia {uri} (via API): {elapsedTime} ms')
        return elapsedTime

    except Exception as e:
        print(f'Error al realizar la solicitud a la API: {e}')
        return None

def obtener_datos_por_ip(ip):
    mac = None
    fabricante_mac = None
    search = Popen(["arp","-a",ip],stdout = PIPE, stderr= PIPE)
    var = ((search.communicate()[0].decode('latin-1').split('Tipo\r\n'))[1]).split('     ')
    MAC = var[2].strip(" ")
    IP = var[0].strip(" ")
    return MAC

def buscar_info_mac_en_arp(mac):
    try:
        # Utilizar arp-scan para buscar información en la tabla ARP
        proceso_arp_scan = subprocess.Popen(['arp-scan', '-q', mac], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        salida_arp_scan, error_arp_scan = proceso_arp_scan.communicate()

        if proceso_arp_scan.returncode == 0:
            # La búsqueda en la tabla ARP fue exitosa, analizar la salida para obtener información
            info_mac = obtener_info_mac_desde_salida_arp_scan(salida_arp_scan)
            return info_mac
        else:
            print(f'Error al buscar información en la tabla ARP: {error_arp_scan}')
            return None

    except Exception as e:
        print(f'Error: {e}')
        return None

def obtener_fabricante(salida_arp_scan):
    # Analizar la salida del comando arp-scan para obtener información
    fabricante_match = re.search(r'(.+) \(hex\)', salida_arp_scan)
    if fabricante_match:
        fabricante = fabricante_match.group(1)
        return fabricante
    else:
        return 'Not found'


def obtener_info_arp():
    try:
        # Ejecutar el comando arp -a para obtener la información de la tabla ARP
        proceso_arp = subprocess.Popen(['arp', '-a'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        salida_arp, error_arp = proceso_arp.communicate()

        if proceso_arp.returncode == 0:
            # La ejecución de arp -a fue exitosa, analizar la salida para obtener la información
            info_arp = analizar_salida_arp(salida_arp)
            return info_arp
        else:
            print(f'Error al ejecutar arp -a: {error_arp}')
            return None

    except Exception as e:
        print(f'Error: {e}')
        return None


def analizar_salida_arp(salida_arp):
    # Analizar la salida del comando arp -a para obtener información
    # Implementa tu lógica específica aquí según el formato de la salida de arp -a
    # Aquí se proporciona un ejemplo simple
    lineas_arp = salida_arp.split('\n')
    info_arp = []

    for linea in lineas_arp:
        if re.match(r'\d+\.\d+\.\d+\.\d+', linea):
            # Coincidencia de una línea con una IP en la salida
            partes = linea.split()
            if len(partes) == 3:
                ip = partes[0]
                mac = partes[1]
                vendor = partes[2]
                info_arp.append((ip, mac, vendor))

    return info_arp
    

def main(argv):
    ip = ''
    mac = ''
    arp_flag = False

    try:
        opts, args = getopt.getopt(argv, "hi:m:a", ["ip=", "mac=", "arp"])
    except getopt.GetoptError:
        print('Uso incorrecto. Verifica los parámetros.')
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print('Uso: python OUILookup.py --ip <IP> | --mac <MAC> | --arp')
            sys.exit()
        elif opt in ("-i", "--ip"):
            ip = arg
        elif opt in ("-m", "--mac"):
            mac = arg
        elif opt in ("-a", "--arp"):
            arp_flag = True

    if ip:
        if ip_pertenece_a_red(ip):
            latencia_ping = medir_latencia_ping(ip)
            mac_buscada = obtener_datos_por_ip(ip)
            fabricante = obtener_fabricante(mac_buscada)
            print("MAC ADDRESS:", mac_buscada)
            print("Fabricante:", fabricante)
            print("Tiempo de respuesta:", latencia_ping)
        else:
            print('Error: IP is outside the host network')

    elif mac:
        uri = f"https://api.maclookup.app/v2/macs/{mac.replace(':', '')}"
        latencia_api = medir_latencia_api(uri)
        info_mac_arp = obtener_fabricante(mac)
        print(f'MAC address : {mac}')
        print(f'Fabricante : {info_mac_arp}')
        print(f'Tiempo de respuesta hacia API: {latencia_api} ms')

    elif arp_flag:
        info_arp = obtener_info_arp()
        if info_arp:
            print('IP/MAC/Vendor:')
            for ip, mac, vendor in info_arp:
                print(f'{ip} / {mac} / {vendor}')
        else:
            print('Error al obtener información de la tabla ARP.')

    else:
        print('Uso: python OUILookup.py --ip <IP> | --mac <MAC> | --arp')


if __name__ == '__main__':
    main(sys.argv[1:])
