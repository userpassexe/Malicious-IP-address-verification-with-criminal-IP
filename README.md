# Malicious-IP-address-verification-with-criminal-IP
This is a code developed in python that seeks to facilitate the analysis of IP addresses possibly reported as malicious. You need your API KEY, whether it is a criminal IP or a total virus.
##########DOOKU#############

@author: Dooku
"""
import pandas as pd
import requests

def check_ip(ip):
    # Llave de la API de VirusTotal
    api_key = 'TU API KEY'
    # URL de la API de VirusTotal para la verificación de direcciones IP
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90'
    # Parámetros de la solicitud HTTP
    params = {'apikey': api_key}

    try:
        # Realizar la solicitud HTTP GET
        response = requests.get(url, params=params)
        # Verificar el código de estado de la respuesta
        if response.status_code == 200:
            # Convertir la respuesta JSON a un diccionario
            result = response.json()
            # Devolver el resultado de la verificación
            return result
        else:
            # Si hay un error en la respuesta, imprimir el código de estado
            print(f'Error al verificar la dirección IP {ip}. Código de estado: {response.status_code}')
    except Exception as e:
        # Si ocurre un error durante la solicitud, imprimir el mensaje de error
        print(f'Error al verificar la dirección IP {ip}: {str(e)}')

def main():
    # Leer el archivo .xlsx
    file_path = r'direccion del archivo'
    df = pd.read_excel(file_path)

    # Verificar cada dirección IP en el archivo
    for ip in df['Dirección IP']:
        result = check_ip(ip)
        if result:
            # Imprimir el resultado de la verificación
            print(result)

if __name__ == '__main__':
    main()
