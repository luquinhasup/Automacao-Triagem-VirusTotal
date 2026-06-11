import requests
import time
import sys
import os
from dotenv import load_dotenv

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

print("Argumentos recebidos:")
print(sys.argv)

# =========================
# SUA API KEY (Puxando do .env com segurança)
# =========================
API_KEY = os.getenv("VT_API_KEY")

headers = {
    "x-apikey": API_KEY
}

# =========================
# VERIFICA ARGUMENTOS
# =========================
if len(sys.argv) < 2:
    print("\n❌ Uso correto:")
    print("python3 vt_lookup_interactive.py IPS.txt")
    sys.exit()

arquivo_ips = sys.argv[1]

# =========================
# LÊ O ARQUIVO TXT
# =========================
try:
    with open(arquivo_ips, "r") as file:
        ips = [linha.strip() for linha in file if linha.strip()]

except FileNotFoundError:
    print(f"\n❌ Arquivo '{arquivo_ips}' não encontrado.")
    sys.exit()

except Exception as erro:
    print(f"\n❌ Erro ao abrir arquivo: {erro}")
    sys.exit()

# =========================
# FUNÇÃO CONSULTA VT
# =========================
def consultar_ip(ip):

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    try:
        response = requests.get(url, headers=headers)

    except requests.exceptions.ConnectionError:
        print(f"\n❌ Sem conexão com a internet ao consultar {ip}")
        return

    except requests.exceptions.Timeout:
        print(f"\n⏳ Tempo esgotado ao consultar {ip}")
        return

    except requests.exceptions.RequestException as erro:
        print(f"\n❌ Erro na requisição do IP {ip}")
        print(f"Detalhes: {erro}")
        return

    # =========================
    # RESPOSTAS DA API
    # =========================
    if response.status_code == 200:

        try:
            data = response.json()

            stats = data["data"]["attributes"]["last_analysis_stats"]

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            print("\n==============================")
            print(f"🔎 IP analisado: {ip}")
            print("==============================")
            print(f"⚠️ Malicioso : {malicious}")
            print(f"🟡 Suspeito  : {suspicious}")
            print(f"✅ Seguro    : {harmless}")
            print(f"❔ Não detectado: {undetected}")

            if malicious > 0:
                print("\n🚨 IP CONSIDERADO MALICIOSO")
            elif suspicious > 0:
                print("\n⚠️ IP SUSPEITO")
            else:
                print("\n✅ Sem detecções relevantes")

        except Exception as erro:
            print(f"\n❌ Erro ao processar resposta do IP {ip}")
            print(f"Detalhes: {erro}")

    elif response.status_code == 401:
        print(f"\n❌ API Key inválida ou bloqueada")
        print("Verifique sua chave da API do VirusTotal.")

    elif response.status_code == 404:
        print(f"\n⚠️ IP {ip} não encontrado no VirusTotal")

    elif response.status_code == 429:
        print(f"\n⏳ Limite de requisições excedido")
        print("A API gratuita permite apenas 4 consultas por minuto.")

    else:
        print(f"\n❌ Erro ao consultar {ip}")
        print(f"Status Code: {response.status_code}")
        print(f"Resposta: {response.text}")

# =========================
# LOOP PRINCIPAL
# =========================
print("\n🚀 Iniciando análise dos IPs...\n")

for ip in ips:

    consultar_ip(ip)

    print("\n⏳ Aguardando 15 segundos...")
    time.sleep(15)

print("\n✅ Análise finalizada.")
