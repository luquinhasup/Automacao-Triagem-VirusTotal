# 🛡️ SOC Automator: Triagem de IoCs com VirusTotal API

## 🎯 Objetivo
Script em Python desenvolvido para automatizar a triagem de endereços IP suspeitos (Indicadores de Comprometimento - IoCs), integrando com a API do VirusTotal. Projeto focado em otimizar o fluxo de trabalho e a resposta a incidentes em operações de SOC (Blue Team).

## 🚨 O Problema
Durante a análise de logs de firewall, proxy ou alertas de SIEM, analistas de segurança frequentemente se deparam com listas extensas de endereços IP desconhecidos. A validação manual de cada IP em plataformas de Threat Intelligence consome um tempo crítico que deveria ser empregado na mitigação da ameaça.

## 💡 A Solução e Metodologia
Esta ferramenta lê arquivos de log e realiza uma consulta automatizada e **estática** na base de dados do VirusTotal. 
A análise estática garante que o ambiente de defesa permaneça seguro, pois o script apenas consulta a reputação do indicador na API do provedor, sem executar ou interagir com a ameaça real. O resultado reduz o tempo de triagem de minutos para poucos segundos, destacando imediatamente os IPs maliciosos.

## 🛠️ Pré-requisitos e Tecnologias
* Python 3.x
* Biblioteca `requests` (para realizar as requisições à API)
* Biblioteca `python-dotenv` (para ocultar e gerenciar a chave de API com segurança)

Para instalar as dependências, execute:
`pip install requests python-dotenv`

## 🚀 Como Usar

1. Clone este repositório para a sua máquina local:
`git clone https://github.com/SeuUsuario/NomeDoRepositorio.git`

2. Crie um arquivo chamado `.env` na raiz da pasta do projeto e adicione a sua chave do VirusTotal:
`VT_API_KEY=sua_chave_api_aqui`

3. Execute o script passando o arquivo de texto com os IPs a serem analisados:
`python seu_script.py lista_de_ips.txt`

## ⚠️ Boas Práticas de Segurança
Este repositório foi configurado com um arquivo `.gitignore` para garantir que o arquivo `.env` (que contém a API Key) **não** seja enviado para o GitHub, prevenindo o vazamento de credenciais.
