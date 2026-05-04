import urllib.parse

def generate_google_dorks(holder_name: str) -> list[dict]:
    """
    Gera links de Google Dorks baseados no nome do detentor do ASN.
    """
    # Limpa o nome do holder para remover termos comuns e focar na marca
    clean_name = holder_name.split('-')[0].split(',')[0].strip()
    # Se o nome for muito genérico ou curto, tentamos usar o nome completo mas escapado
    search_term = f'"{clean_name}"'
    
    dorks_templates = [
        {
            "category": "Gerenciamento",
            "title": "Painéis de Admin / Login",
            "query": f'site:*.br {search_term} inurl:admin OR inurl:login OR inurl:manage'
        },
        {
            "category": "Infraestrutura",
            "title": "Configurações de Rede (Mikrotik/Cisco)",
            "query": f'{search_term} intitle:"index of" "config" OR "backup" OR "winbox" OR ".rsc"'
        },
        {
            "category": "Vazamentos",
            "title": "Arquivos Sensíveis (PDF/XLSX)",
            "query": f'site:*.br {search_term} filetype:pdf OR filetype:xlsx "topology" OR "network" OR "clients"'
        },
        {
            "category": "Segurança",
            "title": "Credenciais e Chaves",
            "query": f'{search_term} "password" OR "passwd" OR "key" filetype:txt OR filetype:env OR filetype:log'
        },
        {
            "category": "Hardware",
            "title": "Dispositivos IoT/OLT",
            "query": f'{search_term} intext:"Huawei" OR intext:"ZTE" OR intext:"FiberHome" inurl:login'
        }
    ]
    
    results = []
    for d in dorks_templates:
        encoded_query = urllib.parse.quote(d["query"])
        results.append({
            "category": d["category"],
            "title": d["title"],
            "dork": d["query"],
            "url": f"https://www.google.com/search?q={encoded_query}"
        })
        
    return results
