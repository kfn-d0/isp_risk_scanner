def calculate_risk(collected_data: list[dict], asn: str, total_time: float, subdomains_count: int = 0) -> dict:
    risk_weights = {
        3389: 10,
        445: 10,
        3306: 10,
        21: 5,
        25: 5,
        22: 3,
        23: 10,
        80: 1,
        443: 1,
        8080: 2,
        8443: 2
    }
    
    risk_labels = {
        10: "Alto",
        5: "Médio",
        3: "Baixo",
        2: "Baixo",
        1: "Baixo"
    }

    port_distribution = {}
    prefix_scores = {}
    total_score = 0
    services_count = {}
    total_ips = set()

    for item in collected_data:
        port = item.get("port")
        prefix = item.get("prefix")
        service = item.get("service")
        ip = item.get("ip")
        
        vulns_count = item.get("vulns_count", 0)
        has_otx = item.get("has_otx", False)

        total_ips.add(ip)

        weight = risk_weights.get(port, 2)
        
        # score de ameacas
        if vulns_count > 0:
            weight = max(weight, 10)
        if has_otx:
            weight = max(weight, 10)

        item["risk_level"] = "Alto" if weight >= 10 else "Médio" if weight >= 5 else "Baixo"
        item["score"] = weight

        port_distribution[port] = port_distribution.get(port, 0) + 1
        if service and service != "Unknown":
            services_count[service] = services_count.get(service, 0) + 1

        if prefix not in prefix_scores:
            prefix_scores[prefix] = 0
        prefix_scores[prefix] += weight
        
        total_score += weight

    # Bônus de risco por subdomínios (indica maior superfície de ataque)
    subdomain_bonus = min(subdomains_count * 2, 50) # Cap em 50 pontos
    total_score += subdomain_bonus

    sorted_prefixes = sorted(prefix_scores.items(), key=lambda x: x[1], reverse=True)
    top_services = sorted(services_count.items(), key=lambda x: x[1], reverse=True)[:10]

    unique_ips_count = len(total_ips)
    avg_score_per_prefix = total_score / len(prefix_scores) if prefix_scores else 0

    return {
        "asn": asn,
        "metrics": {
            "total_time_seconds": round(total_time, 2),
            "total_exposures": len(collected_data),
            "total_ips": unique_ips_count,
            "total_score": total_score,
            "avg_score_per_prefix": round(avg_score_per_prefix, 2)
        },
        "port_distribution": port_distribution,
        "top_prefixes": [{"prefix": p, "score": s} for p, s in sorted_prefixes[:10]],
        "top_services": [{"service": s, "count": c} for s, c in top_services],
        "raw_data": collected_data
    }
