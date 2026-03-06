import time
import os
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel, Field, field_validator
import uvicorn
import re
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

from core.asn_lookup import get_asn_prefixes
from core.passive_collector import collect_passive_data
from core.risk_engine import calculate_risk
from core.db import init_db, save_scan

from contextlib import asynccontextmanager

def is_docker():
    path = '/proc/self/cgroup'
    return (
        os.path.exists('/.dockerenv') or
        os.path.isfile(path) and any('docker' in line for line in open(path))
    )

RUNNING_IN_DOCKER = is_docker()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="ISP Risk Exposure Scanner", lifespan=lifespan)

app.mount("/static", StaticFiles(directory="static"), name="static")

class AnalyzeRequest(BaseModel):
    asn: str = Field(..., description="ASN a ser analisado (ex: AS12345 ou 12345)")

    @field_validator('asn')
    @classmethod
    def validate_asn(cls, v: str) -> str:
        v = v.strip().upper()
        if not re.match(r'^(AS)?\d+$', v):
            raise ValueError("ASN deve conter apenas números, opcionalmente prefixados por 'AS'.")
        if not v.startswith("AS"):
            v = f"AS{v}"
        return v

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    return FileResponse("static/index.html")

@app.get("/api/env")
async def get_env_info():
    return {"is_docker": RUNNING_IN_DOCKER}

@app.websocket("/api/ws/analyze")
async def websocket_analyze(websocket: WebSocket):
    await websocket.accept()
    try:
        data = await websocket.receive_json()
        asn = data.get("asn", "").strip().upper()
        
        if not asn:
            await websocket.send_json({"type": "error", "message": "ASN é obrigatório."})
            return
            
        if not re.match(r'^(AS)?\d+$', asn):
            await websocket.send_json({"type": "error", "message": "Formato de ASN inválido."})
            return

        if not asn.startswith("AS"):
            asn = f"AS{asn}"
            
        start_time = time.time()
        await websocket.send_json({"type": "status", "message": f"[*] Iniciando análise para o {asn}..."})
        
        prefixes = await get_asn_prefixes(asn)
        await websocket.send_json({"type": "status", "message": f"[*] Descobertos {len(prefixes)} blocos IPv4 associados."})
        
        async def progress_cb(msg: str):
            await websocket.send_json({"type": "status", "message": msg})
            
        collected_data = await collect_passive_data(prefixes, asn, progress_cb)
        await websocket.send_json({"type": "status", "message": f"[*] Coletadas {len(collected_data)} exposições possíveis. Finalizando cálculos..."})
        
        end_time = time.time()
        total_time = end_time - start_time
        
        results = calculate_risk(collected_data, asn, total_time)
        
        await asyncio.to_thread(save_scan, asn, results["metrics"]["total_ips"], results["metrics"]["total_score"], results)
        
        await websocket.send_json({"type": "complete", "data": results})
        
    except WebSocketDisconnect:
        logger.info("Cliente desconectado")
    except Exception as e:
        logger.error(f"Erro no WebSocket: {e}")
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except:
            pass

@app.post("/api/analyze")
async def analyze_asn(req: AnalyzeRequest):
    start_time = time.time()
    asn = req.asn
    prefixes = await get_asn_prefixes(asn)
    collected_data = await collect_passive_data(prefixes, asn)
    end_time = time.time()
    total_time = end_time - start_time
    results = calculate_risk(collected_data, asn, total_time)
    await asyncio.to_thread(save_scan, asn, results["metrics"]["total_ips"], results["metrics"]["total_score"], results)
    return results

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
