import asyncio
import json
import os

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

import checker
import mtproto
import store
from jobs import TERMINAL_STATES, jobs


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = FastAPI(title="Proxy Manager", version="2.0")
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
store.init_db()


class Filters(BaseModel):
    security: str = "any"
    only_tcp: bool = False
    require_sni: bool = False
    exclude_ws: bool = False
    countries: list[str] = Field(default_factory=list)
    excluded_countries: list[str] = Field(default_factory=list)


class JobRequest(BaseModel):
    count: int = Field(default=10, ge=1, le=100)
    source: str = "remote"
    text: str = ""
    workers: int = Field(default=8, ge=1, le=16)
    max_checks: int | None = Field(default=2000, ge=10, le=100000)
    enable_xray: bool = True
    speed: bool = False
    test_url: str = checker.DEFAULT_TEST_URL
    speed_url: str = checker.DEFAULT_SPEED_URL
    filters: Filters = Filters()


class SubRequest(BaseModel):
    name: str = "VLESS subscription"
    ttl_minutes: int | None = Field(default=None, ge=1, le=525600)


class TelegramRequest(BaseModel):
    limit: int = Field(default=80, ge=1, le=500)


def get_job(job_id):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Задание не найдено")
    return job


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    desktop = request.query_params.get("desktop") == "1"
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"xray": bool(checker.XRAY_BIN), "desktop": desktop},
    )


@app.get("/api/status")
def status():
    return {"ok": True, "xray": bool(checker.XRAY_BIN)}


@app.post("/api/jobs", status_code=202)
def create_job(req: JobRequest):
    if req.source not in ("remote", "custom"):
        raise HTTPException(status_code=422, detail="Неизвестный источник")
    if req.source == "custom" and not checker.parse_text(req.text):
        raise HTTPException(status_code=422, detail="В тексте нет корректных VLESS-ключей")
    if req.enable_xray and not checker.XRAY_BIN:
        raise HTTPException(status_code=409, detail="Xray не найден рядом с приложением или в PATH")
    countries = [code.strip().upper() for code in req.filters.countries]
    excluded = [code.strip().upper() for code in req.filters.excluded_countries]
    if any(len(code) != 2 or not code.isalpha() for code in countries + excluded):
        raise HTTPException(status_code=422, detail="Некорректный код страны")
    req.filters.countries = list(dict.fromkeys(countries))
    req.filters.excluded_countries = list(dict.fromkeys(excluded))
    overlap = set(req.filters.countries) & set(req.filters.excluded_countries)
    if overlap:
        raise HTTPException(
            status_code=422,
            detail=f"Страна одновременно разрешена и исключена: {', '.join(sorted(overlap))}",
        )
    cfg = req.model_dump()
    job = jobs.create(cfg)
    return {"id": job.id, "state": job.state}


@app.get("/api/jobs/{job_id}")
def read_job(job_id: str):
    return get_job(job_id).snapshot()


@app.get("/api/jobs/{job_id}/events")
async def job_events(job_id: str, request: Request, cursor: int = 0):
    job = get_job(job_id)
    last_event_id = request.headers.get("last-event-id")
    if last_event_id and last_event_id.isdigit():
        cursor = max(cursor, int(last_event_id))

    async def stream():
        current = cursor
        while True:
            if await request.is_disconnected():
                break
            events = job.events_after(current)
            for event in events:
                current = event["id"]
                body = json.dumps(event["data"], ensure_ascii=False)
                yield f"id: {current}\nevent: {event['type']}\ndata: {body}\n\n"
            if job.state in TERMINAL_STATES and not events:
                break
            yield ": ping\n\n"
            await asyncio.sleep(0.5)

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.post("/api/jobs/{job_id}/stop", status_code=202)
def stop_job(job_id: str):
    job = get_job(job_id)
    job.stop()
    return {"ok": True}


@app.get("/api/jobs/{job_id}/download", response_class=PlainTextResponse)
def download_job(job_id: str):
    job = get_job(job_id)
    keys = [item["info"]["raw"] for item in job.results]
    if not keys:
        raise HTTPException(status_code=404, detail="Рабочих ключей пока нет")
    return PlainTextResponse(
        "\n".join(keys),
        headers={"Content-Disposition": f'attachment; filename="vless-{job_id[:8]}.txt"'},
    )


@app.post("/api/jobs/{job_id}/subscriptions")
def create_subscription(job_id: str, req: SubRequest, request: Request):
    job = get_job(job_id)
    keys = [item["info"]["raw"] for item in job.results]
    if not keys:
        raise HTTPException(status_code=409, detail="Рабочих ключей пока нет")
    token, expires = store.create_subscription(keys, req.name, req.ttl_minutes)
    return {"url": str(request.base_url) + f"sub/{token}", "expires": expires}


@app.get("/sub/{token}", response_class=PlainTextResponse)
def subscription(token: str):
    item = store.get_subscription(token)
    if not item:
        raise HTTPException(status_code=404, detail="Подписка не найдена или истекла")
    return PlainTextResponse(
        item["body"],
        headers={"Profile-Update-Interval": "12"},
    )


@app.get("/api/working")
def working(limit: int = 100):
    return store.list_working(max(1, min(limit, 500)))


@app.post("/api/telegram/scan")
def scan_telegram(req: TelegramRequest):
    return mtproto.scan(req.limit)
