import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pathlib import Path

app = FastAPI(title="AgentWazuh SOC Map Level 1 & Live Streamer (Port 9090)", version="2.0")

BASE_DIR = Path(__file__).resolve().parent
web_dir = BASE_DIR / "web"

# Mount /static
if web_dir.exists():
    app.mount("/static", StaticFiles(directory=str(web_dir)), name="static")

@app.get("/", response_class=HTMLResponse)
def get_map():
    map_file = web_dir / "network_map.html"
    if map_file.exists():
        return HTMLResponse(content=map_file.read_text(encoding="utf-8"))
    index_file = web_dir / "index.html"
    if index_file.exists():
        return HTMLResponse(content=index_file.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>WazuhSim Live Network Map & Streamer (Port 9090)</h1>")

# Fallback for static files requested without /static/ prefix
@app.get("/{filename}")
def get_root_file(filename: str):
    file_path = web_dir / filename
    if file_path.exists() and file_path.is_file():
        return FileResponse(file_path)
    return HTMLResponse("File not found", status_code=404)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9090, reload=False)
