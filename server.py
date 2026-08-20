import sys
import uvicorn
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from core.server import app

if __name__ == "__main__":
    uvicorn.run("core.server:app", host="127.0.0.1", port=8080, reload=False)
