"""Owned browser-test fixture; never exposed outside loopback."""
import argparse
import uvicorn
from tests.test_target_scope import scope_lab

app, hits = scope_lab()

@app.get("/__requests")
async def requests():
    return [item for item in hits if not item[1].startswith("/__")]

@app.post("/__clear")
async def clear():
    hits.clear()
    return {"cleared": True}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="error")
