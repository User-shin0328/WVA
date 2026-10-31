import pytest_asyncio
import httpx
import dashboard.server as dashboard

@pytest_asyncio.fixture
async def client(monkeypatch, tmp_path):
    monkeypatch.setattr(dashboard, "state", dashboard.DashboardState())
    monkeypatch.setenv("WVA_DATA_DIR", str(tmp_path))
    async with dashboard.app.router.lifespan_context(dashboard.app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=dashboard.app), base_url="http://127.0.0.1") as client:
            yield client
