"""Owned, in-process loopback lab, compatible with frozen executables."""
import asyncio
import socket
import threading
import uvicorn
from mock_target import app

class LocalTestbed:
    def __init__(self, target_app=None):
        self.app = target_app or app
        self.server = self.thread = self.socket = None

    async def start(self):
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        port = self.socket.getsockname()[1]
        self.socket.listen(128)
        config = uvicorn.Config(self.app, log_level="error", log_config=None, loop="asyncio", lifespan="off")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [self.socket]}, daemon=True)
        self.thread.start()
        for _ in range(100):
            if self.server.started:
                return f"http://127.0.0.1:{port}"
            if not self.thread.is_alive():
                break
            await asyncio.sleep(0.05)
        raise RuntimeError("로컬 실습 서버를 시작하지 못했습니다.")

    async def stop(self):
        if self.server:
            self.server.should_exit = True
        if self.thread:
            await asyncio.to_thread(self.thread.join, 5)
        if self.socket:
            self.socket.close()
