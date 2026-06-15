import threading
import time
import httpx
import logging
import asyncio

logger = logging.getLogger(__name__)

class W.H.AgentClient:
    def __init__(self, agent_id: str, posture_url: str = "http://localhost:8080"):
        self.agent_id = agent_id
        self.posture_url = posture_url
        self._mode = "visibility"
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._poll_mode, daemon=True)
        self._client = httpx.Client()
        self._async_client = httpx.AsyncClient()
        self._thread.start()

    @property
    def mode(self) -> str:
        with self._lock:
            return self._mode

    def _poll_mode(self):
        while not self._stop_event.is_set():
            try:
                res = self._client.get(f"{self.posture_url}/agents/{self.agent_id}/envelope/mode", timeout=5.0)
                if res.status_code == 200:
                    data = res.json()
                    new_mode = data.get("mode", "visibility")
                    with self._lock:
                        self._mode = new_mode
            except Exception as e:
                logger.error(f"Failed to poll W.H.Agent envelope mode: {e}")
            
            # Poll every 60 seconds
            self._stop_event.wait(60.0)

    def dispatch_event(self, event_type: str, payload: dict):
        """Dispatch telemetry asynchronously, gracefully handling both async and sync contexts."""
        try:
            loop = asyncio.get_running_loop()
            
            async def _send_async():
                try:
                    await self._async_client.post(
                        f"{self.posture_url}/ingest",
                        json={"agentId": self.agent_id, "type": event_type, "payload": payload},
                        timeout=5.0
                    )
                except Exception as e:
                    logger.error(f"W.H.Agent HTTP async dispatch failed: {e}")
            
            loop.create_task(_send_async())
        except RuntimeError:
            # No running event loop, fallback to threading + sync client
            def _send_sync():
                try:
                    self._client.post(
                        f"{self.posture_url}/ingest",
                        json={"agentId": self.agent_id, "type": event_type, "payload": payload},
                        timeout=5.0
                    )
                except Exception as e:
                    logger.error(f"W.H.Agent HTTP dispatch failed: {e}")
            
            threading.Thread(target=_send_sync, daemon=True).start()

    def shutdown(self):
        self._stop_event.set()
        self._thread.join(timeout=2.0)
        self._client.close()
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._async_client.aclose())
        except RuntimeError:
            asyncio.run(self._async_client.aclose())

