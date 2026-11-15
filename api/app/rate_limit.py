import math
import time
from collections import deque
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
import app.config as config_module


class RateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        requests_limit: int | None = None,
        window_seconds: int | None = None,
        trust_proxy_headers: bool | None = None,
        max_tracked_ips: int = 10_000,
    ):
        super().__init__(app)
        self._custom_requests_limit = requests_limit
        self._custom_window_seconds = window_seconds
        self._custom_trust_proxy_headers = trust_proxy_headers
        self.max_tracked_ips = max_tracked_ips
        self._history: dict[str, deque[float]] = {}

    @property
    def requests_limit(self) -> int:
        if self._custom_requests_limit is not None:
            return self._custom_requests_limit
        current_settings = getattr(config_module, "settings", None)
        return getattr(current_settings, "rate_limit_requests", 60)

    @property
    def window_seconds(self) -> int:
        if self._custom_window_seconds is not None:
            return self._custom_window_seconds
        current_settings = getattr(config_module, "settings", None)
        return getattr(current_settings, "rate_limit_window_seconds", 60)

    @property
    def trust_proxy_headers(self) -> bool:
        if self._custom_trust_proxy_headers is not None:
            return self._custom_trust_proxy_headers
        current_settings = getattr(config_module, "settings", None)
        return getattr(current_settings, "trust_proxy_headers", False)

    def _get_client_ip(self, request: Request) -> str:
        if self.trust_proxy_headers:
            forwarded = request.headers.get("x-forwarded-for")
            if forwarded:
                return forwarded.split(",")[0].strip()
        if request.client and request.client.host:
            return request.client.host
        return "127.0.0.1"

    def _cleanup(self, now: float) -> None:
        cutoff = now - float(self.window_seconds)
        expired_ips = []
        for ip, timestamps in list(self._history.items()):
            if isinstance(timestamps, deque):
                while timestamps and timestamps[0] < cutoff:
                    timestamps.popleft()
            else:
                timestamps = deque([t for t in timestamps if t >= cutoff])
                self._history[ip] = timestamps

            if not timestamps:
                expired_ips.append(ip)

        for ip in expired_ips:
            self._history.pop(ip, None)

        if len(self._history) > self.max_tracked_ips:
            sorted_by_oldest = sorted(
                self._history.keys(),
                key=lambda k: self._history[k][0] if self._history[k] else 0.0,
            )
            excess = len(self._history) - self.max_tracked_ips
            for ip in sorted_by_oldest[:excess]:
                self._history.pop(ip, None)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        ip = self._get_client_ip(request)
        now = time.monotonic()
        window = float(self.window_seconds)
        limit = self.requests_limit
        cutoff = now - window

        history = self._history.get(ip)
        if history is not None:
            while history and history[0] < cutoff:
                history.popleft()
            if not history:
                self._history.pop(ip, None)
                history = None

        if history is None:
            if len(self._history) >= self.max_tracked_ips:
                self._cleanup(now)
            history = deque()
            self._history[ip] = history

        if len(history) >= limit:
            oldest = history[0]
            retry_after = max(1, math.ceil(window - (now - oldest)))
            return JSONResponse(
                status_code=429,
                content={"detail": "Too Many Requests"},
                headers={"Retry-After": str(retry_after)},
            )

        history.append(now)
        return await call_next(request)
