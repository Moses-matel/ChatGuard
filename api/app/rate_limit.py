import time
from collections import defaultdict, deque
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
    ):
        super().__init__(app)
        self._custom_requests_limit = requests_limit
        self._custom_window_seconds = window_seconds
        self._history: dict[str, deque[float]] = defaultdict(deque)

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

    def _get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client and request.client.host:
            return request.client.host
        return "127.0.0.1"

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        ip = self._get_client_ip(request)
        now = time.monotonic()
        window = float(self.window_seconds)
        limit = self.requests_limit

        history = self._history[ip]
        cutoff = now - window

        while history and history[0] < cutoff:
            history.popleft()

        if len(history) >= limit:
            oldest = history[0]
            retry_after = max(1, int(window - (now - oldest)))
            return JSONResponse(
                status_code=429,
                content={"detail": "Too Many Requests"},
                headers={"Retry-After": str(retry_after)},
            )

        history.append(now)
        return await call_next(request)
