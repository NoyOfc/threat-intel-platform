from typing import Literal

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    service: str
    version: str
    database: Literal["ok", "error"]
    demo_mode: bool
