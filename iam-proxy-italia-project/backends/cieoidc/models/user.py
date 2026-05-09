from pydantic import BaseModel, ConfigDict
from typing import Optional


class OidcUser(BaseModel):
    sub: str
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    fiscal_number: Optional[str] = None

    class Config:
        extra = "allow"
