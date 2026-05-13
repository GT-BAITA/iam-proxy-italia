from pydantic import BaseModel


class OidcUser(BaseModel):
    class Config:
        extra = "allow"
