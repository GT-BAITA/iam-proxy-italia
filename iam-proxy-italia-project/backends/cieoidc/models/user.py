from pydantic import BaseModel


class OidcUser(BaseModel):
    username: str
    first_name: str
    last_name: str
    email: str
    sub: str

    class Config:
        extra = "allow"
