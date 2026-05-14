from pydantic import BaseModel


class OidcUser(BaseModel):
    # Removido os atributos definidos para permitir que mais informações de usuario sejam
    # obtidas e repassadas
    class Config:
        extra = "allow"
