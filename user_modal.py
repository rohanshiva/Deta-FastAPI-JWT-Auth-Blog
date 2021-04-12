from pydantic import BaseModel

class AuthModal(BaseModel):
    username: str
    password: str

