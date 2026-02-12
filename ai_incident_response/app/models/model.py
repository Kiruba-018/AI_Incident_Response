from pydantic import BaseModel, EmailStr, Field
from pydantic_settings import BaseSettings



class ConfigSettings(BaseSettings):
    time_window: int = Field(..., env="TIME_WINDOW")
    port_threshold: int = Field(..., env="PORT_THRESHOLD")
    security_team_email: EmailStr = Field(..., env="SECURITY_TEAM_EMAIL")
    sender_email: EmailStr = Field(..., env="SENDER_EMAIL")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "allow"

settings = ConfigSettings()