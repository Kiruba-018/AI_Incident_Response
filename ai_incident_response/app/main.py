from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers.router import app_router


app = FastAPI(title="AI Incident Response Agent", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

app.include_router(app_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000)