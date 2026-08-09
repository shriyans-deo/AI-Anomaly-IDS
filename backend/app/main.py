from fastapi import FastAPI

app = FastAPI(title="AI Anomaly IDS")


@app.get("/")
def home():
    return {"message": "AI Anomaly IDS Backend is running!"}