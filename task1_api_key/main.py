
import os
from fastapi import FastAPI, Header, HTTPException, Depends
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = FastAPI()

# Read API key from .env
API_KEY = os.getenv("API_KEY")


# Reusable API key authentication dependency
def verify_api_key(x_api_key: str = Header(default=None)):

    if x_api_key is None:
        raise HTTPException(
            status_code=401,
            detail="API key missing"
        )

    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=403,
            detail="Invalid API key"
        )

    return x_api_key


# Endpoint 1
@app.get("/secure-data")
def get_secure_data(api_key: str = Depends(verify_api_key)):
    return {"data": "secret"}


# Endpoint 2
@app.get("/secure-profile")
def get_secure_profile(api_key: str = Depends(verify_api_key)):
    return {"name": "Arun Kumar", "role": "Developer"}
