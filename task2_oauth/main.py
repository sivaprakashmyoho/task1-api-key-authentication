
import os
import secrets
import httpx

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = FastAPI()

# GitHub OAuth configuration
CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"


# Step 1: Redirect user to GitHub
@app.get("/login")
async def login():

    if not CLIENT_ID or not CLIENT_SECRET or not REDIRECT_URI:
        raise HTTPException(
            status_code=500,
            detail="OAuth configuration missing"
        )

    state = secrets.token_urlsafe(32)

    response = RedirectResponse(
        url=f"{GITHUB_AUTHORIZE_URL}?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=read:user&state={state}",
        status_code=302
    )

    response.set_cookie(
        key="oauth_state",
        value=state,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=300
    )

    return response


# Step 2: GitHub callback
@app.get("/callback")
async def callback(request: Request, code: str = None, state: str = None):

    # Verify CSRF state
    saved_state = request.cookies.get("oauth_state")

    if not state or not saved_state or not secrets.compare_digest(state, saved_state):
        raise HTTPException(
            status_code=403,
            detail="Invalid OAuth state"
        )

    if not code:
        raise HTTPException(
            status_code=400,
            detail="Authorization code missing"
        )

    # Step 3: Exchange authorization code for access token
    async with httpx.AsyncClient() as client:

        token_response = await client.post(
            GITHUB_TOKEN_URL,
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "code": code,
                "redirect_uri": REDIRECT_URI
            },
            headers={
                "Accept": "application/json"
            }
        )

        token_data = token_response.json()

        if token_response.status_code != 200 or "access_token" not in token_data:
            raise HTTPException(
                status_code=400,
                detail="Failed to obtain access token"
            )

        access_token = token_data["access_token"]

        # Step 4: Get GitHub user information
        user_response = await client.get(
            GITHUB_USER_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json"
            }
        )

        if user_response.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail="Failed to fetch GitHub user"
            )

        user_data = user_response.json()

    username = user_data["login"]

    # Print masked access token and username
    print("Token received (masked): " + access_token[:4] + "****")
    print("Logged in as:", username)

    response = {
        "message": "GitHub OAuth login successful",
        "username": username,
        "token_received": "Yes (masked in terminal)"
    }

    redirect_response = __import__(
        "fastapi.responses", fromlist=["JSONResponse"]
    ).JSONResponse(content=response)

    redirect_response.delete_cookie("oauth_state")

    return redirect_response
