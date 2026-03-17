from fastapi import FastAPI, Depends
import re
import httpx
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Header
import logging 

app = FastAPI()
security = HTTPBearer()
logging.basicConfig(level=logging.INFO)

def sanitize(s):
    return re.sub(r'[^a-zA-Z0-9_]', '', s)

def transform_users(data):
    """
    Take the Synapse users JSON and return only:
    name, displayname, last_seen_ts
    """
    if not isinstance(data, dict) or "users" not in data:
        return data  # fallback if structure is unexpected

    simplified = []
    for user in data["users"]:
        simplified.append({
            "name": user.get("name"),
            "displayname": user.get("displayname"),
            "last_seen_ts": user.get("last_seen_ts")
        })

    return {"users": simplified, "total": len(simplified)}

@app.get("/admin-api/")
def read_root():
    return {"Hello": "World"}


@app.post("/admin-api/getUsers")
async def get_users(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials

    headers = {
        "Authorization": f"Bearer {sanitize(token)}"
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get("http://localhost:8008/_synapse/admin/v2/users", headers=headers)
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=str(e))


    # Ensure it's JSON
    try:
        data = response.json()
    except ValueError:
        raise HTTPException(status_code=502, detail="Upstream did not return JSON")

    mutated = transform_users(data)

    return mutated

