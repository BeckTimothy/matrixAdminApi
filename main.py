from fastapi import FastAPI
import re
import httpx
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Header

app = FastAPI()
security = HTTPBearer()

def sanitize(s):
    return re.sub(r'[^a-zA-Z0-9_]', '', s)

def transform_users(json):
    return json


@app.get("/admin-api/")
def read_root():
    return {"Hello": "World"}


@app.post("/admin-api/getUsers")
async def get_users(authorization: str = Header(...)):
    token = authorization.split(" ")[1]
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
