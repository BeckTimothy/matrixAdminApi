from fastapi import FastAPI, Depends
import re
import httpx
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Header
import logging 
from pydantic import BaseModel
import hmac, hashlib


app = FastAPI()
security = HTTPBearer()
logging.basicConfig(level=logging.INFO)
shared_secret = SECRETKEY

class NewUser(BaseModel):
    username: str
    password: str

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


def generate_mac(nonce, user, password, admin=False, user_type=None):
    mac = hmac.new(
      key=shared_secret.encode("utf-8"),
      digestmod=hashlib.sha1,
    )

    mac.update(nonce.encode('utf8'))
    mac.update(b"\x00")
    mac.update(user.encode('utf8'))
    mac.update(b"\x00")
    mac.update(password.encode('utf8'))
    mac.update(b"\x00")
    mac.update(b"admin" if admin else b"notadmin")
    if user_type:
        mac.update(b"\x00")
        mac.update(user_type.encode('utf8'))

    return mac.hexdigest()


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


@app.post("/admin-api/newUser")
async def new_user(user: NewUser, credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    
    headers = {
        "Authorization": f"Bearer {sanitize(token)}",
        "Content-Type": "application/json"
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get("http://localhost:8008/_synapse/admin/v1/register", headers=headers)
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=str(e))


    # Ensure it's JSON
    try:
        data = response.json()
    except ValueError:
        raise HTTPException(status_code=502, detail="Upstream did not return JSON")

    if not isinstance(data, dict) or "nonce" not in data:
        return data  # fallback if structure is unexpected

    data['username'] = sanitize(user.username)
    data['password'] = sanitize(user.password)
    data['mac'] = generate_mac(data['nonce'], data['username'], data['password'])

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.post("http://localhost:8008/_synapse/admin/v1/register", 
                                         headers=headers, 
                                         json=data)
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=str(e))


    return response.json()


class User(BaseModel):
    username: str

@app.post("/admin-api/deactivate")
async def delete_user(user: User, credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials

    headers = {
        "Authorization": f"Bearer {sanitize(token)}",
        "Content-Type": "application/json"
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(f"http://localhost:8008/_synapse/admin/v1/deactivate/@{sanitize(user.username)}:matrix.lowtechsanonymous.com", 
                                        headers=headers,
                                        json={"erase": True})
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=str(e))

    return response.json()




