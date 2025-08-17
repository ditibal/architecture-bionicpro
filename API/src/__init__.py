from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
import jwt
from jwt import PyJWKClient
from pydantic import BaseModel
from typing import List
import random
import uuid
from datetime import datetime

app = FastAPI()

# Настройки CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Настройки Keycloak
KEYCLOAK_URL = "http://keycloak:8080"
KEYCLOAK_REALM = "reports-realm"
JWKS_URL = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
REQUIRED_ROLE = "prothetic_user"

security = HTTPBearer()

# Модель отчета
class Report(BaseModel):
    id: str
    title: str
    created_at: str
    status: str
    value: float

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        jwks_client = PyJWKClient(JWKS_URL)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            options={"verify_aud": False}
        )

        if REQUIRED_ROLE not in payload.get("realm_access", {}).get("roles", []):
            raise HTTPException(status_code=403, detail="Access denied")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

@app.get("/reports", response_model=List[Report])
def get_reports(user: dict = Depends(verify_token)):
    # Генерация случайных отчетов
    statuses = ["pending", "completed", "failed"]
    reports = []

    for i in range(5):
        report = Report(
            id=str(uuid.uuid4()),
            title=f"Report {i+1}",
            created_at=datetime.now().isoformat(),
            status=random.choice(statuses),
            value=round(random.uniform(100, 1000), 2)
        )
        reports.append(report)

    return reports