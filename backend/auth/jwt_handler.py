from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from auth import authenticate, create_token, get_user_from_token

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str

@router.post("/token", response_model=TokenResponse)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    OAuth2 compatible token login, getting an access token for future requests.
    """
    user_dict = authenticate(form_data.username, form_data.password)
    if not user_dict:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    role = user_dict.get("role", "analyst")
    tenant_id = user_dict.get("tenant_id", "default")
    
    access_token = create_token(
        username=form_data.username, 
        role=role, 
        tenant_id=tenant_id
    )
    
    return {"access_token": access_token, "token_type": "bearer", "role": role}
