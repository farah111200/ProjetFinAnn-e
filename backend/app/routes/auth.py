from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, UserRole
from app.schemas import UserCreate, UserOut, Token
from app.core.security import hash_password, verify_password, create_access_token
from app.services.audit import log_action
from app.dependencies import get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(
        (User.username == payload.username) | (User.email == payload.email)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Nom d'utilisateur ou email déjà utilisé.")

    # Le tout premier compte créé devient automatiquement admin
    is_first_user = db.query(User).count() == 0
    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        organization=payload.organization,
        role=UserRole.ADMIN if is_first_user else UserRole.USER,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_action(db, action="user_registered", user_id=user.id, details=f"username={user.username}")
    return user


@router.post("/login", response_model=Token)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nom d'utilisateur ou mot de passe incorrect.",
        )
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Ce compte est désactivé.")

    token = create_access_token(data={"sub": str(user.id), "role": user.role.value})
    log_action(db, action="login", user_id=user.id, ip_address=request.client.host if request.client else None)
    return Token(access_token=token)
