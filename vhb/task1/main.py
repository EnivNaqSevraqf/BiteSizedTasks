from typing import Annotated, Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import Field, Session, SQLModel, create_engine, select # type: ignore

sqlite_file_name = "users.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session

SessionDep = Annotated[Session, Depends(get_session)]

app = FastAPI()

# Users model, where the user's name, email, hashed_password, bio would be stored.
class UserBase(SQLModel):
    name: str = Field(index=True)
    bio: str | None

class User(UserBase, table=True):
    username: str = Field(index=True, unique=True, primary_key=True)
    hashed_password: str

class UserCreate(UserBase):
    username: str
    password: str

class UserLogin(SQLModel):
    username: str
    password: str

class UserEdit(SQLModel):
    name: str | None
    bio: str | None

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

def get_user(username: str, session: SessionDep): # type: ignore
    statement = select(User).where(User.username == username)
    return session.exec(statement).first()

def fake_hash_password(password: str):
    return "fakehashed" + password

def fake_decode_token(token: str, session: SessionDep): # type: ignore
    return get_user(token, session)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    with Session(engine) as session:
        user = fake_decode_token(token, session)
    
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/register/")
def register(new_user: UserCreate, session: SessionDep): # type: ignore
    hashed_password = fake_hash_password(new_user.password)
    db_user = User(username=new_user.username, name=new_user.name, bio=new_user.bio, hashed_password=hashed_password)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return {"message": "User registered successfully"}

@app.post("/token")
def login(session: SessionDep, form_data: OAuth2PasswordRequestForm = Depends()): # type: ignore
    user = get_user(form_data.username, session)
    
    if not user or fake_hash_password(form_data.password) != user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    return {"access_token": user.username, "token_type": "bearer"}

@app.put("/edit-details")
@app.put("/edit-details")
def edit_details(session: SessionDep, edit_user: UserEdit, current_user: User = Depends(get_current_active_user)): # type: ignore
    user_db = session.get(User, current_user.username)
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")
    user_data = edit_user.model_dump(exclude_unset=True)
    user_db.sqlmodel_update(user_data)
    session.add(user_db)
    session.commit()
    session.refresh(user_db)
    return {"message": f"User details of {user_db.name} updated successfully"}

@app.get("/me")
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user
