from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sqlite3

def init_db():
    con = sqlite3.connect("task1.db")
    cur = con.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    bio TEXT DEFAULT '')
                    ''')
    con.commit()
    con.close()

init_db()

app = FastAPI()

class User(BaseModel):
    username: str
    password: str

class Bio(BaseModel):
    bio: str

@app.post("/register")
async def register(user: User):
    con = sqlite3.connect("task1.db")
    cursor = con.cursor()

    cursor.execute("SELECT * FROM users WHERE username = ?", (user.username))
    if cursor.fetchone():
        con.close()
        raise HTTPException(status_code=400, detail="Username already exists")
    
    cursor.execute("INSERT INTO users(username, password) VALUES (?, ?)", (user.username, user.password))
    con.commit()
    con.close()

    return {"message": "User created successfully"}

@app.post("/login")
async def login(user: User):
    con = sqlite3.connect("task1.db")
    cursor = con.cursor()

    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (user.username, user.password))
    if not cursor.fetchone():
        con.close()
        raise HTTPException(status_code=400, detail="Invalid username or password")
    
    con.close()
    return {"message": "Login successful"}

@app.post("/update_bio")
async def updateBio(user: User, bio: Bio):
    con = sqlite3.connect("task1.db")
    cursor = con.cursor()

    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (user.username, user.password))
    if not cursor.fetchone():
        con.close()
        raise HTTPException(status_code=400, detail="Invalid username or password")
    
    cursor.execute("UPDATE users SET bio = ? WHERE username = ?", (bio.bio, user.username))
    con.commit()
    con.close()

    return {"message": "Bio updated successfully"}

@app.get("/get_bio")
async def getBio(username: str):
    con = sqlite3.connect("task1.db")
    cursor = con.cursor()

    cursor.execute("SELECT bio from users WHERE username = ?", (username))
    result = cursor.fetchone()
    con.close()

    if not result:
        con.close()
        raise HTTPException(status_code=400, detail="User not found")
    
    return {"username": username, "bio": result[0]}
    
