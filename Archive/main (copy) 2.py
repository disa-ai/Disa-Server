from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import mysql.connector
from passlib.context import CryptContext
import jwt
from jwt import PyJWTError
from datetime import datetime, timedelta
from typing import Optional, List

# FastAPI app
app = FastAPI()

# JWT Settings
SECRET_KEY = "yashnayak"  # Replace with a secure random key in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Token expiration time

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# User model
class User(BaseModel):
    id: Optional[int]
    name: str
    email: str
    mobile_number: str
    corporate_code: Optional[str]
    password: str

# Message model
class Message(BaseModel):
    message: str

# MySQL Connection
mydb = None

# Function to establish MySQL connection
def get_mysql_connection():
    global mydb
    if mydb is None or not mydb.is_connected():
        mydb = mysql.connector.connect(
            host="srv983.hstgr.io",
            user="u763609283_disa",
            password="$2au8dUNK",
            database="u763609283_disa"
        )
    return mydb

# Authenticate user
def authenticate_user(email: str, password: str, db_user):
    if db_user and pwd_context.verify(password, db_user['password']):
        return db_user
    return None

# Create access token
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Signup
@app.post("/signup")
def signup(user: User):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor()
        hashed_password = pwd_context.hash(user.password)
        sql = "INSERT INTO users (name, email, mobile_number, corporate_code, password) VALUES (%s, %s, %s, %s, %s)"
        val = (user.name, user.email, user.mobile_number, user.corporate_code, hashed_password)
        cursor.execute(sql, val)
        mydb.commit()
        return {"message": "User created successfully"}
    except mysql.connector.Error as err:
        return {"error": str(err)}
    finally:
        if 'cursor' in locals():
            cursor.close()

# Signin
@app.post("/signin")
def signin(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)
        cursor.execute(f"SELECT * FROM users WHERE email = '{form_data.username}'")
        user = cursor.fetchone()
        if not user or not authenticate_user(form_data.username, form_data.password, user):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

        access_token = create_access_token(data={"sub": user["email"]})
        return {"access_token": access_token, "token_type": "bearer"}
    except mysql.connector.Error as err:
        return {"error": str(err)}
    finally:
        if 'cursor' in locals():
            cursor.close()

# Dependency to verify JWT token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/signin")

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return email
    except PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# Get current user
@app.get("/users/me")
def read_users_me(current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)
        cursor.execute(f"SELECT * FROM users WHERE email = '{current_user_email}'")
        user = cursor.fetchone()
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        return user
    except mysql.connector.Error as err:
        return {"error": str(err)}
    finally:
        if 'cursor' in locals():
            cursor.close()

# List users with the same corporate code
@app.get("/users/{user_id}/list", response_model=List[User])
def list_users_by_corporate_code(user_id: int, current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)
        cursor.execute(f"SELECT * FROM users WHERE corporate_code = (SELECT corporate_code FROM users WHERE id = {user_id}) AND id != {user_id}")
        users = cursor.fetchall()
        return users
    except mysql.connector.Error as err:
        return {"error": str(err)}
    finally:
        if 'cursor' in locals():
            cursor.close()


# Create a new chat
@app.post("/chats", response_model=dict)
def create_chat(current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor()
        created_at = datetime.utcnow()
        creator_id = get_user_id_by_email(current_user_email)
        if creator_id is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Creator not found")

        # Create chat
        sql_create_chat = "INSERT INTO chats (creator_id, created_at, updated_at) VALUES (%s, %s, %s)"
        val_create_chat = (creator_id, created_at, created_at)
        cursor.execute(sql_create_chat, val_create_chat)
        chat_id = cursor.lastrowid

        # Add creator to chat participants
        sql_add_creator_to_chat = "INSERT INTO chat_participants (chat_id, user_id) VALUES (%s, %s)"
        val_add_creator_to_chat = (chat_id, creator_id)
        cursor.execute(sql_add_creator_to_chat, val_add_creator_to_chat)

        mydb.commit()
        return {"chat_id": chat_id, "message": "Chat created successfully"}
    except mysql.connector.Error as err:
        return {"error": str(err)}
    finally:
        if 'cursor' in locals():
            cursor.close()


# Send message to chat
# Send message to chat
@app.post("/chats/{chat_id}/send-message", status_code=status.HTTP_201_CREATED)
def send_message_to_chat(chat_id: int, message: Message, current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor()
        sender_id = get_user_id_by_email(current_user_email)
        if sender_id is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sender not found")

        sql_send_message = "INSERT INTO messages (chat_id, sender_id, message, sent_at) VALUES (%s, %s, %s, %s)"
        val_send_message = (chat_id, sender_id, message.message, datetime.utcnow())
        cursor.execute(sql_send_message, val_send_message)

        mydb.commit()
        return {"message": "Message sent successfully"}
    except mysql.connector.Error as err:
        return {"error": str(err)}
    finally:
        if 'cursor' in locals():
            cursor.close()


# Add user to chat
@app.post("/chats/{chat_id}/add-user/{user_id}", status_code=status.HTTP_200_OK)
def add_user_to_chat(chat_id: int, user_id: int, current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor()
        # Check if the chat exists and the current user is a participant
        if not is_chat_participant(chat_id, current_user_email):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not a participant of this chat")

        # Check if the user to be added exists
        if not is_user_exist(user_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        # Check if the user is already a participant of the chat
        if is_chat_participant(chat_id, get_user_email_by_id(user_id)):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User is already a participant of this chat")

        # Add user to the chat
        sql = "INSERT INTO chat_participants (chat_id, user_id) VALUES (%s, %s)"
        val = (chat_id, user_id)
        cursor.execute(sql, val)

        mydb.commit()
        return {"message": "User added to chat successfully"}
    except mysql.connector.Error as err:
        return {"error": str(err)}
    finally:
        if 'cursor' in locals():
            cursor.close()

# Check if the user exists
def is_user_exist(user_id: int):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE id = %s", (user_id,))
        count = cursor.fetchone()[0]
        return count > 0
    except mysql.connector.Error as err:
        return False
    finally:
        if 'cursor' in locals():
            cursor.close()



# Check if the user is a participant of the chat
def is_chat_participant(chat_id: int, user_email: str):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor()
        sql = "SELECT COUNT(*) FROM chat_participants cp JOIN users u ON cp.user_id = u.id WHERE cp.chat_id = %s AND u.email = %s"
        val = (chat_id, user_email)
        cursor.execute(sql, val)
        count = cursor.fetchone()[0]
        return count > 0
    except mysql.connector.Error as err:
        return False
    finally:
        if 'cursor' in locals():
            cursor.close()

# Get user ID by email
def get_user_id_by_email(email: str):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor()
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()
        if result:
            return result[0]
        return None
    except mysql.connector.Error as err:
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()

# Get user email by ID
def get_user_email_by_id(user_id: int):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor()
        cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
        result = cursor.fetchone()
        if result:
            return result[0]
        return None
    except mysql.connector.Error as err:
        return None
    finally:
        if 'cursor' in locals():
            cursor.close()



@app.get("/allchats", response_model=List[dict])
def get_user_chats(current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)
        creator_id = get_user_id_by_email(current_user_email)
        if creator_id is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Creator not found")

        # Retrieve chats created by the user
        sql_get_user_chats = "SELECT * FROM chats WHERE creator_id = %s"
        val_get_user_chats = (creator_id,)
        cursor.execute(sql_get_user_chats, val_get_user_chats)
        user_chats = cursor.fetchall()

        return user_chats
    except mysql.connector.Error as err:
        return {"error": str(err)}
    finally:
        if 'cursor' in locals():
            cursor.close()


# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
