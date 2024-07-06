from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import mysql.connector
from mysql.connector import pooling
from passlib.context import CryptContext
import jwt
from jwt import PyJWTError
from datetime import datetime, timedelta
from typing import Optional, List

app = FastAPI()

# CORS settings
origins = ["*"]

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT Settings
SECRET_KEY = "your_secret_key"  # Replace with a secure random key in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 262800  # Token expiration time in minutes

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

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

# MySQL Connection Pool
db_config = {
    'host': 'srv983.hstgr.io',
    'user': 'u763609283_disa',
    'password': '$2au8dUNK',
    'database': 'u763609283_disa',
    'pool_name': 'mypool',
    'pool_size': 5,
}

db_pool = pooling.MySQLConnectionPool(**db_config)

def get_mysql_connection():
    return db_pool.get_connection()

class User(BaseModel):
    id: Optional[int]
    name: str
    email: str
    mobile_number: str
    corporate_code: Optional[str]
    password: str
    verified: bool = False
    is_admin: bool = False
    industry: Optional[str] = None
    specialization: Optional[str] = None
    template_text: Optional[str] = None
    checklist: Optional[str] = None

class Message(BaseModel):
    message: str

class TemplateBase(BaseModel):
    industry: str
    specialization: str
    template_text: str
    checklist: str

class TemplateCreate(TemplateBase):
    pass

class TemplateUpdate(TemplateBase):
    pass

class Template(TemplateBase):
    id: int
    created_date: datetime
    last_modified_date: datetime

    class Config:
        orm_mode = True


# MySQL Connection
mydb = None

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

def authenticate_user(email: str, password: str, db_user):
    if db_user and pwd_context.verify(password, db_user['password']):
        return db_user
    return None

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/signup")
def signup(user: User):
    try:
        conn = get_mysql_connection()
        with conn.cursor() as cursor:
            hashed_password = pwd_context.hash(user.password)
            sql = "INSERT INTO users (name, email, mobile_number, corporate_code, password) VALUES (%s, %s, %s, %s, %s)"
            val = (user.name, user.email, user.mobile_number, user.corporate_code, hashed_password)
            cursor.execute(sql, val)
            conn.commit()
        return {"message": "User created successfully"}
    except mysql.connector.Error as err:
        return {"error": str(err)}
    finally:
        if 'conn' in locals():
            conn.close()

@app.post("/signin")
def signin(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        conn = get_mysql_connection()
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute(f"SELECT * FROM users WHERE mobile_number = %s", (form_data.username,))
            user = cursor.fetchone()

            if not user or not authenticate_user(user['mobile_number'], form_data.password, user):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect mobile number or password")

            if not user['verified']:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User not verified")

            access_token = create_access_token(data={"sub": user["email"]})
            return {"access_token": access_token, "token_type": "bearer"}
    except mysql.connector.Error as err:
        return {"error": str(err)}
    finally:
        if 'conn' in locals():
            conn.close()


@app.get("/users/me", response_model=User)
def read_users_me(current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (current_user_email,))
        user = cursor.fetchone()
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        template_id = user.get('template_id')
        if template_id is not None:
            cursor.execute("SELECT industry, specialization, template_text, checklist FROM templates WHERE id = %s", (template_id,))
            template_details = cursor.fetchone()
            if template_details:
                user["industry"] = template_details["industry"]
                user["specialization"] = template_details["specialization"]
                user["template_text"] = template_details["template_text"]
                user["checklist"] = template_details["checklist"]
        else:
            user["industry"] = None
            user["specialization"] = None
            user["template_text"] = None
            user["checklist"] = None

        return user
    except mysql.connector.Error as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
    finally:
        if 'cursor' in locals():
            cursor.close()

@app.get("/users/list", response_model=List[User])
def list_users_by_corporate_code(current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)

        user_id = get_user_id_by_email(current_user_email)
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        sql_list_users = """
            SELECT u.id, u.name, u.email, u.mobile_number, u.corporate_code, u.password, 
                   u.verified, u.is_admin, u.template_id,
                   t.industry, t.specialization
            FROM users u
            LEFT JOIN templates t ON u.template_id = t.id
            WHERE u.corporate_code = (SELECT corporate_code FROM users WHERE id = %s) 
            AND u.id != %s
        """
        val_list_users = (user_id, user_id)
        cursor.execute(sql_list_users, val_list_users)
        users = cursor.fetchall()

        return users
    except mysql.connector.Error as err:
        return {"error": str(err)}
    finally:
        if 'cursor' in locals():
            cursor.close()

@app.get("/chats/{chat_id}/members", response_model=List[dict])
def get_chat_members(chat_id: int, current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)

        if not is_chat_participant(chat_id, current_user_email):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not a participant of this chat")

        current_user_id = get_user_id_by_email(current_user_email)

        sql_get_chat_members = """
            SELECT u.id, u.name, u.email, u.mobile_number
            FROM chat_participants cp
            JOIN users u ON cp.user_id = u.id
            WHERE cp.chat_id = %s AND u.id != %s
        """
        cursor.execute(sql_get_chat_members, (chat_id, current_user_id))
        chat_members = cursor.fetchall()

        return chat_members
    except mysql.connector.Error as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
    finally:
        if 'cursor' in locals():
            cursor.close()

@app.post("/chats/{chat_id}/add-user/{user_id}", status_code=status.HTTP_200_OK)
def add_user_to_chat(chat_id: int, user_id: int, current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor()

        if not is_chat_participant(chat_id, current_user_email):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not a participant of this chat")

        if not is_user_exist(user_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        if is_chat_participant(chat_id, get_user_email_by_id(user_id)):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User is already a participant of this chat")

        sql_add_user_to_chat = "INSERT INTO chat_participants (chat_id, user_id) VALUES (%s, %s)"
        cursor.execute(sql_add_user_to_chat, (chat_id, user_id))
        mydb.commit()

        return {"message": "User added to chat successfully"}
    except mysql.connector.Error as err:
        return {"error": str(err)}
    finally:
        if 'cursor' in locals():
            cursor.close()

# Additional utility functions
def get_user_id_by_email(email: str):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if user:
            return user["id"]
    except mysql.connector.Error as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
    finally:
        if 'cursor' in locals():
            cursor.close()
    return None

def get_user_email_by_id(user_id: int):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)
        cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        if user:
            return user["email"]
    except mysql.connector.Error as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
    finally:
        if 'cursor' in locals():
            cursor.close()
    return None

def is_user_exist(user_id: int):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)
        cursor.execute("SELECT 1 FROM users WHERE id = %s", (user_id,))
        return cursor.fetchone() is not None
    except mysql.connector.Error as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
    finally:
        if 'cursor' in locals():
            cursor.close()

def is_chat_participant(chat_id: int, user_email: str):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)
        user_id = get_user_id_by_email(user_email)
        if user_id is None:
            return False
        cursor.execute("SELECT 1 FROM chat_participants WHERE chat_id = %s AND user_id = %s", (chat_id, user_id))
        return cursor.fetchone() is not None
    except mysql.connector.Error as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
    finally:
        if 'cursor' in locals():
            cursor.close()



@app.get("/chats/{chat_id}/users", response_model=List[dict])
def list_chat_users_with_status(chat_id: int, current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)

        # Get the current user's corporate code
        user_id = get_user_id_by_email(current_user_email)
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        cursor.execute("SELECT corporate_code FROM users WHERE id = %s", (user_id,))
        corporate_code = cursor.fetchone().get("corporate_code")

        if corporate_code is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Corporate code not found")

        # Fetch all users with the same corporate code, excluding user with id 1
        cursor.execute("SELECT id, name, email, mobile_number FROM users WHERE corporate_code = %s AND id != %s AND id != 1", (corporate_code, user_id))
        all_users = cursor.fetchall()

        # Fetch chat participants
        cursor.execute("SELECT user_id FROM chat_participants WHERE chat_id = %s", (chat_id,))
        chat_participants = cursor.fetchall()
        participant_ids = {participant["user_id"] for participant in chat_participants}

        # Add member_status to all users
        for user in all_users:
            user["member_status"] = user["id"] in participant_ids

        return all_users
    except mysql.connector.Error as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
    finally:
        if 'cursor' in locals():
            cursor.close()



# Remove user from chat
@app.delete("/chats/{chat_id}/remove-user/{user_id}", status_code=status.HTTP_200_OK)
def remove_user_from_chat(chat_id: int, user_id: int, current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor()

        # Check if the chat exists and the current user is a participant
        if not is_chat_participant(chat_id, current_user_email):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not a participant of this chat")

        # Check if the user to be removed exists
        if not is_user_exist(user_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        # Check if the user is actually a participant of the chat
        if not is_chat_participant(chat_id, get_user_email_by_id(user_id)):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User is not a participant of this chat")

        # Remove user from the chat
        sql = "DELETE FROM chat_participants WHERE chat_id = %s AND user_id = %s"
        val = (chat_id, user_id)
        cursor.execute(sql, val)

        mydb.commit()
        return {"message": "User removed from chat successfully"}
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







@app.delete("/chats/{chat_id}", status_code=status.HTTP_200_OK)
def remove_chat(chat_id: int, current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor()

        # Check if the chat exists and the current user is a participant
        if not is_chat_participant(chat_id, current_user_email):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not a participant of this chat")

        # Delete chat participants first
        sql_delete_participants = "DELETE FROM chat_participants WHERE chat_id = %s"
        cursor.execute(sql_delete_participants, (chat_id,))

        # Now delete the chat itself
        sql_delete_chat = "DELETE FROM chats WHERE id = %s"
        cursor.execute(sql_delete_chat, (chat_id,))

        mydb.commit()
        return {"message": "Chat removed successfully"}
    except mysql.connector.Error as err:
        return {"error": str(err)}
    finally:
        if 'cursor' in locals():
            cursor.close()

# Send message to chat
@app.post("/chats/{chat_id}/send-message", status_code=status.HTTP_201_CREATED)
def send_message_to_chat(chat_id: int, message: Message, current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor()
        sender_id = get_user_id_by_email(current_user_email)
        if sender_id is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sender not found")


        # Calculate IST time
        utc_now = datetime.utcnow()
        ist_offset = timedelta(hours=5, minutes=30)
        ist_now = utc_now + ist_offset

        sql_send_message = "INSERT INTO messages (chat_id, sender_id, message, sent_at) VALUES (%s, %s, %s, %s)"
        val_send_message = (chat_id, sender_id, message.message, ist_now)
        cursor.execute(sql_send_message, val_send_message)

        

        #sql_send_message = "INSERT INTO messages (chat_id, sender_id, message, sent_at) VALUES (%s, %s, %s, %s)"
        #val_send_message = (chat_id, sender_id, message.message, datetime.utcnow())
        #cursor.execute(sql_send_message, val_send_message)

        mydb.commit()
        return {"message": "Message sent successfully"}
    except mysql.connector.Error as err:
        return {"error": str(err)}
    finally:
        if 'cursor' in locals():
            cursor.close()


# Send message to chat from bot
@app.post("/chats/{chat_id}/send-message-bot", status_code=status.HTTP_201_CREATED)
def send_message_to_chat_from_bot(chat_id: int, message: Message, current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor()
        # Check if the bot user exists
        bot_user_id = 1  # Assuming the bot user ID is 1

        # Calculate IST time
        utc_now = datetime.utcnow()
        ist_offset = timedelta(hours=5, minutes=30)
        ist_now = utc_now + ist_offset

        # Add message to the chat from the bot
        sql_send_message = "INSERT INTO messages (chat_id, sender_id, message, sent_at) VALUES (%s, %s, %s, %s)"
        val_send_message = (chat_id, bot_user_id, message.message, ist_now)
        cursor.execute(sql_send_message, val_send_message)

        mydb.commit()
        return {"message": "Message sent by bot successfully"}
    except mysql.connector.Error as err:
        return {"error": str(err)}
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


# Model for feedback update
class FeedbackUpdate(BaseModel):
    feedback: Optional[int]

# Endpoint to update message feedback
@app.put("/messages/{message_id}/feedback")
def update_message_feedback(message_id: int, feedback_update: FeedbackUpdate, db: mysql.connector.connection.MySQLConnection = Depends(get_mysql_connection)):
    try:
        cursor = db.cursor()

        # Check if message_id exists
        cursor.execute("SELECT id FROM messages WHERE id = %s", (message_id,))
        message = cursor.fetchone()
        if not message:
            raise HTTPException(status_code=404, detail="Message not found")

        # Update feedback in the database
        update_query = "UPDATE messages SET feedback = %s WHERE id = %s"
        cursor.execute(update_query, (feedback_update.feedback, message_id))
        db.commit()

        return {"message": "Feedback updated successfully"}
    except mysql.connector.Error as err:
        return {"error": str(err)}
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'db' in locals() and db.is_connected():
            db.close()

@app.get("/allchats", response_model=List[dict])
def get_user_chats(current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)
        user_id = get_user_id_by_email(current_user_email)
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        # Retrieve chats where the user is a participant
        sql_get_user_chats = """
            SELECT c.id AS chat_id, c.created_at, u.name AS creator_name
            FROM chats c
            JOIN chat_participants cp ON c.id = cp.chat_id
            JOIN users u ON c.creator_id = u.id
            WHERE cp.user_id = %s
            ORDER BY c.created_at DESC
        """
        val_get_user_chats = (user_id,)
        cursor.execute(sql_get_user_chats, val_get_user_chats)
        user_chats = cursor.fetchall()

        return user_chats
    except mysql.connector.Error as err:
        return {"error": str(err)}
    finally:
        if 'cursor' in locals():
            cursor.close()



# Get messages from a chat
@app.get("/chats/{chat_id}/messages", response_model=List[dict])
def get_chat_messages(chat_id: int, current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)

        # Check if the user is a participant of the chat
        if not is_chat_participant(chat_id, current_user_email):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not a participant of this chat")

        # Retrieve messages from the chat
        sql_get_chat_messages = """
            SELECT m.id AS message_id, m.message, m.sent_at, u.name AS sender_name
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.chat_id = %s
            ORDER BY m.sent_at
        """
        val_get_chat_messages = (chat_id,)
        cursor.execute(sql_get_chat_messages, val_get_chat_messages)
        chat_messages = cursor.fetchall()

        return chat_messages
    except mysql.connector.Error as err:
        return {"error": str(err)}
    finally:
        if 'cursor' in locals():
            cursor.close()



# Verify user endpoint
@app.post("/admin/verify-user/{user_id}")
def verify_user(user_id: int, current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor()

        # Check if the current user is an admin
        if not is_user_admin(current_user_email):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")

        # Verify the user
        sql_verify_user = "UPDATE users SET verified = TRUE WHERE id = %s"
        cursor.execute(sql_verify_user, (user_id,))
        mydb.commit()

        return {"message": "User verified successfully"}
    except mysql.connector.Error as err:
        return {"error": str(err)}
    finally:
        if 'cursor' in locals():
            cursor.close()

def is_user_admin(email: str):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor()
        cursor.execute("SELECT is_admin FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()
        if result:
            return result[0]
        return False
    except mysql.connector.Error as err:
        return False
    finally:
        if 'cursor' in locals():
            cursor.close()


# Unverify user endpoint
@app.post("/admin/unverify-user/{user_id}")
def unverify_user(user_id: int, current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor()

        # Check if the current user is an admin
        if not is_user_admin(current_user_email):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")

        # Unverify the user
        sql_unverify_user = "UPDATE users SET verified = FALSE WHERE id = %s"
        cursor.execute(sql_unverify_user, (user_id,))
        mydb.commit()

        return {"message": "User unverified successfully"}
    except mysql.connector.Error as err:
        return {"error": str(err)}
    finally:
        if 'cursor' in locals():
            cursor.close()




# 1. Endpoint for listing all templates
@app.get("/templates", response_model=List[Template])
def list_templates(current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)
        cursor.execute("SELECT * FROM templates ORDER BY created_date DESC")
        templates = cursor.fetchall()
        return templates
    except mysql.connector.Error as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
    finally:
        if 'cursor' in locals():
            cursor.close()

# 2. Endpoint for creating a template
@app.post("/templates", response_model=Template, status_code=status.HTTP_201_CREATED)
def create_template(template: TemplateCreate, current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)
        sql = """INSERT INTO templates (industry, specialization, template_text) 
                 VALUES (%s, %s, %s)"""
        values = (template.industry, template.specialization, template.template_text)
        cursor.execute(sql, values)
        mydb.commit()

        new_template_id = cursor.lastrowid
        cursor.execute("SELECT * FROM templates WHERE id = %s", (new_template_id,))
        new_template = cursor.fetchone()
        return new_template
    except mysql.connector.Error as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
    finally:
        if 'cursor' in locals():
            cursor.close()

# 3. Endpoint for editing a template
@app.put("/templates/{template_id}", response_model=Template)
def update_template(template_id: int, template: TemplateUpdate, current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)

        # Check if template exists
        cursor.execute("SELECT * FROM templates WHERE id = %s", (template_id,))
        existing_template = cursor.fetchone()
        if not existing_template:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found")

        sql = """UPDATE templates 
                 SET industry = %s, specialization = %s, template_text = %s
                 WHERE id = %s"""
        values = (template.industry, template.specialization, template.template_text, template_id)
        cursor.execute(sql, values)
        mydb.commit()

        cursor.execute("SELECT * FROM templates WHERE id = %s", (template_id,))
        updated_template = cursor.fetchone()
        return updated_template
    except mysql.connector.Error as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
    finally:
        if 'cursor' in locals():
            cursor.close()




#from pydantic import BaseModel

class UserTemplateUpdate(BaseModel):
    user_id: int
    template_id: int

@app.put("/admin/update-user-template", status_code=status.HTTP_200_OK)
def admin_update_user_template(update: UserTemplateUpdate, current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor()

        # Check if the current user is an admin
        if not is_user_admin(current_user_email):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized. Admin access required.")

        # Check if the user exists
        cursor.execute("SELECT id FROM users WHERE id = %s", (update.user_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        # Check if the template exists
        cursor.execute("SELECT id FROM templates WHERE id = %s", (update.template_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found")

        # Update the user's template_id
        sql_update_template = "UPDATE users SET template_id = %s WHERE id = %s"
        val_update_template = (update.template_id, update.user_id)
        cursor.execute(sql_update_template, val_update_template)

        mydb.commit()
        return {"message": f"Template ID updated successfully for user {update.user_id}"}
    except mysql.connector.Error as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
    finally:
        if 'cursor' in locals():
            cursor.close()



# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
