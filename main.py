from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Depends, status, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import mysql.connector
from mysql.connector import pooling
from passlib.context import CryptContext
import jwt
from jwt import PyJWTError
from datetime import datetime, timedelta
from typing import Optional, List
import smtp_hostinger
import secrets
from email.mime.text import MIMEText
#AWS S3
import boto3
import os
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from datetime import datetime, timedelta

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




# AWS S3 Configuration
# Chants images
S3_BUCKET = 'disa-data'
# Profile PIC images
S3_BUCKET2 = 'disa-data2'
# Company Admin Docs
S3_BUCKET_DOCS = 'disaserver1'
S3_REGION = 'eu-north-1'  # e.g., 'us-west-1'
AWS_ACCESS_KEY_ID = os.environ['AccessKey']
AWS_SECRET_ACCESS_KEY = os.environ['SecreAWS']

s3_client = boto3.client(
    's3',
    region_name=S3_REGION,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)


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
    'host': 'srv1336.hstgr.io',
    'user': 'u228575024_disa',
    'password': 'uE9[6aB+',
    'database': 'u228575024_disa',
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
    profile_pic_url: Optional[str] = None
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
    checklist: Optional[str] = None  # Allow checklist to be optional and possibly None
    temperature: Optional[float]
    max_tokens: Optional[int]
    top_p: Optional[float]


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


class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordReset(BaseModel):
    token: str
    new_password: str


# MySQL Connection
mydb = None

def get_mysql_connection():
    global mydb
    if mydb is None or not mydb.is_connected():
        mydb = mysql.connector.connect(
            host="srv1336.hstgr.io",
            user="u228575024_disa",
            password="uE9[6aB+",
            database="u228575024_disa"
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


def send_reset_email(email: str, token: str):
    #msg = (f"Your password reset link is https://disa-ai.com/reset?reset-token={token}")

    msg = (f"""Hi There,

You requested to reset the password for your Disa account with the e-mail address ({email}). Please click this link to reset your password.

https://disa-ai.com/reset?reset-token={token}

If you did not request a password reset, please ignore this email.

Thanks,
The Dizio Team""")
   
    smtp = smtp_hostinger.SMTPHostinger()
    smtp.auth("noreply@dizio.in", "Satyen@2024", "smtp.hostinger.com", 465, False)
    smtp.send(email, "noreply@dizio.in", "Password Reset Request for Disa", msg)


 

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

            # Fetch template details
            template_id = user.get('template_id')
            template_details = {}
            if template_id:
                cursor.execute("SELECT industry, specialization, template_text, checklist FROM templates WHERE id = %s", (template_id,))
                template_details = cursor.fetchone() or {}

            return {
                "access_token": access_token, 
                "token_type": "bearer",
                "id": user['id'],
                    "name": user['name'],
                    "email": user['email'],
                    "mobile_number": user['mobile_number'],
                    "corporate_code": user['corporate_code'],
                    "is_admin": user['is_admin'],
                    "industry": template_details.get('industry'),
                    "specialization": template_details.get('specialization'),
                    "template_text": template_details.get('template_text'),
                    "checklist": template_details.get('checklist')
            }
    except mysql.connector.Error as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
    finally:
        if 'conn' in locals():
            conn.close()




@app.post("/password-reset-request")
def password_reset_request(request: PasswordResetRequest, background_tasks: BackgroundTasks):
    try:
        conn = get_mysql_connection()
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (request.email,))
            user = cursor.fetchone()

            if not user:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

            reset_token = secrets.token_urlsafe(32)
            reset_token_expiry = datetime.utcnow() + timedelta(hours=1)

            cursor.execute(
                "UPDATE users SET reset_token = %s, reset_token_expiry = %s WHERE email = %s",
                (reset_token, reset_token_expiry, request.email)
            )
            conn.commit()

            background_tasks.add_task(send_reset_email, request.email, reset_token)

            return {"message": "Password reset email sent"}
    except mysql.connector.Error as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
    finally:
        if 'conn' in locals():
            conn.close()

@app.post("/password-reset")
def password_reset(reset: PasswordReset):
    try:
        conn = get_mysql_connection()
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM users WHERE reset_token = %s", (reset.token,))
            user = cursor.fetchone()

            if not user or user['reset_token_expiry'] < datetime.utcnow():
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token")

            hashed_password = pwd_context.hash(reset.new_password)

            cursor.execute(
                "UPDATE users SET password = %s, reset_token = NULL, reset_token_expiry = NULL WHERE reset_token = %s",
                (hashed_password, reset.token)
            )
            conn.commit()

            return {"message": "Password reset successfully"}
    except mysql.connector.Error as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
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

        # Ensure the profile_pic_url is included
        user["profile_pic_url"] = user.get("profile_pic_url")

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
                   t.industry, t.specialization, u.profile_pic_url
            FROM users u
            LEFT JOIN templates t ON u.template_id = t.id
            WHERE u.corporate_code = (SELECT corporate_code FROM users WHERE id = %s) 
            AND u.id != %s
        """

        val_list_users = (user_id, user_id)
        cursor.execute(sql_list_users, val_list_users)
        users = cursor.fetchall()

        # Return data in the correct format
        return users
    except mysql.connector.Error as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
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







# Define a model for the request body
class ChatCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    welcome_message: str

@app.post("/chats", response_model=dict)
async def create_chat(
    name: str = Form(...),
    description: Optional[str] = Form(None),
    welcome_message: str = Form(...),
    image: Optional[UploadFile] = File(None),
    #image: Optional[UploadFile] = File(None),
    current_user_email: str = Depends(get_current_user),

    
):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor()
        created_at = datetime.utcnow()
        creator_id = get_user_id_by_email(current_user_email)
        if creator_id is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Creator not found")

        # Handle image upload if provided
        group_icon_url = None
        if image:
            try:
                # Create a unique filename
                timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
                _, file_extension = os.path.splitext(image.filename)
                filename = f"chat_icon_{timestamp}{file_extension}"
                # Upload file to S3
                s3_client.upload_fileobj(image.file, S3_BUCKET, filename)
                # Generate the file URL
                group_icon_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{filename}"
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Error uploading image: {str(e)}")

        # Create chat with name, description (if provided), and group icon URL (if provided)
        sql_create_chat = """
            INSERT INTO chats (creator_id, created_at, updated_at, name, description, group_icon_url)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        val_create_chat = (creator_id, created_at, created_at, name, description, group_icon_url)
        cursor.execute(sql_create_chat, val_create_chat)
        chat_id = cursor.lastrowid

        # Add creator to chat participants
        sql_add_creator_to_chat = "INSERT INTO chat_participants (chat_id, user_id) VALUES (%s, %s)"
        val_add_creator_to_chat = (chat_id, creator_id)
        cursor.execute(sql_add_creator_to_chat, val_add_creator_to_chat)

        # Send welcome message from bot
        bot_user_id = 1  # Assuming the bot user ID is 1
        ist_now = datetime.utcnow() + timedelta(hours=5, minutes=30)
        sql_send_message = "INSERT INTO messages (chat_id, sender_id, message, sent_at) VALUES (%s, %s, %s, %s)"
        val_send_message = (chat_id, bot_user_id, welcome_message, ist_now)
        cursor.execute(sql_send_message, val_send_message)

        mydb.commit()

        return {
            "chat_id": chat_id,
            "message": "Chat created successfully with welcome message",
            "group_icon_url": group_icon_url
        }
    except mysql.connector.Error as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
    except NoCredentialsError:
        raise HTTPException(status_code=403, detail="AWS credentials not available")
    except PartialCredentialsError:
        raise HTTPException(status_code=403, detail="Incomplete AWS credentials")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'mydb' in locals():
            mydb.close()





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


@app.post("/uploads/")
async def upload_file(file: UploadFile = File(...), current_user_email: str = Depends(get_current_user)):
    try:
        # Create a unique filename with timestamp and user email
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        base_filename, file_extension = os.path.splitext(file.filename)
        filename = f"{current_user_email}_{timestamp}{file_extension}"

        # Upload file to S3
        s3_client.upload_fileobj(file.file, S3_BUCKET, filename)

        # Generate the file URL
        file_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{filename}"

        return {"filename": filename, "file_url": file_url, "message": "File uploaded successfully!"}
    except NoCredentialsError:
        raise HTTPException(status_code=403, detail="AWS credentials not available")
    except PartialCredentialsError:
        raise HTTPException(status_code=403, detail="Incomplete AWS credentials")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.post("/userpics/")
async def upload_file(file: UploadFile = File(...), current_user_email: str = Depends(get_current_user)):
    try:
        # Create a unique filename with timestamp and user email
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        base_filename, file_extension = os.path.splitext(file.filename)
        filename = f"{current_user_email}{file_extension}"

        # Upload file to S3
        s3_client.upload_fileobj(file.file, S3_BUCKET2, filename)

        # Generate the file URL
        file_url = f"https://{S3_BUCKET2}.s3.{S3_REGION}.amazonaws.com/{filename}"

        # Update the user record in the database with the new profile pic URL
        conn = get_mysql_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE users SET profile_pic_url = %s WHERE email = %s",
                (file_url, current_user_email)
            )
            conn.commit()

        return {"filename": filename, "file_url": file_url, "message": "File uploaded successfully!"}
    except NoCredentialsError:
        raise HTTPException(status_code=403, detail="AWS credentials not available")
    except PartialCredentialsError:
        raise HTTPException(status_code=403, detail="Incomplete AWS credentials")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if 'conn' in locals():
            conn.close()




@app.post("/upload-doc/")
async def upload_doc(file: UploadFile = File(...), current_user_email: str = Depends(get_current_user)):
    try:
        # Retrieve user information to get corporate_code
        conn = get_mysql_connection()
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT corporate_code FROM users WHERE email = %s", (current_user_email,))
            user = cursor.fetchone()

        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        corporate_code = user.get('corporate_code')
        if not corporate_code:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Corporate code not set")

        # Create a unique filename with timestamp and user email
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        base_filename, file_extension = os.path.splitext(file.filename)
        filename = f"{timestamp}_{base_filename}{file_extension}"

        # Define the S3 folder path
        s3_folder_path = f"{corporate_code}/{filename}"

        # Upload file to S3
        s3_client.upload_fileobj(file.file, S3_BUCKET_DOCS, s3_folder_path)

        # Generate the file URL
        file_url = f"https://{S3_BUCKET_DOCS}.s3.{S3_REGION}.amazonaws.com/{s3_folder_path}"

        return {"filename": filename, "file_url": file_url, "message": "File uploaded successfully!"}
    except NoCredentialsError:
        raise HTTPException(status_code=403, detail="AWS credentials not available")
    except PartialCredentialsError:
        raise HTTPException(status_code=403, detail="Incomplete AWS credentials")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if 'conn' in locals():
            conn.close()





@app.get("/list-docs/")
def list_docs(current_user_email: str = Depends(get_current_user)):
    print("List")
    try:
        # Retrieve user information to get corporate_code
        conn = get_mysql_connection()
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT corporate_code FROM users WHERE email = %s", (current_user_email,))
            user = cursor.fetchone()
        print("List2")
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        corporate_code = user.get('corporate_code')
        if not corporate_code:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Corporate code not set")
        print("List3")
        # List files in the S3 folder path
        s3_folder_path = f"{corporate_code}/"
        response = s3_client.list_objects_v2(Bucket=S3_BUCKET_DOCS, Prefix=s3_folder_path)
        files = response.get('Contents', [])
        print("List4")
        file_list = [
            {
                "filename": file['Key'].replace(s3_folder_path, ""),
                "url": f"https://{S3_BUCKET_DOCS}.s3.{S3_REGION}.amazonaws.com/{file['Key']}"
            }
            for file in files
        ]

        return {"files": file_list}
    except NoCredentialsError:
        raise HTTPException(status_code=403, detail="AWS credentials not available")
    except PartialCredentialsError:
        raise HTTPException(status_code=403, detail="Incomplete AWS credentials")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if 'conn' in locals():
            conn.close()




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
            SELECT c.id AS chat_id, c.created_at, c.description, c.group_icon_url, c.name AS creator_name
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


# Retrieve messages from the chat
sql_get_chat_messages = """
    SELECT m.id AS message_id, m.message, m.sent_at, u.name AS sender_name
    FROM messages m
    JOIN users u ON m.sender_id = u.id
    WHERE m.chat_id = %s
    ORDER BY m.sent_at
"""

# Get messages from a chat
@app.get("/chats/{chat_id}/messages", response_model=List[dict])
def get_chat_messages(chat_id: int, current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)

        # Check if the user is a participant of the chat
        if not is_chat_participant(chat_id, current_user_email):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not a participant of this chat")

        

        # Retrieve messages from the chat, including feedback
        sql_get_chat_messages = """
            SELECT m.id AS message_id, m.message, m.sent_at, u.name AS sender_name, m.feedback
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



@app.get("/templates-users", response_model=List[Template])
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
        if 'mydb' in locals():
            mydb.close()

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
        if 'mydb' in locals():
            mydb.close()

@app.post("/templates", response_model=Template, status_code=status.HTTP_201_CREATED)
def create_template(template: TemplateCreate, current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)
        sql = """INSERT INTO templates (industry, specialization, template_text, checklist, temperature, max_tokens, top_p) 
                 VALUES (%s, %s, %s, %s)"""
        values = (template.industry, template.specialization, template.template_text, template.checklist, template.temperature, template.max_tokens, template.top_p)
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
        if 'mydb' in locals():
            mydb.close()





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
                 SET industry = %s, specialization = %s, template_text = %s, checklist = %s, temperature = %s, max_tokens = %s, top_p = %s
                 WHERE id = %s"""
        print(template.max_tokens)
        values = (template.industry, template.specialization, template.template_text, template.checklist, template.temperature, template.max_tokens, template.top_p, template_id)
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
        if 'mydb' in locals():
            mydb.close()





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
        if 'mydb' in locals():
            mydb.close()





class UserTemplateUpdate(BaseModel):
    template_id: int



@app.put("/user/update-template", status_code=status.HTTP_200_OK)
def user_update_template(update: UserTemplateUpdate, current_user_email: str = Depends(get_current_user)):
    try:
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)

        # Check if the user exists and get user ID
        cursor.execute("SELECT id FROM users WHERE email = %s", (current_user_email,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        user_id = user['id']

        # Check if the template exists
        cursor.execute("SELECT id FROM templates WHERE id = %s", (update.template_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found")

        # Update the user's template_id
        sql_update_template = "UPDATE users SET template_id = %s WHERE id = %s"
        val_update_template = (update.template_id, user_id)
        cursor.execute(sql_update_template, val_update_template)
        mydb.commit()

        # Fetch the updated user details
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        updated_user = cursor.fetchone()

        # Fetch updated template details
        template_id = updated_user.get('template_id')
        template_details = {}
        if template_id:
            cursor.execute("SELECT industry, specialization, template_text, checklist FROM templates WHERE id = %s", (template_id,))
            template_details = cursor.fetchone() or {}

        return {
            "id": updated_user['id'],
            "name": updated_user['name'],
            "email": updated_user['email'],
            "mobile_number": updated_user['mobile_number'],
            "corporate_code": updated_user['corporate_code'],
            "password": updated_user['password'],  # Note: Expose password only if absolutely necessary and securely
            "verified": updated_user['verified'],
            "is_admin": updated_user['is_admin'],
            "industry": template_details.get('industry'),
            "specialization": template_details.get('specialization'),
            "template_text": template_details.get('template_text'),
            "checklist": template_details.get('checklist')
        }
    except mysql.connector.Error as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'mydb' in locals():
            mydb.close()


class ReportUser(BaseModel):
    id: int
    name: str
    email: str
    mobile_number: str
    corporate_code: Optional[str]
    industry: Optional[str]
    specialization: Optional[str]
    num_chats_created: int
    total_messages_sent: int
    total_ai_interactions: int
    active_status: str


@app.get("/admin/reports", response_model=List[ReportUser])
def get_all_users_report(current_user_email: str = Depends(get_current_user)):
    try:
        # Ensure the user is an admin
        if not is_user_admin(current_user_email):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized. Admin access required.")

        # Connect to the database
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)

        # Current date for comparison
        current_date = datetime.utcnow()

        # Query to fetch all users with the number of chats created, their template tags, total messages sent, total AI interactions, and active status
        query = """
            SELECT 
                users.id, 
                users.name, 
                users.email, 
                users.mobile_number, 
                users.corporate_code, 
                templates.industry AS industry,
                templates.specialization AS specialization,
                COUNT(DISTINCT chats.id) AS num_chats_created,
                COALESCE(COUNT(messages.id), 0) AS total_messages_sent,
                COALESCE(SUM(CASE WHEN messages.sender_id = 1 THEN 1 ELSE 0 END), 0) AS total_ai_interactions,
                CASE 
                    WHEN MAX(messages.sent_at) >= %s THEN 'Active'
                    ELSE 'Inactive'
                END AS active_status
            FROM 
                users
            LEFT JOIN 
                templates ON users.template_id = templates.id
            LEFT JOIN 
                chats ON users.id = chats.creator_id
            LEFT JOIN 
                messages ON chats.id = messages.chat_id
            WHERE
                users.id != %s
            GROUP BY 
                users.id, users.name, users.email, users.mobile_number, users.corporate_code, templates.industry, templates.specialization
        """
        seven_days_ago = current_date - timedelta(days=7)
        system_default_user_id = 1  # ID of the system default user to exclude
        cursor.execute(query, (seven_days_ago, system_default_user_id))
        users_report = cursor.fetchall()

        return users_report

    except mysql.connector.Error as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'mydb' in locals():
            mydb.close()





@app.get("/company/reports", response_model=List[ReportUser])
def get_all_users_report(current_user_email: str = Depends(get_current_user)):
    try:
        # Ensure the user is an admin
        if not is_user_admin(current_user_email):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized. Admin access required.")

        # Connect to the database
        mydb = get_mysql_connection()
        cursor = mydb.cursor(dictionary=True)

        # Current date for comparison
        current_date = datetime.utcnow()

        # Query to fetch all users with the number of chats created, their template tags, total messages sent, total AI interactions, and active status
        query = """
            SELECT 
                users.id, 
                users.name, 
                users.email, 
                users.mobile_number, 
                users.corporate_code, 
                templates.industry AS industry,
                templates.specialization AS specialization,
                COUNT(DISTINCT chats.id) AS num_chats_created,
                COALESCE(COUNT(messages.id), 0) AS total_messages_sent,
                COALESCE(SUM(CASE WHEN messages.sender_id = 1 THEN 1 ELSE 0 END), 0) AS total_ai_interactions,
                CASE 
                    WHEN MAX(messages.sent_at) >= %s THEN 'Active'
                    ELSE 'Inactive'
                END AS active_status
            FROM 
                users
            LEFT JOIN 
                templates ON users.template_id = templates.id
            LEFT JOIN 
                chats ON users.id = chats.creator_id
            LEFT JOIN 
                messages ON chats.id = messages.chat_id
            WHERE
                users.id != %s
            GROUP BY 
                users.id, users.name, users.email, users.mobile_number, users.corporate_code, templates.industry, templates.specialization
        """
        seven_days_ago = current_date - timedelta(days=7)
        system_default_user_id = 1  # ID of the system default user to exclude
        cursor.execute(query, (seven_days_ago, system_default_user_id))
        users_report = cursor.fetchall()

        return users_report

    except mysql.connector.Error as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'mydb' in locals():
            mydb.close()



# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
