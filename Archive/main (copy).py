from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import mysql.connector
from passlib.context import CryptContext
import jwt
from jwt import PyJWTError
from datetime import datetime, timedelta
from typing import Optional

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

# MySQL Connection
#mydb = mysql.connector.connect(
#    host="srv983.hstgr.io",
#    user="u763609283_disa",
#    password="$2au8dUNK",
#    database="u763609283_disa"
#)


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


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/signin")

# Dependency to verify JWT token
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return email


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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)