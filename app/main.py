"""
Este proyecto demuestra cómo crear un sistema básico de login y registro
usando FastAPI, JWT y un archivo JSON como "base de datos".
Incluye protección por API Key para los endpoints públicos (/register y /login)
y protección por token JWT para el endpoint privado (/user/me).
"""

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
from pydantic import BaseModel
import json
import os
from datetime import datetime, timedelta
from jose import jwt, JWTError  # Asegúrate de tener python-jose instalado

# -----------------------------------------------------------------------------
# CONFIGURACIÓN DE LA APLICACIÓN
# -----------------------------------------------------------------------------

SECRET_KEY = "SECRET_KEY_SUPER_SEGURO"  # Cambiar por algo seguro en producción
ALGORITHM = "HS256"  # Algoritmo de cifrado para JWT
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Minutos de expiración del token

# Fichero JSON que usaremos como "base de datos"
USERS_FILE = "users.json"

# API Key para endpoints de registro y login
API_KEY = "MI_API_KEY_SECRETA"  # Cambiar por algo seguro

# -----------------------------------------------------------------------------
# MODELOS (Pydantic)
# -----------------------------------------------------------------------------

class User(BaseModel):
    """
    Modelo Pydantic que define la estructura de un usuario:
    - username (str)
    - password (str)
    """
    username: str
    password: str

class TokenData(BaseModel):
    """
    Modelo usado para procesar datos del token JWT, 
    por ejemplo, para extraer el "username" (sub).
    """
    username: Optional[str] = None

# -----------------------------------------------------------------------------
# FUNCIONES AUXILIARES PARA MANEJAR USUARIOS EN EL FICHERO JSON
# -----------------------------------------------------------------------------

def load_users():
    """
    Carga todos los usuarios desde el archivo users.json.
    Si no existe, crea un archivo vacío.
    """
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            json.dump([], f)
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users_list):
    """
    Guarda la lista completa de usuarios en el archivo users.json.
    Sobrescribe el contenido cada vez que se llama.
    """
    with open(USERS_FILE, "w") as f:
        json.dump(users_list, f, indent=4)

def get_user(username: str):
    """
    Devuelve el diccionario de un usuario con el username especificado.
    Si no existe, devuelve None.
    """
    users = load_users()
    for u in users:
        if u["username"] == username:
            return u
    return None

def authenticate_user(username: str, password: str):
    """
    Verifica si existe un usuario con ese username y password.
    Si es correcto, devuelve el usuario. De lo contrario, None.
    """
    user = get_user(username)
    if user and user["password"] == password:
        return user
    return None

# -----------------------------------------------------------------------------
# FUNCIONES AUXILIARES PARA MANEJO DE TOKENS JWT
# -----------------------------------------------------------------------------

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    Genera un token JWT con la información 'data' (por ejemplo, {"sub": username}),
    e incluye un tiempo de expiración definido en expires_delta.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)  # Valor por defecto
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# -----------------------------------------------------------------------------
# DEPENDENCIAS DE SEGURIDAD
# -----------------------------------------------------------------------------

def api_key_dependency(x_api_key: str = Header(None)):
    """
    Verifica que la cabecera X-API-KEY coincida con API_KEY.
    Si no coincide, lanza una excepción 401.
    """
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="API Key inválida")
    return True

# Dependencia para extraer el token JWT de la cabecera 'Authorization: Bearer <TOKEN>'
http_bearer = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(http_bearer)):
    """
    Decodifica el token JWT enviado en Authorization: Bearer <TOKEN>.
    Si es válido, devuelve la información del usuario. Caso contrario, 401 Unauthorized.
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Token inválido: 'sub' no encontrado.")
        user = get_user(username)
        if user is None:
            raise HTTPException(status_code=401, detail="Usuario no encontrado.")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido o expirado.")

# -----------------------------------------------------------------------------
# INICIALIZACIÓN DE LA APLICACIÓN FASTAPI
# -----------------------------------------------------------------------------

app = FastAPI(
    title="Ejemplo de Login con JWT y FastAPI",
    description="Proyecto de demostración para autenticación con API Key y JWT.",
    version="1.0.0"
)

# -----------------------------------------------------------------------------
# ENDPOINTS
# -----------------------------------------------------------------------------

@app.post("/register", dependencies=[Depends(api_key_dependency)])
def register_user(user: User):
    """
    Endpoint para registrar un nuevo usuario. Requiere cabecera:
      X-API-KEY: MI_API_KEY_SECRETA
    Recibe un objeto JSON con 'username' y 'password'.
    """
    existing_user = get_user(user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    users = load_users()
    users.append({"username": user.username, "password": user.password})
    save_users(users)
    return {"message": "Usuario registrado correctamente"}

@app.post("/login", dependencies=[Depends(api_key_dependency)])
def login(user: User):
    """
    Endpoint para autenticarse. Requiere cabecera:
      X-API-KEY: MI_API_KEY_SECRETA
    Recibe un objeto JSON con 'username' y 'password'.
    Si las credenciales son correctas, devuelve un token JWT.
    """
    authenticated = authenticate_user(user.username, user.password)
    if not authenticated:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, 
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/user/me")
def read_me(current_user: dict = Depends(get_current_user)):
    """
    Endpoint para obtener datos del usuario autenticado con JWT.
    Se debe enviar en cabecera:
      Authorization: Bearer <token>
    """
    return {"username": current_user["username"]}
