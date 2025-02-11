import base64
import datetime
from dataclasses import asdict
from typing import List
from dataclass import user
from dataclass import msg
from utils import crypto

from database import db_user, db_message
from database import db_message

User = user.User
Message = msg.Message

def get_user_messages(username: str, password: str):
    current_time = datetime.datetime.now()
    messages: List[Message] = db_message.get_messages_by_receiver(username)

    unlocked_messages = [msg for msg in messages if msg.timeBeforeUnlock <= current_time]
    locked_messages = [msg for msg in messages if msg.timeBeforeUnlock > current_time]
    for msg in locked_messages:
        msg.senderEphemeralPublicKey = None

    return unlocked_messages, locked_messages

def get_ephemeral_keys_by_message_id(id: int):
    _message = db_message.get_message_by_id(id)
    current_time = datetime.datetime.now()
    if _message.timeBeforeUnlock <= current_time:
        return _message.senderEphemeralPublicKey
    else:
        return None

def get_user_unlocked_messages(username: str, password: str):
    messages: List[Message] = db_message.get_messages_by_receiver(username)
    current_time = datetime.datetime.now()
    unlocked_messages = [msg for msg in messages if msg.timeBeforeUnlock <= current_time]
    return unlocked_messages

def get_user_public_key(username: str) -> bytes:
    user = db_user.findUserInDB(username)
    if user is None:
        return None
    return user.public_key

def register(username, password, publicKey, cipheredPrivateKey, nonce):
    userInDB = db_user.findUserInDB(username)
    hashedPassword = crypto.hash_password(password)
    b64_ct = base64.b64encode(cipheredPrivateKey).decode('utf-8')
    b64_nonce = base64.b64encode(nonce).decode('utf-8')
    if userInDB is None:
        db_user.createUserInDB(User(
            username=username,
            hashedPassword=hashedPassword,
            public_key=publicKey,
            encrypted_private_key=b64_ct,
            nonce=b64_nonce
        ))
        print(f"------- Server Log -------")
        print(f"User '{username}' registered successfully.")
        print(f"--------------------------")
    else:
        print(f"------- Server Log -------")
        print(f"User '{username}' already exists.")
        print(f"--------------------------")

def login(username, password):
    user = db_user.findUserInDB(username)
    if not user:
        print(f"------- Server Log -------")
        print("User not found.")
        print(f"--------------------------")
        return False

    hashedInputPassword = crypto.hash_password(password)
    if user.hashedPassword == hashedInputPassword:
        print(f"------- Server Log -------")
        print("Login successful.")
        print(f"--------------------------")
        return user
    else:
        print(f"------- Server Log -------")
        print("Invalid credentials.")
        print(f"--------------------------")
        return False

def modify_password(username: str, old_password: bytes, new_encrypted_private_key, nonce, new_password: bytes):
    db_user.createDB()
    db = db_user.loadDB()

    if username not in db:
        raise ValueError(f"User '{username}' does not exist in the database.")

    user = db_user.findUserInDB(username)
    hashed_old_password = crypto.hash_password(old_password)
    if user.hashedPassword != hashed_old_password:
        raise ValueError("Old password is incorrect.")

    user.hashedPassword = crypto.hash_password(new_password)
    b64_ct = base64.b64encode(new_encrypted_private_key).decode('utf-8')
    b64_nonce = base64.b64encode(nonce).decode('utf-8')
    user.encrypted_private_key = b64_ct
    user.nonce = b64_nonce

    update_user_in_db(user)
    print(f"------- Server Log -------")
    print(f"Password for user '{username}' has been updated successfully.")
    print(f"--------------------------")

def update_user_in_db(user: User):
    db_user.createDB()
    db = db_user.loadDB()
    if user.username not in db:
        raise ValueError(f"User '{user.username}' does not exist in the database.")

    db[user.username] = asdict(user)
    db[user.username]["hashedPassword"] = user.hashedPassword.hex() if user.hashedPassword else None
    db[user.username]["public_key"] = user.public_key.decode('utf-8') if user.public_key else None
    db[user.username]["encrypted_private_key"] = user.encrypted_private_key if user.encrypted_private_key else None

    db_user.saveDB(db)
    print(f"------- Server Log -------")
    print(f"Password changed successfully.")
    print(f"--------------------------")

def get_new_messages(username: str, password: str, id_messages: List[int]):
    current_time = datetime.datetime.now()
    messages: List[Message] = db_message.get_new_messages(username, id_messages)

    if len(messages) == 0:
        return None, None

    unlocked_messages = [msg for msg in messages if msg.timeBeforeUnlock <= current_time]
    locked_messages = [msg for msg in messages if msg.timeBeforeUnlock > current_time]

    return unlocked_messages, locked_messages

def get_message_ephemeral_public_keys(username: str, password: str, id_messages: List[int]) -> dict:
    current_time = datetime.datetime.now()
    ephemeral_keys = db_message.get_ephemeral_public_keys(id_messages)
    if len(ephemeral_keys) == 0:
        return None
    return ephemeral_keys

def send_message(_user: User, _message: Message):
    if db_user.findUserInDB(_message.receiver):
        next_id = db_message.get_next_message_id()
        _message.id = next_id

        db_message.save_message(_message)
        print(f"------- Server Log -------")
        print(f"Message with ID '{_message.id}' sent successfully.")
        print(f"--------------------------")
    else:
        print(f"------- Server Log -------")
        print(f"The receiver '{_message.receiver}' does not exist.")
        print(f"--------------------------")