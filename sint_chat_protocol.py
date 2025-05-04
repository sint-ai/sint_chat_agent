import json
import logging
from datetime import datetime
from dotenv import load_dotenv
import os
import requests
from uagents import Model, Protocol, Context
from ai_engine import UAgentResponseType, UAgentResponse
from schema import AuthData, Chat, ChatMessage, MergeData
import jwt

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

sint_chat = Protocol(name="sint", version="1.1")

load_dotenv()

BACKEND_URL = os.environ["BACKEND_URL"]
SINT_URL = os.environ["SINT_URL"]
ANONYM_AUTHENTICATION_SECRET = os.environ["ANONYM_AUTHENTICATION_SECRET"]

class Request(Model):
    message: str

class MergeRequest(Model):

    pass

def is_token_expired(token: str, ctx: Context) -> bool:
    return True
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        exp = payload.get('exp')
        if exp is None:
            return False
        return datetime.now().timestamp() > exp
    except jwt.InvalidTokenError:
        return True


def auth_anonym(id: str, ctx: Context) -> AuthData:
    stored_auth = ctx.storage.get(f'{id}-auth')
    if not stored_auth:
        response = requests.post(
            f'{BACKEND_URL}/auth/anonym',
            json={"id": id, "source": "deltav"},
            headers={"Authorization": f"{ANONYM_AUTHENTICATION_SECRET}"}
            )
        data = response.json()
        auth_data = AuthData(
            user_id=id,
            access_token=data['accessToken'],
            refresh_token=data['refreshToken']
        )
        ctx.storage.set(f'{id}-auth', json.dumps(auth_data.dict()))
        return auth_data
    else:
        auth_dict = json.loads(stored_auth)
        auth_data = AuthData(
            user_id=auth_dict["user_id"],
            access_token=auth_dict["access_token"],
            refresh_token=auth_dict["refresh_token"]
        )
        if is_token_expired(auth_data.access_token, ctx):
            ctx.storage.remove(f'{id}-auth')
            return auth_anonym(id, ctx)
        return auth_data


def create_chat(sender: str, session_id: str, auth_data: AuthData, ctx: Context) -> Chat:
    stored_chat = ctx.storage.get(f'{sender}-{session_id}')
    if not stored_chat:
        response = requests.post(
            f'{BACKEND_URL}/chats',
            json={"name": session_id},
            headers={"Authorization": f"Bearer {auth_data.access_token}"}
        )
        data = response.json()
        chat = Chat(
            id=data['id'],
            user_id=data['userId'],
            name=data['name'],
            created_at=data['createdAt']
        )
        ctx.storage.set(f'{sender}-{session_id}', json.dumps(chat.dict()))
        return chat
    else:
        chat_dict = json.loads(stored_chat)
        return Chat(
            id=chat_dict["id"],
            user_id=chat_dict["user_id"],
            name=chat_dict["name"],
            created_at=chat_dict["created_at"]
        )


def send_message(chat_id: int, message: str, auth_data: AuthData) -> list[ChatMessage]:
    response = requests.post(
        f'{BACKEND_URL}/chats/{chat_id}/messages',
        json={"message": {"role": "user", "content": message}, "tools": []},
        headers={"Authorization": f"Bearer {auth_data.access_token}"}
    )
    data = response.json()
    return [ChatMessage(
        id=message['id'],
        chat_id=message['chatId'],
        content=message['content'],
        role=message['role'],
    ) for message in data]


@sint_chat.on_message(model=Request, replies={UAgentResponse})
async def handle_message(ctx: Context, sender: str, msg: Request):
    try:
        auth_data = auth_anonym(sender, ctx)
        chat = create_chat(sender, ctx.session.__str__(),
                           auth_data, ctx)
        messages = send_message(chat.id, msg.message, auth_data)
        assistant_response = " ".join(
            [m.content for m in messages if m.role == "assistant"])
        await ctx.send(sender, UAgentResponse(message=assistant_response, type=UAgentResponseType.FINAL))
    except Exception as e:
        print(f"Error processing message: {str(e)}")
        await ctx.send(sender, UAgentResponse(message=f'An error occurred while processing your message {str(e)}', type=UAgentResponseType.ERROR))


def request_merge(auth_data: AuthData) -> MergeData:
    response = requests.post(
        f'{BACKEND_URL}/merge/request',
        headers={"Authorization": f"Bearer {auth_data.access_token}"},
    )
    data = response.json()
    return MergeData(
        code=data["code"],
        expires_at=data["expiresAt"]
    )


@sint_chat.on_message(model=MergeRequest, replies={UAgentResponse})
async def handle_merge(ctx: Context, sender: str, msg: MergeRequest):
    try:
        auth_data = auth_anonym(sender, ctx)
        merge_res = request_merge(auth_data)
        await ctx.send(sender, UAgentResponse(message=f"Proceed to this url and log in using your SINT credentials: {SINT_URL}/?mergeCode={merge_res.code}", type=UAgentResponseType.FINAL))
    except Exception as e:
        ctx.logger.error(f"Error processing message: {str(e)}")
        await ctx.send(sender, UAgentResponse(message=f'An error occurred while processing your message {str(e)}', type=UAgentResponseType.ERROR))
