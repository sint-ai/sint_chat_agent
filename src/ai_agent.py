import json
import os
from datetime import datetime
from uagents_core.contrib.protocols.chat import ChatMessage, ChatAcknowledgement, TextContent, chat_protocol_spec, ResourceContent, Resource
from uagents import Agent, Context, Protocol
from uuid import uuid4
from dotenv import load_dotenv
import json
from datetime import datetime
from dotenv import load_dotenv
import requests
from uagents import Model, Protocol, Context
from schema import AuthData, Chat, MergeData, SintChatMessage, OneTimeCodeData
import jwt
import re

load_dotenv()

SEED = os.environ["SEED"]
BACKEND_URL = os.environ["BACKEND_URL"]
SINT_URL = os.environ["SINT_URL"]
ANONYM_AUTHENTICATION_SECRET = os.environ["ANONYM_AUTHENTICATION_SECRET"]
ENDPOINT = os.environ["ENDPOINT"]
ALLOWED_MCPS_IDS = os.environ["ALLOWED_MCPS_IDS"].split(",")
print(ENDPOINT)


chat_proto = Protocol(spec=chat_protocol_spec)


agent = Agent(
    name="Sint Chat",
    seed=SEED,
    port=8000,
    proxy=True,
    endpoint=(ENDPOINT),
    publish_agent_details=True,
)


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
            f'{BACKEND_URL}/auth/anonymous',
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


def send_message(chat_id: int, message: str, auth_data: AuthData) -> list[SintChatMessage]:
    response = requests.post(
        f'{BACKEND_URL}/chats/{chat_id}/messages',
        json={"message": {"role": "user", "content": message}, "tools": []},
        headers={"Authorization": f"Bearer {auth_data.access_token}"}
    )
    data = response.json()
    return [SintChatMessage(
        id=message['id'],
        chat_id=message['chatId'],
        content=message['content'],
        role=message['role'],
    ) for message in data]


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


def request_one_time_code(auth_data: AuthData) -> OneTimeCodeData:
    response = requests.post(
        f'{BACKEND_URL}/auth/generate-one-time-code',
        headers={"Authorization": f"Bearer {auth_data.access_token}"},
    )
    data = response.json()
    return OneTimeCodeData(
        code=data["code"],
        expires_at=data["expiresAt"]
    )


def shorten_url(url: str) -> str:
    response = requests.post(
        f'{BACKEND_URL}/shorten',
        json={"url": url},
        headers={"Authorization": f"{ANONYM_AUTHENTICATION_SECRET}"}
    )
    data = response.json()
    return data["shortUrl"]


def _process_response_for_jpeg_images(text: str) -> tuple[str, list[ResourceContent]]:
    image_resources: list[ResourceContent] = []
    # Regex to find markdown image links for .jpeg files
    # Example: [My Image](http://example.com/image.jpeg)
    jpeg_image_pattern = r'\[([^\]]*)\]\(([^)]+\.jpeg)\)'

    extracted_jpeg_urls: list[str] = []
    matches = re.findall(jpeg_image_pattern, text)

    if matches:
        for _image_name, image_url in matches:
            if image_url not in extracted_jpeg_urls:  # Avoid duplicate resources
                extracted_jpeg_urls.append(image_url)

    cleaned_text = re.sub(jpeg_image_pattern, '', text).strip()

    for url in extracted_jpeg_urls:
        image_resources.append(
            ResourceContent(
                type="resource",
                resource_id=uuid4(),
                resource=Resource(
                    uri=url,
                    metadata={
                        "role": "image",
                        "mime_type": "image/jpeg"
                    }
                )
            )
        )
    return cleaned_text, image_resources


@agent.on_event("startup")
async def on_startup(ctx: Context):
    ctx.logger.info(agent.address)


@chat_proto.on_message(ChatMessage)
async def handle_message(ctx: Context, sender: str, msg: ChatMessage):
    ctx.logger.info(
        f"Got a message from {sender} in session {str(ctx.session)}: {msg.content}")
    if not ctx.storage.has(str(ctx.session)):
        auth_data = auth_anonym(sender, ctx)
        one_time_code_data = request_one_time_code(auth_data)
        merge_code_data = request_merge(auth_data)
        url = f"{SINT_URL}/one-time-login?mergeCode={merge_code_data.code}&oneTimeCode={one_time_code_data.code}&redirect=%2Fapp%2Fskills%3Fid%3D{ALLOWED_MCPS_IDS[0]}%26ref%3Dasi1"
        short_url = shorten_url(url)
        ctx.storage.set(str(ctx.session), sender)
        message_text = f"**Hey, I'm SINT!** \nWelcome to the **SINT & Fetch Giveaway!**\n\nTo start enable giveaway skill by following the link bellow\nAfter that comeback to agentverse and i'll guide you every step of the way.\nLet’s start chatting and get you in the game!"
        if msg.content[0].type == 'start-session':
            message_text = f"**Click the link to connect your accounts and activate the giveaway skill.**\nOnce completed, you’ll be able to continue with the giveaway flow."
        return await ctx.send(
            sender,
            ChatMessage(
                timestamp=datetime.now(),
                msg_id=uuid4(),
                content=[
                    TextContent(
                        type="text", text=message_text
                    ),
                    ResourceContent(
                        type="resource",
                        resource_id=uuid4(),
                        resource=Resource(
                            uri=short_url,
                            metadata={
                                "role": "Link to sint"
                            }
                        )
                    ),
                ],
            ),
        )

    await ctx.send(
        sender,
        ChatAcknowledgement(timestamp=datetime.now(),
                            acknowledged_msg_id=msg.msg_id),
    )
    try:
        auth_data = auth_anonym(sender, ctx)
        chat = create_chat(sender, ctx.session.__str__(),
                           auth_data, ctx)
        content = "\n".join(map(lambda c: c.text, filter(
            lambda c: hasattr(c, 'text'), msg.content)))
        messages = send_message(chat.id, content, auth_data)
        assistant_responses = []
        for m in messages:
            if m.role == "assistant":
                try:
                    parsed = json.loads(m.content)
                    if isinstance(parsed, dict) and "content" in parsed:
                        assistant_responses.append(parsed["content"])
                except json.JSONDecodeError:
                    assistant_responses.append(m.content)
        assistant_response_original = "\n".join(assistant_responses)

        # cleaned_response_text, image_resources = _process_response_for_jpeg_images(
        #     assistant_response_original)

        message_content_parts = [
            TextContent(type="text", text=assistant_response_original)
        ]
        # if image_resources:
        #     message_content_parts.extend(image_resources)

        await ctx.send(sender, ChatMessage(
            timestamp=datetime.now(),
            msg_id=uuid4(),
            content=message_content_parts,
        ))
    except Exception as e:
        print(f"Error processing message: {str(e)}")
        await ctx.send(sender, ChatMessage(
            timestamp=datetime.now(),
            msg_id=uuid4(),
            content=[
                TextContent(
                    type="text", text=f'An error occurred while processing your message {str(e)}')
            ],
        ))


@chat_proto.on_message(ChatAcknowledgement)
async def handle_ack(ctx: Context, sender: str, msg: ChatAcknowledgement):
    ctx.logger.info(
        f"Got an acknowledgement from {sender} for {msg.acknowledged_msg_id}")


agent.include(chat_proto, publish_manifest=True)

agent.run()
