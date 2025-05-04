from typing import Optional
from uagents import Model


class AuthData(Model):
    user_id: str
    access_token: str
    refresh_token: str


class Chat(Model):
    id: int
    user_id: str
    name: str
    created_at: str


class SintChatMessage(Model):
    id: Optional[int]
    chat_id: int
    content: str
    role: str  # "user" | "assistant"
    created_at: Optional[str]
    temp_id: Optional[str]
    thinking: Optional[str]


class MergeData(Model):
    code: str
    expires_at: str
