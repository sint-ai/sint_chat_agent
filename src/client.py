from datetime import datetime
from uuid import uuid4
from uagents import Agent, Context, Protocol, Model
from uagents_core.contrib.protocols.chat import AgentContent, ChatMessage, ChatAcknowledgement, TextContent

AI_AGENT_ADDRESS = "agent1q2cduhv4z5cleynmmlwymluazp0v6vx48wa9g496n067j3guarjkwtk957g"

agent = Agent(
    name="asi-agent",
    seed="hiweihvhieivhwehihiweivbw;ibv;rikbv;erv;rkkbv",
    port=8001,
    endpoint=["http://127.0.0.1:8001/submit"],
)


@agent.on_event("startup")
async def send_message(ctx: Context):
    await ctx.send(AI_AGENT_ADDRESS, ChatMessage(
        timestamp=datetime.now(),
        msg_id=uuid4(),
        content=[TextContent(type="text", text="who is president of US")],
    ))


@agent.on_message(ChatAcknowledgement)
async def handle_ack(ctx: Context, sender: str, msg: ChatAcknowledgement):
    ctx.logger.info(f"Got an acknowledgement from {sender} for {msg.acknowledged_msg_id}")


@agent.on_message(ChatMessage)
async def handle_ack(ctx: Context, sender: str, msg: ChatMessage):
    ctx.logger.info(f"Received request from {sender} for {msg.content[0].text}")

agent.run()