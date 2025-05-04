from uagents import Agent
from sint_chat_protocol import sint_chat

agent = Agent(name="Sint Chat", version="1.1", seed="123435", port=8000, 
              endpoint="https://beetle-healthy-stinkbug.ngrok-free.app/submit")

agent.include(sint_chat, publish_manifest=True)

if __name__ == "__main__":
    agent.run()
