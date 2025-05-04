​![tag : innovationlab](https://img.shields.io/badge/innovationlab-3D8BD3)

# SINT Chat Agent

## Overview

SINT Chat Agent is a middleware solution that enables applications to connect to the SINT AI platform. Built on the uAgents framework, it provides an agent-based approach to chat interactions, authentication, and message handling.

## Features

- **Agent-based Architecture**: Built on uAgents library for autonomous agent functionality
- **Authentication**: Anonymous authentication with JWT token management
- **Chat Management**: Create chat sessions and send/receive messages
- **Account Merging**: Support for merging anonymous accounts with registered SINT accounts

## Installation

```bash
git clone https://github.com/yourusername/sint-chat-agent.git
cd sint-chat-agent
pip install -r requirements.txt
```

## Configuration

1. Create a `.env` file based on the provided `.env.example`:

```bash
cp .env.example .env
```

2. Edit the `.env` file with your configuration:

```
BACKEND_URL=your_backend_url
SINT_URL=your_sint_url
ANONYM_AUTHENTICATION_SECRET=your_secret_key
```

## Usage

### Running the Agent

```bash
python agent.py
```

The agent will start on port 8000 by default.

### Integrating with Applications

Include the SINT Chat Protocol in your application:

```python
from uagents import Agent
from sint_chat_protocol import sint_chat

agent = Agent(name="Your App", version="1.0", seed="your_seed")
agent.include(sint_chat)
```

### Sending Messages

```python
from uagents import Agent, Context
from sint_chat_protocol import Request

async def send_message(ctx: Context, recipient: str, message: str):
    await ctx.send(recipient, Request(message=message))
```

## Protocol

The SINT Chat Protocol includes:
- Message handling
- Anonymous authentication
- Chat creation and management
- Account merging capabilities


