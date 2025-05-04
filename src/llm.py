import json
import os
from typing import Any
import requests

HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': 'bearer {ASI_KEY_HERE}'
}

URL = "https://api.asi1.ai/v1/chat/completions"

MODEL = "asi1-mini"


async def get_completion(context: str, prompt: str,) -> str:
    # payload = json.dumps({
    #     "model": MODEL,
    #     "messages": [
    #         {
    #             "role": "user",
    #             "content": context + " " + prompt
    #         }
    #     ],
    #     "temperature": 0,
    #     "stream": False,
    #     "max_tokens": 0
    # })

    # response = requests.request("POST", URL, headers=HEADERS, data=payload)

    return 'test'
