"""
Target interaction module.
Handles sending request prompts to the target chatbot API/endpoint.
"""

from typing import Dict, Any, Optional
import requests


class Target:
    """
    Client interface for connecting to and communicating with an AI chatbot endpoint.

    Attributes:
        base_url (str): The base URL of the target service (e.g., 'http://localhost:5000').
        endpoint (str): The endpoint path for sending chat requests (default: '/chat').
        api_key (str): API key sent via the 'X-API-Key' header.
    """

    def __init__(
        self,
        base_url: str,
        endpoint: str = "/chat",
        api_key: str = "",
        timeout: int = 30,
        message_field: str = "message",
        auth_header: str = "X-API-Key",
    ):
        """
        Initialize the Target client.

        Args:
            base_url (str):      Base URL of the chatbot service.
            endpoint (str):      Target API endpoint path. Defaults to "/chat".
            api_key (str):       Authentication API key string. Defaults to "".
            timeout (int):       Request timeout in seconds. Defaults to 30.
                                 Increase for slow/local LLMs (e.g. Ollama = 60s).
            message_field (str): JSON field name for the chat message.
                                 Defaults to "message". Use "prompt" or "query"
                                 if the target API uses a different field name.
            auth_header (str):   HTTP header name for the API key.
                                 Defaults to "X-API-Key". Use "Authorization"
                                 for Bearer token APIs.
        """
        self.base_url     = base_url.rstrip("/")
        self.endpoint     = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        self.api_key      = api_key
        self.timeout      = timeout
        self.message_field = message_field
        self.auth_header  = auth_header

    def send_message(self, message: str) -> Dict[str, Any]:
        """
        Send a chat message to the target chatbot endpoint via HTTP POST.

        Args:
            message (str): The prompt or message text to send to the chatbot.

        Returns:
            dict: Standardized response dictionary containing:
                - success (bool): True if HTTP 200 response received, False otherwise.
                - reply (str): Response text from the chatbot, or empty string on failure.
                - status_code (int): HTTP status code, or 0 if connection/timeout error.
                - error (str or None): Error description if request failed, else None.
        """
        url = f"{self.base_url}{self.endpoint}"
        headers = {
            "Content-Type": "application/json",
            self.auth_header: self.api_key,
        }
        payload = {self.message_field: message}

        try:
            response = requests.post(url, json=payload, headers=headers, timeout=self.timeout)
            status_code = response.status_code

            if status_code == 200:
                try:
                    data = response.json()
                    reply_text = ""
                    if isinstance(data, dict):
                        reply_text = (
                            data.get("reply")
                            or data.get("response")
                            or data.get("message")
                            or data.get("text")
                            or str(data)
                        )
                    else:
                        reply_text = str(data)

                    return {
                        "success": True,
                        "reply": reply_text,
                        "status_code": status_code,
                        "error": None
                    }
                except ValueError:
                    return {
                        "success": True,
                        "reply": response.text,
                        "status_code": status_code,
                        "error": None
                    }
            else:
                return {
                    "success": False,
                    "reply": "",
                    "status_code": status_code,
                    "error": f"HTTP {status_code}: {response.text}"
                }

        except requests.exceptions.Timeout:
            return {
                "success": False,
                "reply": "",
                "status_code": 0,
                "error": "Request timed out after 5 seconds"
            }
        except requests.exceptions.ConnectionError:
            return {
                "success": False,
                "reply": "",
                "status_code": 0,
                "error": "Failed to connect to target endpoint (Connection Refused)"
            }
        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "reply": "",
                "status_code": 0,
                "error": f"Request failed: {str(e)}"
            }
        except Exception as e:
            return {
                "success": False,
                "reply": "",
                "status_code": 0,
                "error": f"Unexpected error: {str(e)}"
            }
