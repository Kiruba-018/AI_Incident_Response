"""This module contains functions to interact with the LLM for the AI Incident Response Agent."""

import os

from langchain.chat_models import init_chat_model
from langchain_community.utilities import SerpAPIWrapper
from langchain_core.messages import HumanMessage, SystemMessage
from langfuse.langchain import CallbackHandler

chat_model = None


def get_chat_model():
    """Initialize and return the chat model."""
    global chat_model
    if chat_model is None:
        chat_model = init_chat_model(
            "groq:llama-3.1-8b-instant",
            temperature=0.2,
            api_key=os.getenv("GROQ_API_KEY")
        )
    return chat_model



async def invoke_llm(system_prompt: str) -> str:
    """Invoke the LLM with the given system prompt."""
    model = get_chat_model()
    response = await model.ainvoke([
    SystemMessage(content="You are a senior SOC analyst."),
    HumanMessage(content=system_prompt)], config={"callbacks": [CallbackHandler()]})

    return response.content



def web_search(query: str) -> str:
    """Perform a web search using SerpAPI.

    Args:
        query (str): The search query.

    Returns:
        str: The search results.
    """
    serp_api = SerpAPIWrapper(serpapi_api_key=os.getenv("SERPAPI_API_KEY"))
    return serp_api.run(query)


