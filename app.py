"""Entry point of the Streamlit app: the page menu.

Run with: streamlit run app.py

st.navigation lists the pages and gives each a proper title, instead of
Streamlit naming them after their file names ("app", "1_Attack_Lab").
"""

import streamlit as st

# Page titles shown in the sidebar menu. Change them here.
PAGES = [
    st.Page("chat.py", title="Support Chat", default=True),
    st.Page("pages/1_Attack_Lab.py", title="Attack Lab"),
]

st.navigation(PAGES).run()
