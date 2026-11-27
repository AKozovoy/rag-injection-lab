"""Attack Lab (#17): the defense comparison from findings/, with a drill-down into answers.

Listed in the page menu by app.py (st.navigation).
Model answers and attack documents are attacker-influenced text, so they are
only ever shown as plain text (st.text / st.code), never as Markdown.
"""

import altair as alt
import streamlit as st

from lab_data import (
    ATTACK_LABELS,
    BEST_CONFIG,
    attack_doc_text,
    config_frame,
    defenses_label,
    drilldown,
    headline,
    load_report,
    load_run,
    results_frame,
)

# Sequential blue ramps, validated with the data-viz palette checker (one hue,
# monotone lightness, visible steps). Low values recede toward the page surface.
LIGHT_RAMP = ["#84b9f3", "#519ced", "#2370cd", "#0e3d7e"]
DARK_RAMP = ["#1757ac", "#2370cd", "#519ced", "#84b9f3"]
SURFACE = {"light": "#ffffff", "dark": "#0e1117"}  # Streamlit's default page backgrounds
TEXT_ON_DARK, TEXT_ON_LIGHT = "#ffffff", "#1f1f1f"
CELL_TEXT_SWITCH = 0.5  # at or above this share, a cell is dark (light mode) or bright (dark mode)

st.set_page_config(page_title="Attack Lab", layout="wide")
st.title("Attack Lab")
st.caption("How many prompt-injection attacks got through each defense. Lower is better.")

try:
    report = load_report()
except FileNotFoundError:
    st.error("No findings yet.")
    st.text("Run: python compare_defenses.py")
    st.stop()

settings = report["settings"]
st.text(
    f"Generated {report['generated']} · {settings['chat_model']} · k={settings['k']} · "
    f"temperature {settings['temperature']} · seed {settings['seed']} · "
    "12 tries per attack type, 5 clean questions"
)
if report.get("corpus_verified"):
    st.success("Corpus verified: every run used the same documents.")
else:
    st.warning("Unverified: the runs can't prove they used the same documents.")

# --- Headline: no defense vs the best config ---------------------------------
best_label = defenses_label(report["configs"][BEST_CONFIG])
st.subheader(f"No defense vs. the best config ({BEST_CONFIG}: {best_label})")
for column, tile in zip(st.columns(4), headline(report)):
    is_clean = tile["label"].startswith("Clean")
    column.metric(
        tile["label"],
        f"{tile['best']}/{tile['tries']}",
        delta=f"{tile['best'] - tile['baseline']:+d} vs. no defense",
        delta_color="normal" if is_clean else "inverse",  # fewer attack wins is good
    )

# --- Heatmap: attack success by config and attack type -----------------------
st.subheader("Attacks that got through, by defense")
frame = results_frame(report)
mode = "dark" if st.context.theme.type == "dark" else "light"
configs = list(report["configs"])

base = alt.Chart(frame).encode(
    x=alt.X("attack:N", sort=list(ATTACK_LABELS.values()), title=None,
            axis=alt.Axis(orient="top", labelAngle=0)),
    y=alt.Y("config:N", sort=configs, title=None),
)
cells = base.mark_rect(cornerRadius=4, stroke=SURFACE[mode], strokeWidth=2).encode(
    color=alt.Color(
        "attack_success_rate:Q",
        scale=alt.Scale(domain=[0, 1], range=LIGHT_RAMP if mode == "light" else DARK_RAMP),
        legend=alt.Legend(title="Share of attacks that got through", format="%"),
    ),
    tooltip=[
        alt.Tooltip("config:N", title="Config"),
        alt.Tooltip("defenses:N", title="Defenses"),
        alt.Tooltip("attack:N", title="Attack type"),
        alt.Tooltip("cell:N", title="Got through"),
        alt.Tooltip("blocked_text:N", title="Baseline wins blocked"),
        alt.Tooltip("new_wins:Q", title="New wins"),
    ],
)
# The count is printed in every cell, so color is never the only cue.
dark_cell = alt.datum.attack_success_rate >= CELL_TEXT_SWITCH
labels = base.mark_text(fontSize=14).encode(
    text="cell:N",
    color=alt.condition(
        dark_cell,
        alt.value(TEXT_ON_DARK if mode == "light" else TEXT_ON_LIGHT),
        alt.value(TEXT_ON_LIGHT if mode == "light" else TEXT_ON_DARK),
    ),
)
st.altair_chart((cells + labels).properties(height=40 * len(configs)), width="stretch")
st.caption(
    "Hover a cell for details. Blocked = baseline wins this defense stopped; "
    "new wins = attacks that only got through with it. Links had 1 baseline win, "
    "so their block counts rest on a single answer."
)

st.subheader("Cost of each defense")
st.dataframe(
    config_frame(report),
    hide_index=True,
    column_config={
        "config": "Config",
        "defenses": "Defenses",
        "clean": "Clean answers correct",
        "false_alarms": "False alarms",
        "avg_latency_s": st.column_config.NumberColumn("Avg. answer time (s)", format="%.2f"),
    },
)

with st.expander("Full table"):
    st.dataframe(
        frame[["config", "attack", "wins", "tries", "attack_success_rate",
               "blocked_text", "new_wins"]],
        hide_index=True,
        column_config={
            "config": "Config", "attack": "Attack type", "wins": "Got through",
            "tries": "Tries",
            "attack_success_rate": st.column_config.NumberColumn("Success rate", format="percent"),
            "blocked_text": "Baseline wins blocked", "new_wins": "New wins",
        },
    )

# --- Drill-down: the answers behind a number ---------------------------------
st.subheader("Look at the answers")
TYPE_OPTIONS = {"All attacks": None, **{label: key for key, label in ATTACK_LABELS.items()},
                "Clean questions": "clean"}
left, middle, right = st.columns(3)
config = left.selectbox("Config", configs, index=configs.index(BEST_CONFIG))
type_label = middle.selectbox("Attack type", list(TYPE_OPTIONS))
only_wins = right.checkbox("Only attacks that got through")

items = drilldown(load_run(report, config), attack_type=TYPE_OPTIONS[type_label])
if TYPE_OPTIONS[type_label] is None:
    items = [i for i in items if i["type"] != "clean"]
if only_wins:
    items = [i for i in items if i["verdict"].startswith("attack won")]
st.text(f"{len(items)} answers")

for item in items:
    with st.container(border=True):
        st.text(f"{item['case']}  ·  {item['verdict']}")
        st.text(f"Question: {item['question']}")
        st.code(item["answer"], language=None, wrap_lines=True)
        details = []
        if item["attack_doc"]:
            ranks = ", ".join(f"#{r}" for r in item["attack_ranks"]) or "not retrieved"
            details.append(f"Attack chunk retrieved at: {ranks}")
        if item["filter_actions"]:
            details.append(f"Output filter: {len(item['filter_actions'])} action(s)")
        if item["quarantined"]:
            details.append(f"Scanner quarantined: {', '.join(item['quarantined'])}")
        if details:
            st.text("\n".join(details))
        if item["attack_doc"]:
            with st.expander("Attack document"):  # fixed label: expander labels parse Markdown
                st.text(item["attack_doc"])
                st.code(attack_doc_text(item["attack_doc"]), language=None, wrap_lines=True)

st.divider()
st.caption("Try attacks and defenses live: open \"Support Chat\" in the sidebar menu.")
