import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import os

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="SECF Benchmark Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- LOAD DATA ---
@st.cache_data
def load_data():
    file_path = "benchmark_results.json"
    
    # If the JSON doesn't exist, load the mock data from your screenshot
    if not os.path.exists(file_path):
        return {
            "methodology": "real measurements via clock_gettime...",
            "payload_size_bytes": 256,
            "latency": {
                "baseline": {"mean_us": 0.2082, "p95_us": 0.0850, "p99_us": 12.9550},
                "hardened": {"mean_us": 9.6644, "p95_us": 5.9130, "p99_us": 413.2360},
                "overhead_percent": 4542.76
            },
            "throughput": {
                "baseline": {"mbps": 148427.30, "packets_per_second": 72474269},
                "hardened": {"mbps": 378.91, "packets_per_second": 185015},
                "reduction_percent": 99.74
            },
            "overhead": {
                "aes": {"avg_time_us": 1.9959},
                "hmac": {"avg_time_us": 3.3155},
                "sequence": {"avg_time_us": 1.4861},
                "total_crypto_overhead_us": 5.3114
            },
            "jitter": {
                "baseline_stdev_us": 1.2876,
                "hardened_stdev_us": 40.7675
            }
        }
    
    with open(file_path, "r") as f:
        return json.load(f)

data = load_data()

# --- HEADER ---
st.title("🛡️ Secure Embedded Communication Framework (SECF)")
st.markdown("### Cryptographic Performance & Benchmark Analysis")
st.caption(f"Payload Size: {data['payload_size_bytes']} bytes | {data['methodology']}")
st.divider()

# --- TOP METRICS ROW ---
col1, col2, col3, col4 = st.columns(4)
col1.metric("Hardened Mean Latency", f"{data['latency']['hardened']['mean_us']:.2f} µs", f"+{data['latency']['overhead_percent']:.0f}%", delta_color="inverse")
col2.metric("Hardened Throughput", f"{data['throughput']['hardened']['mbps']:.2f} Mbps", f"-{data['throughput']['reduction_percent']:.2f}%", delta_color="inverse")
col3.metric("Total Crypto Overhead", f"{data['overhead']['total_crypto_overhead_us']:.2f} µs")
col4.metric("Hardened Jitter (σ)", f"{data['jitter']['hardened_stdev_us']:.2f} µs")

st.divider()

# --- VISUALIZATIONS ---
colA, colB = st.columns(2)

with colA:
    st.subheader("🚀 Throughput Comparison (Mbps)")
    tp_data = pd.DataFrame({
        "Protocol": ["Baseline", "Hardened"],
        "Mbps": [data['throughput']['baseline']['mbps'], data['throughput']['hardened']['mbps']]
    })
    fig_tp = px.bar(tp_data, x="Protocol", y="Mbps", text="Mbps", color="Protocol", 
                    color_discrete_sequence=["#1f77b4", "#ff7f0e"])
    fig_tp.update_traces(texttemplate='%{text:.2s}', textposition='outside')
    fig_tp.update_layout(yaxis_type="log") # Log scale because baseline is massive
    st.plotly_chart(fig_tp, use_container_width=True)
    st.caption("*Note: Y-axis is on a logarithmic scale due to massive raw memory copy speeds.*")

with colB:
    st.subheader("⏱️ Per-Mechanism Latency Overhead")
    oh_data = pd.DataFrame({
        "Mechanism": ["AES-256-GCM", "HMAC-SHA256", "Sequence Counter"],
        "Time (µs)": [
            data['overhead']['aes']['avg_time_us'],
            data['overhead']['hmac']['avg_time_us'],
            data['overhead']['sequence']['avg_time_us']
        ]
    })
    fig_oh = px.pie(oh_data, values="Time (µs)", names="Mechanism", hole=0.4,
                    color_discrete_sequence=px.colors.qualitative.Pastel)
    fig_oh.update_traces(textposition='inside', textinfo='percent+label')
    st.plotly_chart(fig_oh, use_container_width=True)

st.subheader("📊 Latency Distribution Breakdown")
lat_data = pd.DataFrame({
    "Metric": ["Mean (µs)", "p95 (µs)", "p99 (µs)"],
    "Baseline": [
        data['latency']['baseline']['mean_us'],
        data['latency']['baseline']['p95_us'],
        data['latency']['baseline']['p99_us']
    ],
    "Hardened": [
        data['latency']['hardened']['mean_us'],
        data['latency']['hardened']['p95_us'],
        data['latency']['hardened']['p99_us']
    ]
})

fig_lat = go.Figure(data=[
    go.Bar(name='Baseline', x=lat_data['Metric'], y=lat_data['Baseline'], marker_color='#1f77b4'),
    go.Bar(name='Hardened', x=lat_data['Metric'], y=lat_data['Hardened'], marker_color='#ff7f0e')
])
fig_lat.update_layout(barmode='group', yaxis_title="Microseconds (µs)")
st.plotly_chart(fig_lat, use_container_width=True)
