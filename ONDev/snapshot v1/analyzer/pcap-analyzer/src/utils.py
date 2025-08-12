def format_packet_data(packet):
    # Function to format packet data for display
    return {
        'timestamp': packet.time,
        'source': packet[IP].src if IP in packet else None,
        'destination': packet[IP].dst if IP in packet else None,
        'protocol': packet.proto,
        'length': len(packet)
    }

def save_uploaded_file(uploaded_file):
    # Function to save the uploaded file to a temporary location
    with open(f"temp/{uploaded_file.name}", "wb") as f:
        f.write(uploaded_file.getbuffer())

def clear_session_state():
    # Function to clear session state
    import streamlit as st
    if 'uploaded_file' in st.session_state:
        del st.session_state['uploaded_file']
    if 'parsed_data' in st.session_state:
        del st.session_state['parsed_data']