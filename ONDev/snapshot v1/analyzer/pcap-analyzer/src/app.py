import streamlit as st
from parser import parse_pcap
from filters import filter_by_protocol, filter_by_ip, filter_by_length
from stats import protocol_distribution, packet_length_stats, top_talkers
from visualization import generate_bar_chart, generate_pie_chart, generate_line_chart
from geoip import map_ip_addresses

def main():
    st.title("PCAP Analyzer")
    
    uploaded_file = st.file_uploader("Upload a .pcap file", type=["pcap"])
    
    if uploaded_file is not None:
        # Store the uploaded file in session state
        st.session_state.uploaded_file = uploaded_file
        
        # Parse the pcap file
        parsed_data = parse_pcap(uploaded_file)
        st.session_state.parsed_data = parsed_data
        
        # Display filtering options
        protocol = st.selectbox("Filter by Protocol", options=["All", "TCP", "UDP", "ICMP"])
        ip_address = st.text_input("Filter by IP Address")
        length = st.number_input("Filter by Packet Length", min_value=0)
        
        filtered_data = parsed_data
        
        if protocol != "All":
            filtered_data = filter_by_protocol(filtered_data, protocol)
        if ip_address:
            filtered_data = filter_by_ip(filtered_data, ip_address)
        if length > 0:
            filtered_data = filter_by_length(filtered_data, length)
        
        # Display statistics
        st.subheader("Statistics")
        st.write("Protocol Distribution:", protocol_distribution(filtered_data))
        st.write("Packet Length Stats:", packet_length_stats(filtered_data))
        st.write("Top Talkers:", top_talkers(filtered_data))
        
        # Visualization
        st.subheader("Visualizations")
        st.pyplot(generate_bar_chart(filtered_data))
        st.pyplot(generate_pie_chart(filtered_data))
        st.pyplot(generate_line_chart(filtered_data))
        
        # Geolocation
        st.subheader("Geolocation")
        map = map_ip_addresses(filtered_data)
        st.write(map)
        
        # Raw Data View
        st.subheader("Raw Packet Data")
        st.write(filtered_data)

if __name__ == "__main__":
    main()