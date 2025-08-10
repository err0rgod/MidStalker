import matplotlib.pyplot as plt
import streamlit as st

def generate_bar_chart(data, title="Bar Chart", xlabel="", ylabel=""):
    fig, ax = plt.subplots()
    ax.bar(data.keys(), data.values())
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    st.pyplot(fig)

def generate_pie_chart(data, title="Pie Chart"):
    fig, ax = plt.subplots()
    ax.pie(data.values(), labels=data.keys(), autopct='%1.1f%%')
    ax.set_title(title)
    st.pyplot(fig)

def generate_line_chart(x, y, title="Line Chart", xlabel="", ylabel=""):
    fig, ax = plt.subplots()
    ax.plot(x, y)
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    st.pyplot(fig)