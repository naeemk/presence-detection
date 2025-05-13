import matplotlib.pyplot as plt
import json

# Easily editable variables
ssid_data_length = [28, 43, 32, 44, 68, 81, 90, 97, 117, 130, 147, 148, 152, 156, 164, 177]
feature_data_length = [12, 14, 15, 17, 18, 20, 20, 20, 23, 24, 23, 23, 23, 23, 24, 24]
minutes = list(range(1, len(ssid_data_length) + 1))

def plot_graph():
    fig, ax = plt.subplots()

    bar_width = 0.4
    index = range(len(minutes))

    ax.bar([i - bar_width / 2 for i in index], ssid_data_length, bar_width, label='SSID Groups', color='#2ecc71')
    ax.bar([i + bar_width / 2 for i in index], feature_data_length, bar_width, label='Feature Groups', color='#3498db')

    ax.set_xlabel('Minutes')
    ax.set_ylabel('Number of Groups')
    ax.set_title('Comparison of SSID Groups and Feature Groups per Minute')
    ax.set_xticks(index)
    ax.set_xticklabels(minutes)
    ax.legend()

    plt.show()

plot_graph()
