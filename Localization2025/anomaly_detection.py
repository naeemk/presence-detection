import matplotlib.pyplot as plt
from scapy.all import Dot11Elt, Dot11ProbeReq  # Make sure Scapy is imported
from sklearn.ensemble import IsolationForest

def detect_anomalies(X, df):
    ## Apply Isolation Forest for anomaly detection (to detect new devices)
    #iso_forest = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    #df["Anomaly_Score"] = iso_forest.fit_predict(X)
    #print(df["Anomaly_Score"])
    ## Label "New" vs "Persistent" MACs based on anomaly scores
    #df["Device_Type"] = df["Anomaly_Score"].apply(lambda x: "New Device" if x == -1 else "Persistent Device")

    # Print the results
    #print(df[["MAC", "SSID", "RSSI", "Avg_Probe_Interval", "Device_Type"]])

    # Plot the results of anomaly detection (Red for "New Device" and Blue for "Persistent Device")
    #plt.figure(figsize=(10, 6))
    #colors = {"New Device": "red", "Persistent Device": "blue"}
    #plt.scatter(df.index, df["RSSI"], c=df["Device_Type"].map(colors), alpha=0.7)
    #plt.xlabel("Device Index")
    #plt.ylabel("RSSI (Signal Strength)")
    #plt.title("Anomaly Detection: New vs. Persistent Devices")
    #plt.show()

    ###############
    # Apply Isolation Forest for anomaly detection
    iso_forest = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    df["Anomaly_Score"] = iso_forest.fit_predict(X)

    # Remove false positives: Only consider devices that appear consistently as anomalies
    persistent_macs = df[df["Anomaly_Score"] == 1]["MAC"].unique()
    df_filtered = df[df["MAC"].isin(persistent_macs)].copy()  # Keep only persistent devices

    # Assign device labels
    df_filtered["Device_Type"] = "Persistent Device"

    # Print the results
    #print(df_filtered[["MAC", "SSID", "RSSI", "Avg_Probe_Interval", "Device_Type"]])

    return df_filtered  # Return the cleaned dataframe



    #SMA
    #df["SMA"] = df["RSSI"].rolling(window=5).mean()

    # Moving Average
    # Weighted average
    # Estimated Position
    