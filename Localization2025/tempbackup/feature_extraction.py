import pandas as pd
import numpy as np
from scapy.all import Dot11, Dot11Elt
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

def extract_features(probe_data):
    # Convert captured data into a DataFrame
    df = pd.DataFrame(probe_data)

    # Handle missing values (e.g., if RSSI is None)
    df["RSSI"] = df["RSSI"].fillna(df["RSSI"].mean())

    # Compute probe request intervals per MAC
    df["Timestamp_Diff"] = df.groupby("MAC")["Timestamp"].diff().fillna(0)
    df["Avg_Probe_Interval"] = df.groupby("MAC")["Timestamp_Diff"].transform("mean")
    df["Probe_Interval_Variance"] = df.groupby("MAC")["Timestamp_Diff"].transform("var").fillna(0)

    # Ensure Features column is a list of strings (if it's a list, join the elements into a single string)
    df["Features"] = df["Features"].apply(lambda x: " ".join(x) if isinstance(x, list) else x)

    # Encode SSIDs as numerical features using TF-IDF
    vectorizer = TfidfVectorizer()
    ssid_matrix = vectorizer.fit_transform(df["SSID"])
    
    # Encode Wi-Fi Capabilities using TF-IDF (assuming "Features" is now a list of features)
    feature_vectorizer = TfidfVectorizer()
    features_matrix = feature_vectorizer.fit_transform(df["Features"])

    # Normalize numerical features (RSSI, Avg Probe Interval, Probe Interval Variance)
    scaler = StandardScaler()
    numeric_features = scaler.fit_transform(df[["RSSI", "Avg_Probe_Interval", "Probe_Interval_Variance"]])

    # Combine all feature matrices into a single feature set
    X = np.hstack([ssid_matrix.toarray(), features_matrix.toarray(), numeric_features])
    
    return X, df
