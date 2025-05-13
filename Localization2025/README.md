## Setup Instructions

> [!Note]
> An antenna with monitor mode enabled is required to capture packets!

1. **Clone the repository**:

    ```bash
    git clone git@github.com:naeemk/presence-detection.git    
    cd presence-detection/Localization2025
    ```

2. **Create a virtual environment**:

    ```bash
    python3 -m venv myenv
    ```

3. **Activate the virtual environment**:

    ```bash
    source myenv/bin/activate  # On Linux/macOS
    myenv\Scripts\activate.bat  # On Windows
    ```

4. **Install dependencies**:

    ```bash
    pip install -r requirements.txt
    ```

5. **Run your project**:

    ```bash
    sudo myenv/bin/python3 main.py # Linux
    python main.py # Windows
    ```

---

# Configuration Overview (config.json)

This file contains configuration options for the probe request fingerprinting project.

## General Settings

* **interface**: Network interface for sniffing (e.g., `wlan0`).
* **time\_window**: Data collection duration in seconds (default: 120).
* **capture\_delay**: Delay between capture sessions in seconds (default: 30).
* **duration\_of\_sniffing**: Length of each sniffing session in seconds (default: 10).
* **fake\_seconds\_offline**: Delay between packet when using offline mode.

## Distance Calculation

* **rssi\_1\_meter**: RSSI value at 1 meter.
* **path\_loss\_exponent**: Factor for signal loss over distance.
* **shadowing\_effect**: Adjustment for obstacles.
* **reference\_distance**: Base distance for calculations.
* **environmental\_correction\_constant**: Factor for environment-based adjustments.

## Fingerprint

* **ssid\_common\_threshold**: Threshold for finding common SSIDs.
* **group\_ssid\_match\_threshold**: Threshold for grouping similar SSIDs.

## Kalman Filter

* **posteri\_error\_estimate**: Initial error estimate.
* **process\_variance**: Smoothness factor.
* **estimated\_measurement\_variance**: Measurement noise variance.

## Feature Weights

* **supported\_rates**: Basic rates weight.
* **extended\_supported\_rates**: Extended rates weight.
* **erp\_information**: ERP info weight.
* **ht\_capabilities**: High Throughput features weight.
* **extended\_capabilities**: Extended features weight.
* **vht\_capabilities**: Very High Throughput features weight.
* **vendor\_specific**: Vendor-specific features weight.

## Plot Settings

* **max\_distance**: Max distance displayed.
* **max\_alpha**: Max opacity for points.
* **min\_alpha**: Min opacity for points.
* **fade\_time**: Fade-out duration for points.

## File Paths

* Paths to store and retrieve **data files**, including packet captures and result files.
