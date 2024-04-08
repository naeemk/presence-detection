class ProbeRequest:
    def __init__(self, macaddress, rssi, fingerprint):
        self.macaddress = macaddress
        self.rssi = rssi
        self.fingerprint = fingerprint