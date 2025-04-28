

class KalmanFilter:
    def __init__(self, process_variance=1e-5, estimated_measurement_variance=1e-2):
        # Process variance (Q): how much we trust the model
        self.process_variance = process_variance
        # Measurement variance (R): how much we trust the measurements
        self.estimated_measurement_variance = estimated_measurement_variance
        # Initialize state
        self.posteri_estimate = 0.0
        self.posteri_error_estimate = 1.0

    def filter(self, measurement):
        # Prediction update
        priori_estimate = self.posteri_estimate
        priori_error_estimate = self.posteri_error_estimate + self.process_variance

        # Measurement update
        kalman_gain = priori_error_estimate / (priori_error_estimate + self.estimated_measurement_variance)
        self.posteri_estimate = priori_estimate + kalman_gain * (measurement - priori_estimate)
        self.posteri_error_estimate = (1 - kalman_gain) * priori_error_estimate

        return self.posteri_estimate
