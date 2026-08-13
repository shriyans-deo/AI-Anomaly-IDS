from detection.detector import AnomalyDetector

MODEL_PATH = "detection/model"

detector = AnomalyDetector.load(MODEL_PATH)


def analyze_flow(flow: dict):
    return detector.score_one(flow)