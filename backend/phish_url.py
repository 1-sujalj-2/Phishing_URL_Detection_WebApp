from backend import schema
from backend.extract import extract_features
from backend import model


def detect_url(request:schema.URL):
    extracted_feature_values = extract_features(request.url)
    result = model.url_model.predict(extracted_feature_values)[0]
    if result == 1:
        return {"Output":"Phishing"}
    else:
        return {"Output": "Legitimate"}