from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from backend import router



app = FastAPI()
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"], # Allows all methods (GET, POST, etc.)
    allow_headers=["*"], # Allows all headers
)

app.include_router(router.url_router)

# @app.post('/detect_url')
# def detect(request:schema.URL):
#     extracted_feature_values = extract_features(request.url)
#     result = model.url_model.predict(extracted_feature_values)[0]
#     if result == 1:
#         return {"Output":"Phishing"}
#     else:
#         return {"Output": "Legitimate"}