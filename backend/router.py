from fastapi import APIRouter
from backend import schema,phish_url

url_router = APIRouter(
    prefix='/url',
    tags=['URL']
)


@url_router.post('/detect')
def detect(request:schema.URL):
    return phish_url.detect_url(request)
