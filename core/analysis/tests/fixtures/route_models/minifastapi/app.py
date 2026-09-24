"""FastAPI fixture: verb decorators, router prefix, api_route."""
from fastapi import APIRouter, FastAPI

app = FastAPI()
router = APIRouter(prefix="/v1")


@app.get("/items/{item_id}")
def read_item(item_id):
    return item_id


@router.post("/orders")
def create_order():
    return []


@app.api_route("/multi", methods=["GET", "PUT"])
def multi():
    return "multi"
