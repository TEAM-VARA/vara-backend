# embedding_server.py
from fastapi import FastAPI
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer

app = FastAPI()

model = SentenceTransformer("BAAI/bge-m3")

class EmbedRequest(BaseModel):
    text: str

@app.post("/embed")
def embed(req: EmbedRequest):
    vector = model.encode(req.text, normalize_embeddings=True)

    return {
        "model": "BAAI/bge-m3",
        "dimension": len(vector),
        "embedding": vector.tolist()
    }