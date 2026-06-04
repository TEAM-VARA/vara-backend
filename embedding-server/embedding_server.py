from fastapi import FastAPI
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer
from typing import Optional

app = FastAPI()

model = SentenceTransformer("BAAI/bge-m3")


class EmbedRequest(BaseModel):
    text: Optional[str] = None
    texts: Optional[list[str]] = None


@app.post("/embed")
def embed(req: EmbedRequest):
    # Batch mode: {"texts": ["text1", "text2"]}
    if req.texts is not None:
        vectors = model.encode(req.texts, normalize_embeddings=True)
        return {
            "model": "BAAI/bge-m3",
            "dimension": len(vectors[0]) if len(vectors) > 0 else 0,
            "embeddings": [v.tolist() for v in vectors],
        }

    # Single mode: {"text": "single string"}
    if req.text is not None:
        vector = model.encode(req.text, normalize_embeddings=True)
        return {
            "model": "BAAI/bge-m3",
            "dimension": len(vector),
            "embedding": vector.tolist(),
        }

    return {"error": "text or texts field required"}
