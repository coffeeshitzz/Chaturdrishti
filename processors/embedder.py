import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from loguru import logger
from typing import List
from sentence_transformers import SentenceTransformer
from graph.schema import Signal

# Load model once at module level
# all-MiniLM-L6-v2 is fast, lightweight, and great for semantic similarity
MODEL_NAME = "all-MiniLM-L6-v2"
model = SentenceTransformer(MODEL_NAME)


class SignalEmbedder:
    """
    Converts signal raw content into dense vector embeddings
    using sentence-transformers. Enables semantic similarity
    search across signals from different sources.
    """

    def embed(self, signal: Signal) -> Signal:
        """Embed a single signal."""
        if not signal.raw_content:
            return signal

        embedding = model.encode(
            signal.raw_content,
            normalize_embeddings=True
        ).tolist()

        signal.embedding = embedding
        return signal

    def embed_batch(self, signals: List[Signal]) -> List[Signal]:
        """
        Embed a batch of signals efficiently.
        sentence-transformers handles batching internally.
        """
        logger.info(f"  Embedding {len(signals)} signals...")

        texts = [s.raw_content for s in signals]
        embeddings = model.encode(
            texts,
            batch_size=32,
            normalize_embeddings=True,
            show_progress_bar=True
        ).tolist()

        for signal, embedding in zip(signals, embeddings):
            signal.embedding = embedding

        logger.success(f"  ✅ Embedding complete — {len(signals)} signals embedded")
        return signals

    def find_similar(
        self,
        query: str,
        signals: List[Signal],
        top_k: int = 5
    ) -> List[Signal]:
        """
        Find the most semantically similar signals to a query string.
        Useful for the inference engine to retrieve relevant context.
        """
        import numpy as np

        query_embedding = model.encode(
            query,
            normalize_embeddings=True
        )

        # Filter signals that have embeddings
        embedded_signals = [s for s in signals if s.embedding]
        if not embedded_signals:
            return []

        # Compute cosine similarity
        embeddings_matrix = np.array([s.embedding for s in embedded_signals])
        similarities = embeddings_matrix @ query_embedding

        # Get top_k indices
        top_indices = np.argsort(similarities)[::-1][:top_k]

        results = []
        for idx in top_indices:
            signal = embedded_signals[idx]
            logger.debug(
                f"  Similar signal [{similarities[idx]:.3f}]: "
                f"{signal.raw_content[:60]}"
            )
            results.append(signal)

        return results