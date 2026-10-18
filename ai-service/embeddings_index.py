"""
MITRE ATT&CK Embeddings Index

Downloads the MITRE ATT&CK Enterprise dataset, embeds technique descriptions
using sentence-transformers, and stores vectors in a local FAISS index for
semantic similarity search.
"""

import json
import os
import pickle
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

import numpy as np
import requests
from sentence_transformers import SentenceTransformer
import faiss

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# MITRE ATT&CK Enterprise dataset URL
MITRE_ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

# Local paths
CACHE_DIR = Path("/app/mitre_cache")
CACHE_DIR.mkdir(parents=True, exist_ok=True)
MITRE_JSON_PATH = CACHE_DIR / "enterprise-attack.json"
INDEX_PATH = CACHE_DIR / "mitre_index.faiss"
METADATA_PATH = CACHE_DIR / "mitre_metadata.pkl"

# Embedding model
EMBEDDING_MODEL = "all-MiniLM-L6-v2"  # Fast, good quality, 384 dimensions


class MITREEmbeddingsIndex:
    """FAISS index for MITRE ATT&CK technique descriptions."""

    def __init__(self, model_name: str = EMBEDDING_MODEL):
        self.model_name = model_name
        self.model: Optional[SentenceTransformer] = None
        self.index: Optional[faiss.Index] = None
        self.techniques: List[Dict[str, Any]] = []
        self._loaded = False

    def _load_model(self):
        """Load the sentence transformer model."""
        if self.model is None:
            logger.info(f"Loading embedding model: {self.model_name}")
            self.model = SentenceTransformer(self.model_name)
            logger.info("Model loaded successfully")

    def _download_mitre_data(self) -> Dict[str, Any]:
        """Download MITRE ATT&CK Enterprise dataset."""
        logger.info(f"Downloading MITRE ATT&CK data from {MITRE_ENTERPRISE_URL}")
        response = requests.get(MITRE_ENTERPRISE_URL, timeout=60)
        response.raise_for_status()
        data = response.json()

        # Cache locally
        with open(MITRE_JSON_PATH, 'w') as f:
            json.dump(data, f)

        logger.info("MITRE data downloaded and cached")
        return data

    def _load_mitre_data(self) -> Dict[str, Any]:
        """Load MITRE data from cache or download."""
        if MITRE_JSON_PATH.exists():
            logger.info("Loading MITRE data from cache")
            with open(MITRE_JSON_PATH, 'r') as f:
                return json.load(f)
        return self._download_mitre_data()

    def _extract_techniques(self, mitre_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract technique objects from MITRE STIX data."""
        techniques = []

        for obj in mitre_data.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                # Skip revoked/deprecated techniques
                if obj.get('revoked', False) or obj.get('x_mitre_deprecated', False):
                    continue

                # Get technique ID (e.g., T1078, T1078.001)
                external_refs = obj.get('external_references', [])
                technique_id = None
                for ref in external_refs:
                    if ref.get('source_name') == 'mitre-attack':
                        technique_id = ref.get('external_id')
                        break

                if not technique_id:
                    continue

                # Build description from name and description
                name = obj.get('name', '')
                description = obj.get('description', '')

                # Get tactic(s)
                tactics = []
                for phase in obj.get('kill_chain_phases', []):
                    if phase.get('kill_chain_name') == 'mitre-attack':
                        tactics.append(phase.get('phase_name'))

                # Get platforms
                platforms = obj.get('x_mitre_platforms', [])

                # Get data sources
                data_sources = obj.get('x_mitre_data_sources', [])

                # Combine text for embedding
                combined_text = f"{technique_id}: {name}. {description}"
                if tactics:
                    combined_text += f" Tactics: {', '.join(tactics)}."
                if platforms:
                    combined_text += f" Platforms: {', '.join(platforms)}."

                techniques.append({
                    'id': technique_id,
                    'name': name,
                    'description': description,
                    'tactics': tactics,
                    'platforms': platforms,
                    'data_sources': data_sources,
                    'combined_text': combined_text,
                    'url': f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
                })

        logger.info(f"Extracted {len(techniques)} techniques from MITRE data")
        return techniques

    def _build_index(self, techniques: List[Dict[str, Any]]):
        """Build FAISS index from technique embeddings."""
        self._load_model()

        texts = [t['combined_text'] for t in techniques]
        logger.info(f"Embedding {len(texts)} technique descriptions...")

        # Generate embeddings in batches
        embeddings = self.model.encode(
            texts,
            batch_size=32,
            show_progress_bar=True,
            convert_to_numpy=True,
            normalize_embeddings=True  # For cosine similarity
        )

        # Create FAISS index (Inner Product = cosine similarity with normalized vectors)
        dimension = embeddings.shape[1]
        self.index = faiss.IndexFlatIP(dimension)
        self.index.add(embeddings.astype(np.float32))

        logger.info(f"FAISS index built with {self.index.ntotal} vectors of dimension {dimension}")

        # Save index and metadata
        faiss.write_index(self.index, str(INDEX_PATH))
        with open(METADATA_PATH, 'wb') as f:
            pickle.dump(techniques, f)

        self.techniques = techniques
        self._loaded = True

    def _load_index(self) -> bool:
        """Load FAISS index and metadata from disk."""
        if not INDEX_PATH.exists() or not METADATA_PATH.exists():
            return False

        try:
            logger.info("Loading FAISS index from cache")
            self.index = faiss.read_index(str(INDEX_PATH))
            with open(METADATA_PATH, 'rb') as f:
                self.techniques = pickle.load(f)
            self._loaded = True
            logger.info(f"Loaded index with {self.index.ntotal} techniques")
            return True
        except Exception as e:
            logger.warning(f"Failed to load cached index: {e}")
            return False

    def initialize(self, force_rebuild: bool = False):
        """Initialize the index (load from cache or build)."""
        if self._loaded and not force_rebuild:
            return

        if not force_rebuild and self._load_index():
            return

        logger.info("Building MITRE embeddings index from scratch...")
        mitre_data = self._load_mitre_data()
        self.techniques = self._extract_techniques(mitre_data)
        self._build_index(self.techniques)

    def search(self, query: str, top_k: int = 10) -> List[Dict[str, Any]]:
        """Search for techniques similar to the query text."""
        if not self._loaded:
            self.initialize()

        self._load_model()

        # Embed query
        query_embedding = self.model.encode(
            [query],
            convert_to_numpy=True,
            normalize_embeddings=True
        ).astype(np.float32)

        # Search
        scores, indices = self.index.search(query_embedding, top_k)

        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx >= 0 and idx < len(self.techniques):
                tech = self.techniques[idx].copy()
                tech['confidence'] = float(score)
                results.append(tech)

        return results

    def get_technique_by_id(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get technique metadata by ID."""
        for tech in self.techniques:
            if tech['id'] == technique_id:
                return tech
        return None


# Singleton instance
_index_instance: Optional[MITREEmbeddingsIndex] = None


def get_index() -> MITREEmbeddingsIndex:
    """Get the global index instance."""
    global _index_instance
    if _index_instance is None:
        _index_instance = MITREEmbeddingsIndex()
    return _index_instance


def initialize_index(force_rebuild: bool = False):
    """Initialize the global index."""
    get_index().initialize(force_rebuild)


if __name__ == "__main__":
    # Test the index
    idx = MITREEmbeddingsIndex()
    idx.initialize()
    results = idx.search("ssh brute force login", top_k=5)
    for r in results:
        print(f"{r['id']} - {r['name']} (confidence: {r['confidence']:.3f})")