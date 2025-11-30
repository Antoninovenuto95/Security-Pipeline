from __future__ import annotations

# Supporto per annotazioni forward e typing moderno
from typing import Any, Dict  # Tipi generici per i documenti Mongo

from bson import ObjectId  # Gestione degli ObjectId MongoDB
from pymongo import MongoClient  # Client ufficiale MongoDB

from .config import MongoConfig


class MetadataStore:
    """
    Semplice wrapper attorno a una collezione MongoDB.

    Responsabilità:
    - Connessione al database
    - Inserimento record
    - Recupero record tramite ObjectId
    """

    def __init__(self, cfg: MongoConfig):
        """Inizializza il client MongoDB e seleziona la collezione indicata."""
        self.client = MongoClient(cfg.uri)
        self.col = self.client[cfg.db][cfg.collection]

    def insert_record(self, doc: Dict[str, Any]) -> str:
        """Inserisce un documento nella collezione e restituisce l'ObjectId come stringa."""
        res = self.col.insert_one(doc)
        return str(res.inserted_id)

    def get_record(self, oid: str) -> Dict[str, Any]:
        """Recupera un documento tramite il suo ObjectId (stringa)."""
        return self.col.find_one({"_id": ObjectId(oid)})