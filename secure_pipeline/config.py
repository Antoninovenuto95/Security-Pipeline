from __future__ import annotations

# Importa il modulo os per leggere variabili d'ambiente
import os
# Importa dataclass per definire configurazioni strutturate
from dataclasses import dataclass
# Importa Optional per definire parametri facoltativi
from typing import Optional


def env(key: str, default: Optional[str] = None) -> str:
    """
    Funzione helper per leggere le variabili d'ambiente.
    - key: nome della variabile d'ambiente da leggere.
    - default: valore di fallback se la variabile non è presente.
    Se la variabile è obbligatoria e non è presente, solleva un errore.
    """
    val = os.getenv(key, default)
    if val is None:
        raise RuntimeError(f"Missing required env: {key}")
    return val


@dataclass
class SMBConfig:
    """
    Configurazione per la connessione a un server SMB/CIFS.
    - server: indirizzo/server SMB da montare.
    - username: utente Samba.
    - password: password Samba.
    - port: porta SMB (default 445).
    - domain: eventuale dominio/WORKGROUP.
    - share_path_prefix: percorso radice della share remota.
    """
    server: str
    username: str
    password: str
    port: int = 445
    domain: str = ""
    share_path_prefix: str = "/"


@dataclass
class SFTPConfig:
    """
    Configurazione per connessione SFTP.
    - host: indirizzo del server SFTP.
    - port: porta del server.
    - username: utente SFTP.
    - password: password (opzionale se si usa key_path).
    - key_path: percorso chiave privata SSH.
    - remote_dir: directory remota dove caricare i file.
    """
    host: str
    port: int
    username: str
    password: Optional[str] = None
    key_path: Optional[str] = None
    remote_dir: str = "/"


@dataclass
class MongoConfig:
    """
    Configurazione per connessione a MongoDB.
    - uri: stringa di connessione Mongo.
    - db: nome del database.
    - collection: collezione in cui salvare i metadati.
    """
    uri: str
    db: str
    collection: str
