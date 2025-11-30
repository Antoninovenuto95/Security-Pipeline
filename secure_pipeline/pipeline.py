from __future__ import annotations

# Abilita le annotazioni di tipo future-proof
import datetime as dt  # Gestione di date e orari
import os  # Accesso al filesystem e alle variabili d'ambiente
import tempfile
from typing import Any, Dict

from .config import MongoConfig, SFTPConfig, SMBConfig, env
from .crypto import AESGCMStream, Hasher, maybe_unwrap_key, maybe_wrap_key
from .storage import MetadataStore
from .transports import SFTPClient, SMBClient


class Pipeline:
    """Coordinatore principale del flusso: cifratura, storage e trasferimento SFTP."""

    def __init__(self):
        """Inizializza le connessioni a MongoDB, SMB e la configurazione SFTP."""
        # Istanzia il MetadataStore con la configurazione MongoDB letta dalle env
        self.mongo = MetadataStore(
            MongoConfig(
                uri=env("MONGO_URI", "mongodb://localhost:27017"),
                db=env("MONGO_DB", "secure_pipeline"),
                collection=env("MONGO_COLLECTION", "files"),
            )
        )
        # Client SMB per caricare/scaricare file cifrati da una share di rete
        self.smb = SMBClient(
            SMBConfig(
                server=env("SMB_SERVER"),
                username=env("SMB_USERNAME"),
                password=env("SMB_PASSWORD"),
                port=int(env("SMB_PORT", "445")),
                domain=env("SMB_DOMAIN", ""),
                share_path_prefix=env("SMB_PATH_PREFIX", "/"),
            )
        )
        # Configurazione SFTP (solo dati, il client viene creato on-demand)
        self.sftp_cfg = SFTPConfig(
            host=env("SFTP_HOST"),
            port=int(env("SFTP_PORT", "22")),
            username=env("SFTP_USERNAME"),
            password=os.getenv("SFTP_PASSWORD"),
            key_path=os.getenv("SFTP_KEY_PATH"),
            remote_dir=env("SFTP_REMOTE_DIR", "/"),
        )
        # Identificativo del dispositivo, utile per audit/log
        self.device_id = env("DEVICE_ID", os.getenv("COMPUTERNAME", "windows-host"))
        # Dimensione dei chunk per lettura/scrittura in streaming
        self.chunk_size = int(env("CHUNK_SIZE", "1048576"))

    # ---------- Encrypt + upload ----------
    def encrypt_and_upload(self, src_path: str) -> str:
        """Cifra un file locale e carica il ciphertext su SMB, salvando metadati in MongoDB.

        - Genera una chiave AES-256 casuale.
        - Cifra il file in streaming con AES-GCM calcolando hash plain/cipher.
        - Carica il file cifrato su SMB con path basato sulla data.
        - Salva in MongoDB tutti i metadati necessari per la futura decifratura.
        """
        # Genera chiave simmetrica e (opzionalmente) la avvolge con RSA
        key = AESGCMStream.generate_key()
        key_store = maybe_wrap_key(key)
        now = dt.datetime.now(dt.timezone.utc)

        # Hasher per contenuto in chiaro e cifrato
        h_plain = Hasher()
        h_ct = Hasher()

        # Cifra in un file temporaneo su disco
        with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tmp_ct:
            with open(src_path, "rb") as fin:
                plain_size, cipher_size = AESGCMStream.encrypt_stream(
                    fin=fin,
                    fout=tmp_ct,
                    key=key,
                    chunk_size=self.chunk_size,
                    hash_plain=h_plain,
                    hash_cipher=h_ct,
                )
            ct_path = tmp_ct.name

        # Nome remoto deterministico basato sull'hash del ciphertext
        remote_name = f"{h_ct.hexdigest()}.enc"
        # Struttura a directory per data: es. 2025/01/31/<hash>.enc
        remote_rel = os.path.join(now.strftime("%Y/%m/%d"), remote_name)
        self.smb.upload_file(ct_path, remote_rel)

        # Documento di metadati da salvare su MongoDB
        doc: Dict[str, Any] = {
            "device": self.device_id,
            "src_basename": os.path.basename(src_path),
            "plain_size": plain_size,
            "plain_sha256": h_plain.hexdigest(),
            "cipher_size": cipher_size,
            "cipher_sha256": h_ct.hexdigest(),
            "smb_rel_path": remote_rel,
            "aes_key": key_store,
            "created_utc": now,
            "algo": "AES-256-GCM",
            "nonce_len": AESGCMStream.NONCE_LEN,
            "tag_len": AESGCMStream.TAG_LEN,
        }
        # Inserisce il record in Mongo e rimuove il file temporaneo cifrato
        oid = self.mongo.insert_record(doc)
        os.remove(ct_path)
        return oid

    # ---------- Verify, decrypt, and push to SFTP ----------
    def verify_decrypt_and_push(self, oid: str) -> str:
        """Verifica integrità, decifra il file e lo invia via SFTP.

        Passi principali:
        1. Recupera il record da MongoDB tramite ObjectId.
        2. Scarica il file cifrato da SMB in un temporaneo.
        3. Verifica l'hash del ciphertext (nonce+ciphertext+tag).
        4. Recupera la chiave AES (eventualmente unwrappata da RSA).
        5. Decifra in streaming e verifica l'hash del plaintext.
        6. Carica il file in chiaro sul server SFTP.
        """
        rec = self.mongo.get_record(oid)
        if not rec:
            raise RuntimeError(f"Record not found: {oid}")

        # Scarica il file cifrato dalla share SMB in un file temporaneo
        with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tmp_ct:
            self.smb.download_file(rec["smb_rel_path"], tmp_ct.name)
            ct_path = tmp_ct.name

        # Verifica hash del ciphertext (nonce + ciphertext + tag)
        h = Hasher()
        with open(ct_path, "rb") as f:
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        if h.hexdigest() != rec["cipher_sha256"]:
            os.remove(ct_path)
            raise RuntimeError("Ciphertext hash mismatch — integrity check failed")

        # Ricostruisce la chiave AES a partire dai dati salvati su MongoDB
        key = maybe_unwrap_key(rec["aes_key"])

        # Decifra in streaming e calcola l'hash del plaintext
        h_plain = Hasher()
        with tempfile.NamedTemporaryFile(delete=False) as tmp_pt:
            with open(ct_path, "rb") as fin:
                AESGCMStream.decrypt_stream(
                    fin=fin,
                    fout=tmp_pt,
                    key=key,
                    chunk_size=self.chunk_size,
                    hash_plain=h_plain,
                )
            pt_path = tmp_pt.name

        # Verifica che il plaintext ottenuto combaci con l'hash atteso
        if h_plain.hexdigest() != rec["plain_sha256"]:
            os.remove(pt_path)
            os.remove(ct_path)
            raise RuntimeError("Plaintext hash mismatch — integrity check failed")

        # Apre un client SFTP e carica il file in chiaro
        sftp = SFTPClient(self.sftp_cfg)
        try:
            remote = sftp.upload(pt_path, remote_name=rec.get("src_basename"))
        finally:
            sftp.close()

        # Pulisce i file temporanei (plain e cipher)
        os.remove(pt_path)
        os.remove(ct_path)
        return remote
