from __future__ import annotations

import base64  # Modulo per codifica/decodifica base64
import hashlib  # Funzioni crittografiche di hash
import io
import os
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

from .config import env


class Hasher:
    """Wrapper semplice attorno a hashlib per calcolare digest incrementali."""

    def __init__(self, algo: str = "sha256"):
        # Inizializza un nuovo oggetto hash con l'algoritmo indicato (default SHA-256)
        self._h = hashlib.new(algo)
        self.algo = algo

    def update(self, data: bytes) -> None:
        """Aggiorna lo stato dell'hash con un nuovo blocco di dati."""
        self._h.update(data)

    def hexdigest(self) -> str:
        """Restituisce il digest esadecimale dell'hash calcolato."""
        return self._h.hexdigest()


class AESGCMStream:
    """
    Cifratura/decifratura in streaming usando AES-GCM.

    Formato del file cifrato: [nonce(12)] [ciphertext ...] [tag(16)].
    - nonce: numero casuale unico per ogni cifratura.
    - ciphertext: dati cifrati in streaming.
    - tag: tag di autenticazione GCM per integrità e autenticità.
    """

    NONCE_LEN = 12
    TAG_LEN = 16

    @staticmethod
    def generate_key() -> bytes:
        """Genera una chiave casuale a 256 bit per AES-256."""
        return os.urandom(32)  # AES-256

    @staticmethod
    def encrypt_stream(
        fin: io.BufferedReader,
        fout: io.BufferedWriter,
        key: bytes,
        chunk_size: int = 1024 * 1024,
        hash_plain: Optional[Hasher] = None,
        hash_cipher: Optional[Hasher] = None,
    ) -> tuple[int, int]:
        """
        Cifra da fin a fout in streaming usando AES-GCM.

        Layout in uscita: [nonce][ciphertext...][tag].

        Ritorna: (plain_size, cipher_size).
        Se hash_plain/hash_cipher sono forniti, vengono aggiornati al volo
        rispettivamente con i dati in chiaro e con i dati cifrati.
        """
        # Genera nonce casuale e scrivilo all'inizio dell'output
        nonce = os.urandom(AESGCMStream.NONCE_LEN)
        fout.write(nonce)
        if hash_cipher:
            hash_cipher.update(nonce)

        # Crea l'oggetto encryptor AES-GCM
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend(),
        ).encryptor()

        plain_size = 0
        cipher_size = AESGCMStream.NONCE_LEN  # abbiamo già scritto il nonce

        # Legge il file a blocchi, cifra e scrive in streaming
        while True:
            chunk = fin.read(chunk_size)
            if not chunk:
                break
            plain_size += len(chunk)
            if hash_plain:
                hash_plain.update(chunk)

            ct_chunk = encryptor.update(chunk)
            if ct_chunk:
                fout.write(ct_chunk)
                cipher_size += len(ct_chunk)
                if hash_cipher:
                    hash_cipher.update(ct_chunk)

        # Finalizza la cifratura e scrive il tag GCM in coda
        encryptor.finalize()
        tag = encryptor.tag
        fout.write(tag)
        cipher_size += len(tag)
        if hash_cipher:
            hash_cipher.update(tag)

        return plain_size, cipher_size

    @staticmethod
    def decrypt_stream(
        fin: io.BufferedReader,
        fout: io.BufferedWriter,
        key: bytes,
        chunk_size: int = 1024 * 1024,
        hash_plain: Optional[Hasher] = None,
    ) -> int:
        """
        Decifra da fin a fout in streaming.
        Si aspetta layout: [nonce(12)][ciphertext...][tag(16)].

        Ritorna: plain_size (numero di byte in chiaro scritti).

        Richiede che 'fin' sia seekable (supporti tell/seek).
        """
        start_pos = fin.tell()

        # Legge il nonce all'inizio del flusso
        nonce = fin.read(AESGCMStream.NONCE_LEN)
        if len(nonce) != AESGCMStream.NONCE_LEN:
            raise ValueError("Ciphertext too short (missing nonce)")

        # Calcola la posizione di fine per ricavare la lunghezza totale
        fin.seek(0, io.SEEK_END)
        end_pos = fin.tell()

        total_len = end_pos - start_pos
        if total_len < AESGCMStream.NONCE_LEN + AESGCMStream.TAG_LEN:
            raise ValueError("Ciphertext too short (no room for tag)")

        # La posizione del tag corrisponde agli ultimi TAG_LEN byte del file
        tag_pos = end_pos - AESGCMStream.TAG_LEN

        fin.seek(tag_pos, io.SEEK_SET)
        tag = fin.read(AESGCMStream.TAG_LEN)
        if len(tag) != AESGCMStream.TAG_LEN:
            raise ValueError("Missing GCM tag at the end of ciphertext")

        # Crea il decryptor AES-GCM usando nonce e tag
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend(),
        ).decryptor()

        # La parte cifrata inizia subito dopo il nonce e termina prima del tag
        ct_start = start_pos + AESGCMStream.NONCE_LEN
        fin.seek(ct_start, io.SEEK_SET)

        cipher_bytes_len = tag_pos - ct_start
        remaining = cipher_bytes_len

        plain_size = 0

        # Legge i blocchi cifrati, li decifra e li scrive in output
        while remaining > 0:
            to_read = min(chunk_size, remaining)
            chunk = fin.read(to_read)
            if not chunk:
                raise ValueError("Unexpected EOF while reading ciphertext")
            remaining -= len(chunk)

            pt_chunk = decryptor.update(chunk)
            if pt_chunk:
                fout.write(pt_chunk)
                plain_size += len(pt_chunk)
                if hash_plain:
                    hash_plain.update(pt_chunk)

        # Finalizza la decifratura: qui viene verificato il tag GCM
        decryptor.finalize()
        return plain_size


def maybe_wrap_key(raw_key: bytes) -> dict:
    """
    Applica opzionalmente il key wrapping RSA-OAEP alla chiave AES.

    Se WRAP_AES_KEY_WITH_RSA=false (o non impostato), restituisce la chiave
    in chiaro codificata in base64.
    Se true, cifra la chiave con la chiave pubblica RSA usando OAEP+SHA-256
    e restituisce un dizionario con la chiave avvolta.
    """
    wrap = os.getenv("WRAP_AES_KEY_WITH_RSA", "false").lower() == "true"
    if not wrap:
        # Modalità semplice: salviamo la chiave AES in chiaro (ma base64-encoded)
        return {"mode": "raw", "key_b64": base64.b64encode(raw_key).decode()}

    # Modalità avanzata: key wrapping con chiave pubblica RSA
    pub_pem = env("RSA_PUBLIC_KEY_PEM")
    pub = load_pem_public_key(pub_pem.encode(), backend=default_backend())
    wrapped = pub.encrypt(
        raw_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return {"mode": "rsa_oaep_sha256", "wrapped_b64": base64.b64encode(wrapped).decode()}


def maybe_unwrap_key(stored: dict) -> bytes:
    """
    Inverso di maybe_wrap_key: recupera la chiave AES dal formato salvato.

    - Se mode == "raw": decodifica la chiave base64 e la restituisce.
    - Se mode == "rsa_oaep_sha256": usa la chiave privata RSA per decrittare
      la chiave AES avvolta con OAEP+SHA-256.
    """
    mode = stored.get("mode")
    if mode == "raw":
        # nosec: la chiave viene comunque gestita in memoria; il controllo
        # di sicurezza è demandato a come viene archiviato 'stored'.
        return base64.b64decode(stored["key_b64"])  # nosec
    elif mode == "rsa_oaep_sha256":
        priv_pem = env("RSA_PRIVATE_KEY_PEM")
        priv = load_pem_private_key(
            priv_pem.encode(), password=None, backend=default_backend()
        )
        wrapped = base64.b64decode(stored["wrapped_b64"])  # nosec
        return priv.decrypt(
            wrapped,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    else:
        raise ValueError(f"Unknown key storage mode: {mode}")
