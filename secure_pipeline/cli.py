from __future__ import annotations

# Import dei moduli standard della libreria Python
import json
import sys
from typing import List

# Carica le variabili d'ambiente dal file .env
from dotenv import load_dotenv

# Importa la classe Pipeline che gestisce cifratura e decifratura
from .pipeline import Pipeline


def main(argv: List[str]) -> int:
    """
    Entry point dell'applicazione CLI. Gestisce i comandi:
      - encrypt <file>
      - decrypt <mongodb_id>

    argv: lista di argomenti da riga di comando.
    Ritorna un codice di uscita POSIX standard (0=successo, 2=errore input).
    """

    # Carica automaticamente le variabili dal file .env nella root del progetto.
    load_dotenv()

    # Controlla che ci siano almeno due argomenti: il comando e il valore.
    if len(argv) < 2:
        print("Usage:\n  encrypt <file>\n  decrypt <mongodb_id>")
        return 2

    cmd = argv[1]

    # Istanzia il Pipeline che contiene la logica di cifratura, salvataggio e recupero.
    pipe = Pipeline()

    # === Comando ENCRYPT ===
    if cmd == "encrypt":
        # Verifica che sia stato fornito il percorso al file
        if len(argv) != 3:
            print("Usage: encrypt <file>")
            return 2

        # Esegue la cifratura del file e l'upload verso MongoDB/Samba
        oid = pipe.encrypt_and_upload(argv[2])

        # Stampa un output JSON strutturato, utile per script automatizzati
        print(json.dumps({"ok": True, "mongodb_id": oid}, indent=2, default=str))
        return 0

    # === Comando DECRYPT ===
    elif cmd == "decrypt":
        # Verifica che sia stato fornito l'ObjectId MongoDB
        if len(argv) != 3:
            print("Usage: decrypt <mongodb_id>")
            return 2

        # Verifica, decifra e invia il file tramite SFTP
        remote = pipe.verify_decrypt_and_push(argv[2])

        # Output JSON con il percorso remoto del file trasferito
        print(json.dumps({"ok": True, "sftp_remote": remote}, indent=2))
        return 0

    # === Comando non riconosciuto ===
    else:
        print("Unknown command")
        return 2
