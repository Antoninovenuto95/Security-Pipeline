# File Encryption, Integrity & Secure Transfer

Il sistema è completamente containerizzato e fornisce:

1. **Cifratura dei file** tramite AES‑256‑GCM  
2. **Storage sicuro dei ciphertext** su una share SMB  
3. **Archiviazione metadati e chiavi** (opzionalmente con RSA-OAEP) in MongoDB  
4. **Verifica integrità + decifratura** su richiesta  
5. **Trasferimento finale del file in chiaro** tramite SFTP  

Tutto funziona in **streaming**, per gestire file molto grandi senza caricarli in RAM.

---

# Struttura del progetto

```
secure-pipeline/
│
├── docker-compose.yml        # Orchestrazione completa: MongoDB, Samba, SFTP e app Python
├── Dockerfile                # Costruzione dell’immagine Docker per l’app Secure Pipeline
├── requirements.txt          # Dipendenze Python necessarie all’app
│
├── secure_pipeline/          # Codice principale dell’applicazione
│   │
│   ├── __init__.py           # Esporta Pipeline e definisce il pacchetto Python
│   ├── cli.py                # Entry point CLI: comandi encrypt/decrypt
│   ├── __main__.py           # Permette l'esecuzione con: python -m secure_pipeline
│   │
│   ├── config.py             # Caricamento configurazione e modelli (SFTP/SMB/Mongo)
│   ├── crypto.py             # AES-GCM streaming, hashing, RSA key wrapping/unwrapping
│   ├── pipeline.py           # Pipeline completa: cifratura → upload SMB → Mongo → decifratura → SFTP
│   ├── storage.py            # Gestione dei metadati su MongoDB
│   └── transports.py         # Client SMB (smbclient) e SFTP (paramiko)
│
├── samba-data/               # Volume locale montato come share SMB (contiene ciphertext)
├── sftp-data/                # Volume locale per il container SFTP
│   └── upload/               # Directory remota dove finiscono i file decifrati
│
└── test.txt                  # File di esempio per testare la pipeline
```

---

# Funzionamento della pipeline

## 1) Cifratura + upload SMB

Comando:

```
docker-compose run --rm app encrypt /data/test.txt
```

Cosa succede:

- Generazione chiave AES‑256  
- (Opzionale) RSA-OAEP wrapping  
- Cifratura streaming AES-GCM  
- Calcolo hash plaintext e ciphertext  
- Upload del ciphertext nella share SMB interna (samba-data/)  
- Salvataggio metadati e chiave in MongoDB  
- Restituzione dell’ObjectId che identifica il file  

---

## 2) Verifica integrità + decifratura + upload SFTP

Comando:

```
docker-compose run --rm app decrypt <mongodb_id>
```

Cosa succede:

- Estrae i metadati da Mongo  
- Scarica il ciphertext da Samba  
- Verifica SHA‑256 del ciphertext  
- Recupera e unwrappa la chiave AES (se RSA)  
- Decifra il file in streaming  
- Verifica SHA‑256 del plaintext  
- Carica il file in chiaro via SFTP (sftp-data/upload/)  
- Restituisce il percorso remoto  

---

# Utilizzo con Docker

## 1) Build iniziale

```
docker-compose build
```

## 2) Avviare i servizi di base

```
docker-compose up -d
```

Questo avvia:

- MongoDB → `mongo-secure-pipeline`
- Samba → `samba-secure-pipeline`
- SFTP → `sftp-secure-pipeline`
- L’app viene lanciata on‑demand (run/exec)

## 3) Cifrare un file

Assicurati che il file si trovi nella directory del progetto:

```
echo "CIAO MONDO" > test.txt
docker-compose run --rm app encrypt /data/test.txt
```

Output:

```json
{
  "ok": true,
  "mongodb_id": "65f0a8c5f0e8ad3f9f0b1234"
}
```

## 4) Decifrare + inviare via SFTP

```
docker-compose run --rm app decrypt 65f0a8c5f0e8ad3f9f0b1234
```

Output:

```json
{
  "ok": true,
  "sftp_remote": "/upload/test.txt"
}
```

Il file decifrato sarà dentro:

```
./sftp-data/upload/
```

---

# Configurazione Docker

Tutte le variabili necessarie all’applicazione sono definite nel docker-compose nella sezione:

```
services.app.environment:
```

---

# Sicurezza

- **AES‑256‑GCM** → confidenzialità + autenticazione integrata  
- **SHA‑256 su plaintext e ciphertext** → doppia verifica integrità  
- **RSA‑OAEP SHA‑256 (opzionale)** → wrapping sicuro della chiave AES  
- **File temporanei eliminati automaticamente**  
- **Nessun venv necessario** → ambiente sempre pulito e riproducibile mediante Docker  


