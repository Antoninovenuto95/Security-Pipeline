from __future__ import annotations

# Moduli standard: gestione percorsi, variabili d'ambiente
import os  # Usato per path e generazione GUID client SMB
from typing import Optional  # Parametri opzionali nelle funzioni

import paramiko  # Libreria SSH/SFTP
import smbclient  # Client SMB/CIFS Python

from .config import SMBConfig, SFTPConfig


class SMBClient:
    """
    Client SMB per caricare e scaricare file da una share di rete.

    Responsabilità:
    - Registrare una sessione SMB usando credenziali e porta personalizzata.
    - Costruire percorsi UNC remoti.
    - Creare directory lato SMB quando necessario.
    - Eseguire upload/download in streaming.
    """

    def __init__(self, cfg: SMBConfig):
        self.cfg = cfg

        # Parsing dell'URL SMB: deve essere nel formato //host/share
        path = cfg.server
        if not path.startswith("//"):
            raise ValueError("SMB_SERVER must look like //server/share")

        # Estrae host e share dal formato //host/share
        _, _, host_share = path.partition("//")
        host, _, share = host_share.partition("/")
        self.host = host
        self.share = share

        # Configurazione client SMB: GUID casuale
        smbclient.ClientConfig(client_guid=os.urandom(16))

        # Registra la sessione SMB con credenziali e porta
        smbclient.register_session(
            self.host,
            username=self.cfg.username,
            password=self.cfg.password,
            port=self.cfg.port,
        )

    def _build_unc(self, remote_rel_path: str) -> str:
        """Costruisce il percorso UNC finale del file remoto."""
        prefix = self.cfg.share_path_prefix.lstrip("/\\")
        rel_path = os.path.join(prefix, remote_rel_path)
        rel_path = rel_path.replace("/", "\\")
        return fr"\\{self.host}\{self.share}\{rel_path}"

    def _ensure_remote_dirs(self, remote_rel_path: str) -> None:
        """
        Crea ricorsivamente le directory remote necessarie nella share SMB.
        Ignora gli errori se la directory esiste già.
        """
        prefix = self.cfg.share_path_prefix.lstrip("/\\")
        rel_dir = os.path.dirname(remote_rel_path)
        if rel_dir:
            combined = os.path.join(prefix, rel_dir).replace("/", "\\")
        else:
            combined = prefix

        if not combined:
            return

        parts = combined.split("\\")
        current = ""
        for part in parts:
            if not part:
                continue
            current = f"{current}\\{part}" if current else part
            unc_dir = fr"\\{self.host}\{self.share}\{current}"
            try:
                smbclient.mkdir(
                    unc_dir,
                    username=self.cfg.username,
                    password=self.cfg.password,
                    port=self.cfg.port,
                )
            except OSError:
                # directory already exists
                pass

    def upload_file(self, local_path: str, remote_rel_path: str) -> str:
        """Carica un file locale sulla share SMB in modalità streaming."""
        self._ensure_remote_dirs(remote_rel_path)

        unc_path = self._build_unc(remote_rel_path)
        with open(local_path, "rb") as src, smbclient.open_file(
            unc_path,
            mode="wb",
            username=self.cfg.username,
            password=self.cfg.password,
            port=self.cfg.port,
        ) as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)
        return unc_path

    def download_file(self, remote_rel_path: str, local_path: str) -> str:
        """Scarica un file remoto dalla share SMB verso un file locale."""
        unc_path = self._build_unc(remote_rel_path)
        with smbclient.open_file(
            unc_path,
            mode="rb",
            username=self.cfg.username,
            password=self.cfg.password,
            port=self.cfg.port,
        ) as src, open(local_path, "wb") as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)
        return unc_path


class SFTPClient:
    """
    Client SFTP minimale basato su Paramiko.

    Responsabilità:
    - Stabilire connessione SSH tramite password o chiave privata.
    - Verificare/creare cartella remota.
    - Caricare file mantenendo il nome o fornendone uno personalizzato.
    """

    def __init__(self, cfg: SFTPConfig):
        # Inizializza trasporto SSH verso host/porta indicati
        self.transport = paramiko.Transport((cfg.host, cfg.port))

        # Autenticazione via chiave privata o password
        if cfg.key_path:
            pkey = paramiko.RSAKey.from_private_key_file(cfg.key_path)
            self.transport.connect(username=cfg.username, pkey=pkey)
        else:
            self.transport.connect(username=cfg.username, password=cfg.password)

        # Istanze del client SFTP
        self.sftp = paramiko.SFTPClient.from_transport(self.transport)

        # Rimozione slash superflui e normalizzazione directory remota
        self.remote_dir = (cfg.remote_dir or "").strip().strip("/")

        # Crea la directory remota se necessario
        if self.remote_dir:
            dir_path = f"/{self.remote_dir}"  # es. "/upload"
            try:
                self.sftp.stat(dir_path)
            except IOError:
                # Se manca, proviamo a crearla
                try:
                    self.sftp.mkdir(dir_path)
                except OSError:
                    # Directory già presente o impossibile da creare → ignoriamo
                    pass
        else:
            self.remote_dir = ""

    def upload(self, local_path: str, remote_name: Optional[str] = None) -> str:
        """Carica un file sul server SFTP e restituisce il percorso remoto."""
        basename = remote_name or os.path.basename(local_path)

        if self.remote_dir:
            remote_path = f"/{self.remote_dir}/{basename}"
        else:
            remote_path = basename

        self.sftp.put(local_path, remote_path)
        return remote_path

    def close(self) -> None:
        """Chiude connessione SFTP e trasporto SSH."""
        self.sftp.close()
        self.transport.close()
