import base64
import os
import uuid
import itertools
import json
import sqlite3
import shutil
import zlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

class Connection():

    def __init__(self, working_dir, encrypted_dir, passphrase):
        self._cryptographic_backend = default_backend()

        self._working_dir = working_dir
        self._encrypted_dir = encrypted_dir
        self._config_path = os.path.join(self._encrypted_dir,".psfel_cfg.json")
        self._passphrase = passphrase

        self._verify_encrypted_dir()
        self._verify_working_dir()

    def _derive_key(self):
        kdf = PBKDF2HMAC(
                algorithm = hashes.SHA256(),
                length = 32,
                salt = self._configuration.get("salt"),
                iterations = self._configuration.get("iterations"),
                backend = self._cryptographic_backend
            )
        key = kdf.derive(self._passphrase.encode('utf-8'))
        self._key = base64.b64encode(key)

    def _encrypt_file(self, path):
        with open(path,"rb") as input_file:
            compressed_data = zlib.compress(input_file.read())

        f = Fernet(self._key)
        return f.encrypt(compressed_data)
    
    def _decrypt_file(self, path):
        f = Fernet(self._key)
        with open(path,"rb") as input_file:
            decrypted_data = f.decrypt(input_file.read())

        return zlib.decompress(decrypted_data)

    def _verify_encrypted_dir(self):
        if not os.path.isdir(self._encrypted_dir):
            os.makedirs(self._encrypted_dir)

        if os.path.exists(self._config_path):
            with open(self._config_path, "r") as config_file:
                self._configuration = json.loads(config_file.read())

            self._derive_key()

        else:
            default_config = {
                "salt": base64.urlsafe_b64encode(os.urandom(16)),
                "iterations": 10000
            }
            with open(self._config_path, "w") as config_file:
                config_file.write(json.dumps(default_config))

        if not os.path.exists(
                os.path.join(self._encrypted_dir,".psfel_manifest.db")
        ):
           self._generate_manifest()

    def _generate_manifest(self):
        # Decrypt manifest, load data, change what has changed