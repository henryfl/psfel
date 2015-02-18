import base64
import os
import uuid
import itertools
import json
import sqlite3
import shutil

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

class Connection():

    def __init__(self, working_dir, encrypted_dir, passphrase):
        self._working_dir = working_dir
        self._encrypted_dir = encrypted_dir
        self._config_path = os.path.join(self._encrypted_dir,".psfel_cfg.json")
        self._passphrase = passphrase

        self._verify_encrypted_dir()
        self._verify_working_dir()

    def _derive_key(self, salt = None):
        kdf = PBKDF2HMAC(
                algorithm = hashes.SHA256(),
                length = 32,
                salt = salt,
                iterations = 100000,
                backend = self._cryptographic_backend
            )
        key = kdf.derive(self._passphrase.encode('utf-8'))
        self._key = base64.b64encode(key)
        

    def _verify_encrypted_dir(self):
        if not os.path.isdir(self._encrypted_dir):
            os.makedirs(self._encrypted_dir)

        if os.path.exists(self._config_path):
            with open(self._config_path, "r") as config_file:
                self._configuration = json.loads(config_file.readlines())
                #TODO: verify configuraiton
            self._derive_key()

        else:
            #generate config file

        if not os.path.exists(
                os.path.join(self._encrypted_dir,".psfel_manifest.db")
        ):
           self._generate_manifest()

    def _generate_manifest(self):
        # Decrypt manifest, load data, change what has changed