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
                salt = self._configuration.get("salt").encode('utf-8'),
                iterations = self._configuration.get("iterations"),
                backend = self._cryptographic_backend
            )
        key = kdf.derive(self._passphrase.encode('utf-8'))
        self._key = base64.b64encode(key)

    def _encrypt_file(self, path):
        with open(path,"rb") as input_file:
            compressed_data = zlib.compress(input_file.read())

        return self._encrypt_data(compressed_data)
    
    def _decrypt_file(self, path):
        with open(path,"rb") as input_file:
            decrypted_data = self._decrypt_data(input_file.read())

        return zlib.decompress(decrypted_data)

    def _encrypt_data(self, data):
        f = Fernet(self._key)
        return f.encrypt(data)

    def _decrypt_data(self, data):
        f = Fernet(self._key)
        return f.decrypt(data)

    def _verify_encrypted_dir(self):
        if not os.path.isdir(self._encrypted_dir):
            os.makedirs(self._encrypted_dir)

        if os.path.exists(self._config_path):
            with open(self._config_path, "r") as config_file:
                self._configuration = json.loads(config_file.read())
        else:
            default_config = {
                "salt": base64.urlsafe_b64encode(
                        os.urandom(16)).decode('utf-8'),
                "iterations": 10000
            }
            with open(self._config_path, "w") as config_file:
                config_file.write(json.dumps(default_config))

            self._configuration = default_config

        self._derive_key()
        
        self._generate_manifest()

    def _verify_working_dir(self):
        if not os.path.isdir(self._working_dir):
            os.makedirs(self._working_dir)

    def _generate_manifest(self):
        manifest_connection = sqlite3.connect(
                os.path.join(self._encrypted_dir,".psfel_manifest.db")
            )
        manifest_connection.row_factory = sqlite3.Row
        manifest_cursor = manifest_connection.cursor()

        try:
            manifest_cursor.execute("SELECT * FROM files")
        except Exception:
            manifest_cursor.execute(
                    "CREATE TABLE files (name BLOB, hash TEXT)"
                )
            manifest_connection.commit()
            manifest_cursor.execute("SELECT * FROM files")

        # Prunes manifest file to remove any entries that may have survived
        # the deletion of their respective files.
        for file_entry in manifest_cursor.fetchall():
            relative_path = (file_entry["hash"][0]+"/"+
                            file_entry["hash"][1]+"/"+file_entry["hash"]+".gz")
            if not os.path.exists(
                    os.path.join(self._encrypted_dir,relative_path)
            ):
                manifest_cursor.execute(
                        "DELETE FROM files WHERE hash = '{}'".format(
                                file_entry["hash"])
                    )
        manifest_connection.commit()

        for root, dirnames, filenames in os.walk(self._encrypted_dir):
            for file_name in filenames:
                if ".gz" in file_name:
                    manifest_cursor.execute(
                            "SELECT * FROM files WHERE hash = '{}'".format(
                                    file_name.replace(".gz","")
                                )
                        )
                    if len(manifest_cursor.fetchall()) == 0:
                        os.remove(os.path.join(root,file_name))

        manifest_connection.close()

    def push_working(self):
        self._generate_manifest()

        manifest_connection = sqlite3.connect(
                os.path.join(self._encrypted_dir,".psfel_manifest.db")
            )
        manifest_connection.row_factory = sqlite3.Row
        manifest_cursor = manifest_connection.cursor()
        manifest_cursor.execute("SELECT * FROM files")
        path_cache = {}
        for file_entry in manifest_cursor.fetchall():
            path_cache[self._decrypt_data(file_entry["name"]).decode('utf-8')] = file_entry["hash"]

        manifest_cursor.execute("DELETE FROM files")
        manifest_connection.commit()

        for root, dirnames, filenames in os.walk(self._working_dir):
            for file_name in filenames:
                r_path = os.path.join(root,
                        file_name)[len(self._working_dir)+1:]
                if r_path in path_cache:
                    uid = path_cache[r_path]
                else:
                    uid = uuid.uuid4().hex
                
                manifest_cursor.execute(
                        "INSERT INTO files (name, hash) VALUES (?,?)",
                        [self._encrypt_data(r_path.encode('utf-8')),uid])

                encrypted_data = self._encrypt_file(
                        os.path.join(root, file_name))

                derived_directory = os.path.join(
                        self._encrypted_dir,(uid[0]+"/"+uid[1]))
                if not os.path.isdir(derived_directory):
                    os.makedirs(derived_directory)
                file_name = uid+".gz"


                with open(os.path.join(
                        derived_directory,file_name),"wb") as out_f:
                    out_f.write(encrypted_data)

        manifest_connection.commit()
        manifest_connection.close()
        self._generate_manifest()

    def pull_encrypted(self):
        pass