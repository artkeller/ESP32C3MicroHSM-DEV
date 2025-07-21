import serial
import time
import binascii
import os
import json
import requests
from tqdm import tqdm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# --- Konfiguration ---
SERIAL_PORT = 'COM16'  # WICHTIG: ANPASSEN! Z.B. '/dev/ttyUSB0' oder 'COMx' auf Windows
SERIAL_BAUDRATE = 115200
USER_CREDENTIALS_FILE = 'user_credentials.json' # Vom Admin-Tool erstellte Datei
OUTPUT_DIR = 'hsm_output' # Verzeichnis für Ergebnisdateien

# Marker, die mit dem ESP32-C3 Sketch übereinstimmen müssen (Beachten Sie, dass der Sketch für C3 ist, aber Sie einen S3 flashen)
ECDH_PUBKEY_REQ_MARKER_START = b"ECDH_PUBKEY_REQ:"
ECDH_PUBKEY_RESP_MARKER_START = b"ECDH_PUBKEY_RESP:"
AUTH_REQ_GROUP_MARKER_START = b"AUTH_REQ_GROUP:"
AUTH_CHALLENGE_MARKER_START = b"AUTH_CHALLENGE:"
AUTH_RESPONSE_MARKER_START = b"AUTH_RESPONSE:"
SESSION_KEY_RESP_MARKER_START = b"SESSION_KEY_RESP:"
DATA_END_MARKER = b":END"
NVS_SUCCESS_MARKER = b"NVS_SUCCESS"
NVS_FAILED_MARKER = b"NVS_FAILED"
ENCRYPT_FILE_REQ_MARKER_START = b"ENC_FILE_REQ:"
ENCRYPT_FILE_RESP_MARKER_START = b"ENC_FILE_RESP:"
DECRYPT_FILE_REQ_MARKER_START = b"DEC_FILE_REQ:"
DECRYPT_FILE_RESP_MARKER_START = b"DEC_FILE_RESP:"
AUTH_TOKEN_UPDATE_REQ_MARKER_START = b"AUTH_TOKEN_UPDATE_REQ:"

# Krypto-Parameter
AES_KEY_SIZE_BYTES = 32  # AES-256
GCM_IV_SIZE_BYTES = 12 # Standard-IV-Größe für GCM
GCM_TAG_SIZE_BYTES = 16 # Standard-Tag-Größe für GCM
PBKDF2_ITERATIONS = 100000 # Muss mit hsm_admin_provision_pc.py übereinstimmen
PBKDF2_SALT_SIZE_BYTES = 16
AUTH_TOKEN_SIZE_BYTES = 32 # HMAC-SHA256

# Globale Variablen für den Sitzungsschlüssel und Authentifizierung
session_key = None
authenticated_group_token = None
active_group_id_on_pc = None # Speichert die ID der Gruppe, für die ein Token gesendet wurde

# DEMO: Dateiverschlüsselung mit bekannten FEKs
# In einem realen System würden diese Schlüssel sicher vom HSM kommen
DEMO_FEKS = {
    "group_a": b'1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d', # Beispiel F_EK für Gruppe A
    "group_b": b'f1e2d3c4b5a697887968574635241302'  # Beispiel F_EK für Gruppe B
}


def read_serial_response(ser, timeout=10):
    start_time = time.time()
    response = b''
    while time.time() - start_time < timeout:
        if ser.in_waiting > 0:
            response += ser.read(ser.in_waiting)
            if DATA_END_MARKER in response:
                return response.decode('utf-8', errors='ignore').strip()
        time.sleep(0.01)
    return response.decode('utf-8', errors='ignore').strip()

def hex_to_bytes(hex_str):
    return binascii.unhexlify(hex_str)

def bytes_to_hex(byte_arr):
    return binascii.hexlify(byte_arr).decode('utf-8')

def ecdh_key_exchange(ser):
    global session_key
    print("--- Starte ECDH Schlüsselaustausch (Kanalverschlüsselung) ---")
    
    # 1. PC generiert sein temporäres ECDH Schlüsselpaar
    pc_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pc_public_key_bytes = pc_private_key.public_key().public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint
    )
    
    # KORREKTUR: Präfix den PC-eigenen öffentlichen Schlüssel mit 0x41, da ESP32 dies auch zu senden scheint
    pc_public_key_bytes_to_send = b'\x41' + pc_public_key_bytes # Jetzt 66 Bytes
    
    print(f"[PC -> ESP32] Sende PC's öffentlichen Schlüssel (Hex): {binascii.hexlify(pc_public_key_bytes_to_send).decode('utf-8')}")
    
    # Sende den öffentlichen Schlüssel des PCs an den ESP32
    command = ECDH_PUBKEY_REQ_MARKER_START + binascii.hexlify(pc_public_key_bytes_to_send) + DATA_END_MARKER
    ser.write(command + b'\n')
    time.sleep(0.1) # Kurze Pause

    # 2. Empfange den öffentlichen Schlüssel des ESP32
    esp32_response = read_serial_response(ser)
    print(f"Rohdaten: {esp32_response}")

    if ECDH_PUBKEY_RESP_MARKER_START.decode('utf-8') in esp32_response:
        try:
            esp_pubkey_hex = esp32_response.split(ECDH_PUBKEY_RESP_MARKER_START.decode('utf-8'))[1].split(DATA_END_MARKER.decode('utf-8'))[0]
            esp_public_key_bytes = hex_to_bytes(esp_pubkey_hex)
            print(f"[PC <- ESP32] Empfange ESP32's öffentlichen Schlüssel (Hex): {esp_pubkey_hex} (Länge: {len(esp_public_key_bytes)} Bytes)")

            # KORREKTUR: Handhabung des 66-Byte-Schlüssels vom ESP32-C3
            esp_public_key_bytes_standard = esp_public_key_bytes
            if len(esp_public_key_bytes) == 66 and esp_public_key_bytes[0] == 0x41:
                # Wenn der Schlüssel 66 Bytes lang ist und mit 0x41 beginnt,
                # entfernen wir das 0x41 Präfix, um das Standard 65-Byte-Format zu erhalten.
                esp_public_key_bytes_standard = esp_public_key_bytes[1:]
                print("HINWEIS: Entfernte 0x41 Präfix vom ESP32 öffentlichen Schlüssel.")
            
            # Prüfe, ob der Schlüssel die erwartete Länge hat (nach Korrektur)
            if len(esp_public_key_bytes_standard) != 65 or esp_public_key_bytes_standard[0] != 0x04:
                print("FEHLER: ESP32-Schlüssel hat kein gültiges 65-Byte-SECP256R1-Format (erwartet 0x04 Präfix nach evtl. 0x41-Entfernung).")
                return False

            # 3. Ableitung des gemeinsamen Geheimnisses (shared secret)
            # Konvertiere den öffentlichen Schlüssel des ESP32 von Bytes in ein cryptography-Objekt
            esp_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(),
                esp_public_key_bytes_standard
            )
            
            shared_secret = pc_private_key.exchange(ec.ECDH(), esp_public_key)
            
            # HKDF zur Schlüsselableitung
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=AES_KEY_SIZE_BYTES,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            )
            session_key = hkdf.derive(shared_secret)
            
            print(f"ECDH Schlüsselaustausch erfolgreich. Sitzungsschlüssel abgeleitet: {binascii.hexlify(session_key).decode('utf-8')}")
            return True
        except Exception as e:
            print(f"FEHLER: Fehler beim Parsen der ESP32-Antwort oder Schlüsselableitung: {e}")
            session_key = None
            return False
    else:
        print("FEHLER: ECDH fehlgeschlagen oder keine/ungültige Antwort vom ESP32.")
        session_key = None
        return False

def authenticate_group(ser):
    global authenticated_group_token, active_group_id_on_pc, session_key

    if session_key is None:
        print("FEHLER: Es muss zuerst ein ECDH Schlüsselaustausch durchgeführt werden (Option 1).")
        return False

    if not os.path.exists(USER_CREDENTIALS_FILE):
        print(f"FEHLER: Benutzer-Anmeldeinformationen-Datei '{USER_CREDENTIALS_FILE}' nicht gefunden.")
        print("Bitte verwenden Sie das 'hsm_admin_provision_pc.py'-Skript, um diese zu erstellen.")
        return False

    with open(USER_CREDENTIALS_FILE, 'r') as f:
        credentials_data = json.load(f) # {'version': '1.0', 'credentials': [...]}

    if "credentials" not in credentials_data or not isinstance(credentials_data["credentials"], list):
        print("FEHLER: Ungültiges Format der Benutzer-Anmeldeinformationen-Datei. Erwarteter 'credentials'-Schlüssel als Liste.")
        return False

    # Extrahieren Sie verfügbare Gruppen aus der Liste
    available_groups_info = credentials_data["credentials"]
    available_group_ids = [item["group_id"] for item in available_groups_info]

    if not available_group_ids:
        print("FEHLER: Keine Authentifizierungs-Token in der Anmeldeinformationen-Datei gefunden.")
        return False

    print("\nVerfügbare Gruppen für die Authentifizierung:")
    for i, group_id in enumerate(available_group_ids):
        print(f"{i+1}. {group_id}")

    group_choice = input("Wählen Sie die Nummer der Gruppe aus, mit der Sie sich authentifizieren möchten: ")
    try:
        group_idx = int(group_choice) - 1
        if not (0 <= group_idx < len(available_group_ids)):
            print("Ungültige Auswahl.")
            return False
        
        selected_group_id = available_group_ids[group_idx]
        selected_group_creds = available_groups_info[group_idx] # Holen Sie das Diktat für die ausgewählte Gruppe

        user_password = input(f"Bitte geben Sie das Passwort (Master Access Key) für Gruppe '{selected_group_id}' ein: ")
        
        # Entschlüsseln Sie das group_token aus der Credentials-Datei
        try:
            salt = hex_to_bytes(selected_group_creds["salt"])
            iv = hex_to_bytes(selected_group_creds["iv"])
            ciphertext_hex = selected_group_creds["ciphertext"]
            ciphertext = hex_to_bytes(ciphertext_hex)
            tag = hex_to_bytes(selected_group_creds["tag"])

            # Leiten Sie den Schlüssel mit PBKDF2 ab (muss mit MAK-Ableitung in admin-Tool übereinstimmen)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=AES_KEY_SIZE_BYTES,
                salt=salt,
                iterations=PBKDF2_ITERATIONS, # Muss mit hsm_admin_provision_pc.py übereinstimmen
                backend=default_backend()
            )
            decryption_key = kdf.derive(user_password.encode('utf-8'))

            # Entschlüsseln Sie das tatsächliche Gruppen-Token
            decryptor = Cipher(
                algorithms.AES(decryption_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            ).decryptor()

            group_token = decryptor.update(ciphertext) + decryptor.finalize()
            print(f"Gruppen-Authentifizierungs-Token für '{selected_group_id}' erfolgreich entschlüsselt.")

        except Exception as e:
            print(f"FEHLER: Das eingegebene Passwort ist falsch oder die Token-Daten sind beschädigt: {e}")
            return False

    except ValueError:
        print("Ungültige Eingabe.")
        return False

    # 1. Sende Authentifizierungs-Anfrage an ESP32
    print(f"[PC -> ESP32] Fordere Authentifizierungs-Challenge für Gruppe '{selected_group_id}' an...")
    command = AUTH_REQ_GROUP_MARKER_START + selected_group_id.encode('utf-8') + DATA_END_MARKER
    ser.write(command + b'\n')
    time.sleep(0.1) # Kurze Pause

    # 2. Empfange Challenge vom ESP32 (verschlüsselt mit Sitzungsschlüssel)
    challenge_response = read_serial_response(ser)
    print(f"Rohdaten: {challenge_response}")

    if AUTH_CHALLENGE_MARKER_START.decode('utf-8') in challenge_response:
        try:
            encrypted_challenge_hex = challenge_response.split(AUTH_CHALLENGE_MARKER_START.decode('utf-8'))[1].split(DATA_END_MARKER.decode('utf-8'))[0]
            encrypted_challenge_bytes = hex_to_bytes(encrypted_challenge_hex)

            # Entschlüssle Challenge mit Sitzungsschlüssel (AES-GCM)
            # Format: IV || Ciphertext || Tag
            iv = encrypted_challenge_bytes[:GCM_IV_SIZE_BYTES]
            ciphertext_with_tag = encrypted_challenge_bytes[GCM_IV_SIZE_BYTES:]
            ciphertext = ciphertext_with_tag[:-GCM_TAG_SIZE_BYTES]
            tag = ciphertext_with_tag[-GCM_TAG_SIZE_BYTES:]

            decryptor = Cipher(
                algorithms.AES(session_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            ).decryptor()

            challenge = decryptor.update(ciphertext) + decryptor.finalize()
            print(f"[PC <- ESP32] Empfange und entschlüssele Challenge: {binascii.hexlify(challenge).decode('utf-8')}")

            # 3. Berechne HMAC-Antwort
            h = hmac.HMAC(group_token, hashes.SHA256(), backend=default_backend())
            h.update(challenge)
            response_hmac = h.finalize()
            print(f"[PC -> ESP32] Berechne HMAC-Antwort: {binascii.hexlify(response_hmac).decode('utf-8')}")

            # 4. Sende HMAC-Antwort an ESP32 (verschlüsselt mit Sitzungsschlüssel)
            # Verschlüssle die Antwort vor dem Senden
            encryptor = Cipher(
                algorithms.AES(session_key),
                modes.GCM(os.urandom(GCM_IV_SIZE_BYTES)), # Neuer IV für jede Verschlüsselung
                backend=default_backend()
            ).encryptor()

            encrypted_response_hmac = encryptor.update(response_hmac) + encryptor.finalize()
            encrypted_response_with_iv_tag = encryptor.nonce + encrypted_response_hmac + encryptor.tag
            encrypted_response_hmac_hex = binascii.hexlify(encrypted_response_with_iv_tag)

            command = AUTH_RESPONSE_MARKER_START + encrypted_response_hmac_hex + DATA_END_MARKER
            ser.write(command + b'\n')
            time.sleep(0.1) # Kurze Pause

            # 5. Empfange Ergebnis der Authentifizierung
            auth_result_response = read_serial_response(ser)
            print(f"Rohdaten: {auth_result_response}")

            if NVS_SUCCESS_MARKER.decode('utf-8') in auth_result_response:
                authenticated_group_token = group_token # Speichere den Token lokal, um den Status anzuzeigen
                active_group_id_on_pc = selected_group_id
                print(f"AUTHENTIFIZIERUNG ERFOLGREICH für Gruppe '{selected_group_id}'!")
                return True
            elif NVS_FAILED_MARKER.decode('utf-8') in auth_result_response:
                print("AUTHENTIFIZIERUNG FEHLGESCHLAGEN: Falsche HMAC-Antwort oder unbekannte Gruppe.")
                authenticated_group_token = None
                active_group_id_on_pc = None
                return False
            else:
                print("FEHLER: Unerwartete Authentifizierungsantwort vom ESP32.")
                authenticated_group_token = None
                active_group_id_on_pc = None
                return False
        except Exception as e:
            print(f"FEHLER: Fehler bei der Authentifizierung: {e}")
            authenticated_group_token = None
            active_group_id_on_pc = None
            return False
    else:
        print("FEHLER: Keine Authentifizierungs-Challenge vom ESP32 erhalten.")
        return False

def request_session_key_from_esp32(ser, group_id):
    global session_key

    if authenticated_group_token is None or active_group_id_on_pc != group_id:
        print(f"FEHLER: Nicht für Gruppe '{group_id}' authentifiziert. Bitte zuerst authentifizieren (Option 2).")
        return False

    print(f"[PC -> ESP32] Fordere neuen Sitzungsschlüssel für Gruppe '{group_id}' an...")
    command = b"REQUEST_SK:" + group_id.encode('utf-8') + DATA_END_MARKER
    ser.write(command + b'\n')
    time.sleep(0.1)

    response = read_serial_response(ser)
    print(f"Rohdaten: {response}")

    if SESSION_KEY_RESP_MARKER_START.decode('utf-8') in response:
        try:
            encrypted_sk_hex = response.split(SESSION_KEY_RESP_MARKER_START.decode('utf-8'))[1].split(DATA_END_MARKER.decode('utf-8'))[0]
            encrypted_sk_bytes = hex_to_bytes(encrypted_sk_hex)

            # Entschlüssle den Session Key mit dem Gruppen-Auth-Token
            iv = encrypted_sk_bytes[:GCM_IV_SIZE_BYTES]
            ciphertext_with_tag = encrypted_sk_bytes[GCM_IV_SIZE_BYTES:]
            ciphertext = ciphertext_with_tag[:-GCM_TAG_SIZE_BYTES]
            tag = ciphertext_with_tag[-GCM_TAG_SIZE_BYTES:]

            decryptor = Cipher(
                algorithms.AES(authenticated_group_token), # Hier den Gruppen-Auth-Token als Schlüssel verwenden
                modes.GCM(iv, tag),
                backend=default_backend()
            ).decryptor()

            session_key = decryptor.update(ciphertext) + decryptor.finalize()
            print(f"Sitzungsschlüssel für Gruppe '{group_id}' erfolgreich vom ESP32 erhalten und entschlüsselt: {binascii.hexlify(session_key).decode('utf-8')}")
            return True
        except Exception as e:
            print(f"FEHLER beim Entschlüsseln des Sitzungsschlüssels: {e}")
            session_key = None
            return False
    elif NVS_FAILED_MARKER.decode('utf-8') in response:
        print("FEHLER: ESP32 konnte keinen Sitzungsschlüssel bereitstellen (z.B. nicht authentifiziert).")
        session_key = None
        return False
    else:
        print("FEHLER: Unerwartete Antwort beim Anfordern des Sitzungsschlüssels.")
        session_key = None
        return False

def encrypt_file_for_group_remote(ser, file_path, group_id_for_f_ek):
    global session_key

    if session_key is None:
        print("FEHLER: Es muss zuerst ein ECDH Schlüsselaustausch durchgeführt werden (Option 1).")
        return False
    
    if authenticated_group_token is None or active_group_id_on_pc != group_id_for_f_ek:
        print(f"FEHLER: Nicht für Gruppe '{group_id_for_f_ek}' authentifiziert. Bitte zuerst authentifizieren (Option 2).")
        return False

    if not os.path.exists(file_path):
        print(f"FEHLER: Datei nicht gefunden: {file_path}")
        return False
    
    # 1. Datei einlesen
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    print(f"[PC -> ESP32] Sende Anfrage zur Verschlüsselung von '{os.path.basename(file_path)}'...")
    # Sende den Plaintext verschlüsselt mit dem Session Key an den ESP32
    encryptor = Cipher(
        algorithms.AES(session_key),
        modes.GCM(os.urandom(GCM_IV_SIZE_BYTES)), # Neuer IV für jede Verschlüsselung
        backend=default_backend()
    ).encryptor()

    encrypted_data_session_key = encryptor.update(plaintext) + encryptor.finalize()
    encrypted_data_with_iv_tag = encryptor.nonce + encrypted_data_session_key + encryptor.tag
    encrypted_data_hex = binascii.hexlify(encrypted_data_with_iv_tag)

    # Befehl an ESP32 senden: ENCRYPT_FILE_REQ:group_id:hex_encrypted_data:END
    command = ENCRYPT_FILE_REQ_MARKER_START + group_id_for_f_ek.encode('utf-8') + b":" + encrypted_data_hex + DATA_END_MARKER
    ser.write(command + b'\n')
    time.sleep(0.1)

    # 2. Empfange verschlüsselte Datei und F_EK (vom ESP32 mit Gruppen-Auth-Token verschlüsselt)
    response = read_serial_response(ser, timeout=30) # Längeres Timeout für große Dateien
    print(f"Rohdaten: {response}")

    if ENCRYPT_FILE_RESP_MARKER_START.decode('utf-8') in response:
        try:
            parts = response.split(ENCRYPT_FILE_RESP_MARKER_START.decode('utf-8'))[1].split(DATA_END_MARKER.decode('utf-8'))[0].split(':')
            if len(parts) != 2:
                raise ValueError("Unerwartetes Format für ENCRYPT_FILE_RESP.")
            
            encrypted_f_ek_hex = parts[0]
            encrypted_file_with_f_ek_hex = parts[1]

            encrypted_f_ek_bytes = hex_to_bytes(encrypted_f_ek_hex)
            encrypted_file_with_f_ek_bytes = hex_to_bytes(encrypted_file_with_f_ek_hex)

            # Entschlüssle F_EK mit dem Authentifizierungs-Token (AES-GCM)
            iv_f_ek = encrypted_f_ek_bytes[:GCM_IV_SIZE_BYTES]
            ciphertext_with_tag_f_ek = encrypted_f_ek_bytes[GCM_IV_SIZE_BYTES:]
            ciphertext_f_ek = ciphertext_with_tag_f_ek[:-GCM_TAG_SIZE_BYTES]
            tag_f_ek = ciphertext_with_tag_f_ek[-GCM_TAG_SIZE_BYTES:]

            decryptor_f_ek = Cipher(
                algorithms.AES(authenticated_group_token), # Hier den Gruppen-Auth-Token als Schlüssel verwenden
                modes.GCM(iv_f_ek, tag_f_ek),
                backend=default_backend()
            ).decryptor()

            f_ek = decryptor_f_ek.update(ciphertext_f_ek) + decryptor_f_ek.finalize()
            print(f"F_EK für Gruppe '{group_id_for_f_ek}' erfolgreich entschlüsselt: {binascii.hexlify(f_ek).decode('utf-8')}")

            # Speichere die verschlüsselte Datei und den entschlüsselten F_EK
            output_file_name = os.path.basename(file_path) + f".enc_{group_id_for_f_ek}"
            output_file_path = os.path.join(OUTPUT_DIR, output_file_name)
            os.makedirs(OUTPUT_DIR, exist_ok=True)

            with open(output_file_path, 'wb') as out_f:
                out_f.write(encrypted_file_with_f_ek_bytes)
            
            # Speichere den F_EK separat, da dieser zum Entschlüsseln der Datei benötigt wird
            f_ek_file_name = f"f_ek_{group_id_for_f_ek}.bin"
            f_ek_file_path = os.path.join(OUTPUT_DIR, f_ek_file_name)
            with open(f_ek_file_path, 'wb') as f_ek_f:
                f_ek_f.write(f_ek)

            print(f"Datei '{output_file_name}' und F_EK '{f_ek_file_name}' erfolgreich gespeichert im Verzeichnis '{OUTPUT_DIR}'.")
            return True
        except Exception as e:
            print(f"FEHLER beim Verarbeiten der Verschlüsselungsantwort: {e}")
            return False
    elif NVS_FAILED_MARKER.decode('utf-8') in response:
        print("FEHLER: ESP32 konnte die Datei nicht verschlüsseln (z.B. kein passender F_EK für die Gruppe).")
        return False
    else:
        print("FEHLER: Unerwartete Antwort bei der Dateiverschlüsselung.")
        return False

def decrypt_file_remote(ser, file_path, group_id_for_f_ek):
    global session_key

    if session_key is None:
        print("FEHLER: Es muss zuerst ein ECDH Schlüsselaustausch durchgeführt werden (Option 1).")
        return False
    
    if authenticated_group_token is None or active_group_id_on_pc != group_id_for_f_ek:
        print(f"FEHLER: Nicht für Gruppe '{group_id_for_f_ek}' authentifiziert. Bitte zuerst authentifizieren (Option 2).")
        return False
    
    f_ek_file_name = f"f_ek_{group_id_for_f_ek}.bin"
    f_ek_file_path = os.path.join(OUTPUT_DIR, f_ek_file_name)

    if not os.path.exists(file_path) or not os.path.exists(f_ek_file_path):
        print(f"FEHLER: Verschlüsselte Datei '{file_path}' oder F_EK-Datei '{f_ek_file_path}' nicht gefunden.")
        return False

    # 1. Verschlüsselte Datei und F_EK einlesen
    with open(file_path, 'rb') as f:
        encrypted_data_with_f_ek_bytes = f.read()
    with open(f_ek_file_path, 'rb') as f:
        f_ek = f.read()

    # 2. Sende Request an ESP32 zur Entschlüsselung
    print(f"[PC -> ESP32] Sende Anfrage zur Entschlüsselung von '{os.path.basename(file_path)}'...")
    
    # Verschlüssle den F_EK und die verschlüsselte Datei mit dem Session Key für den Transport
    encryptor_f_ek = Cipher(
        algorithms.AES(session_key),
        modes.GCM(os.urandom(GCM_IV_SIZE_BYTES)),
        backend=default_backend()
    ).encryptor()
    encrypted_f_ek_session_key = encryptor_f_ek.update(f_ek) + encryptor_f_ek.finalize()
    encrypted_f_ek_with_iv_tag = encryptor_f_ek.nonce + encrypted_f_ek_session_key + encryptor_f_ek.tag
    encrypted_f_ek_hex = binascii.hexlify(encrypted_f_ek_with_iv_tag)

    encryptor_file_data = Cipher(
        algorithms.AES(session_key),
        modes.GCM(os.urandom(GCM_IV_SIZE_BYTES)),
        backend=default_backend()
    ).encryptor()
    encrypted_file_data_session_key = encryptor_file_data.update(encrypted_data_with_f_ek_bytes) + encryptor_file_data.finalize()
    encrypted_file_data_with_iv_tag = encryptor_file_data.nonce + encrypted_file_data_session_key + encryptor_file_data.tag
    encrypted_file_data_hex = binascii.hexlify(encrypted_file_data_with_iv_tag)

    # Befehl an ESP32 senden: DEC_FILE_REQ:group_id:hex_encrypted_f_ek:hex_encrypted_file_data:END
    command = DEC_FILE_REQ_MARKER_START + group_id_for_f_ek.encode('utf-8') + b":" + \
              encrypted_f_ek_hex + b":" + encrypted_file_data_hex + DATA_END_MARKER
    ser.write(command + b'\n')
    time.sleep(0.1)

    # 3. Empfange entschlüsselte Datei vom ESP32 (verschlüsselt mit Session Key)
    response = read_serial_response(ser, timeout=30)
    print(f"Rohdaten: {response}")

    if DECRYPT_FILE_RESP_MARKER_START.decode('utf-8') in response:
        try:
            encrypted_decrypted_data_hex = response.split(DECRYPT_FILE_RESP_MARKER_START.decode('utf-8'))[1].split(DATA_END_MARKER.decode('utf-8'))[0]
            encrypted_decrypted_data_bytes = hex_to_bytes(encrypted_decrypted_data_hex)

            # Entschlüssle die Datei mit dem Session Key
            iv = encrypted_decrypted_data_bytes[:GCM_IV_SIZE_BYTES]
            ciphertext_with_tag = encrypted_decrypted_data_bytes[GCM_IV_SIZE_BYTES:]
            ciphertext = ciphertext_with_tag[:-GCM_TAG_SIZE_BYTES]
            tag = ciphertext_with_tag[-GCM_TAG_SIZE_BYTES:]

            decryptor = Cipher(
                algorithms.AES(session_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            ).decryptor()

            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            output_file_name = os.path.basename(file_path).replace(f".enc_{group_id_for_f_ek}", "")
            output_file_path = os.path.join(OUTPUT_DIR, output_file_name)
            os.makedirs(OUTPUT_DIR, exist_ok=True)

            with open(output_file_path, 'wb') as out_f:
                out_f.write(plaintext)
            
            print(f"Datei '{output_file_name}' erfolgreich entschlüsselt und gespeichert im Verzeichnis '{OUTPUT_DIR}'.")
            return True
        except Exception as e:
            print(f"FEHLER beim Entschlüsseln der Antwortdatei: {e}")
            return False
    elif NVS_FAILED_MARKER.decode('utf-8') in response:
        print("FEHLER: ESP32 konnte die Datei nicht entschlüsseln (z.B. falscher F_EK).")
        return False
    else:
        print("FEHLER: Unerwartete Antwort bei der Dateientschlüsselung.")
        return False

def encrypt_file_for_group_local(file_path, group_id_for_f_ek):
    if not os.path.exists(file_path):
        print(f"FEHLER: Datei nicht gefunden: {file_path}")
        return False
    
    if group_id_for_f_ek not in DEMO_FEKS:
        print(f"FEHLER: Gruppen-F_EK für '{group_id_for_f_ek}' nicht lokal bekannt.")
        return False
    
    f_ek = DEMO_FEKS[group_id_for_f_ek]

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Verschlüssle mit F_EK (AES-GCM)
    encryptor = Cipher(
        algorithms.AES(f_ek),
        modes.GCM(os.urandom(GCM_IV_SIZE_BYTES)), # Neuer IV für jede Verschlüsselung
        backend=default_backend()
    ).encryptor()

    encrypted_data = encryptor.update(plaintext) + encryptor.finalize()
    encrypted_data_with_iv_tag = encryptor.nonce + encrypted_data + encryptor.tag

    output_file_name = os.path.basename(file_path) + f".enc_{group_id_for_f_ek}_local"
    output_file_path = os.path.join(OUTPUT_DIR, output_file_name)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with open(output_file_path, 'wb') as out_f:
        out_f.write(encrypted_data_with_iv_tag)
    
    print(f"Datei '{output_file_name}' lokal verschlüsselt und gespeichert im Verzeichnis '{OUTPUT_DIR}'.")


def decrypt_file_for_group_local(file_path, group_id_for_f_ek):
    if not os.path.exists(file_path):
        print(f"FEHLER: Datei nicht gefunden: {file_path}")
        return False
    
    if group_id_for_f_ek not in DEMO_FEKS:
        print(f"FEHLER: Gruppen-F_EK für '{group_id_for_f_ek}' nicht lokal bekannt.")
        return False
    
    f_ek = DEMO_FEKS[group_id_for_f_ek]

    with open(file_path, 'rb') as f:
        encrypted_data_with_iv_tag = f.read()

    try:
        iv = encrypted_data_with_iv_tag[:GCM_IV_SIZE_BYTES]
        ciphertext_with_tag = encrypted_data_with_iv_tag[GCM_IV_SIZE_BYTES:]
        ciphertext = ciphertext_with_tag[:-GCM_TAG_SIZE_BYTES]
        tag = ciphertext_with_tag[-GCM_TAG_SIZE_BYTES:]

        decryptor = Cipher(
            algorithms.AES(f_ek),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        output_file_name = os.path.basename(file_path).replace(f".enc_{group_id_for_f_ek}_local", "")
        output_file_path = os.path.join(OUTPUT_DIR, output_file_name)
        os.makedirs(OUTPUT_DIR, exist_ok=True)

        with open(output_file_path, 'wb') as out_f:
            out_f.write(plaintext)
        
        print(f"Datei '{output_file_name}' lokal entschlüsselt und gespeichert im Verzeichnis '{OUTPUT_DIR}'.")
    except Exception as e:
        print(f"FEHLER beim lokalen Entschlüsseln der Datei: {e}")


def main():
    global session_key, authenticated_group_token, active_group_id_on_pc

    print("Starte HSM-Client PC-Skript...")
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    ser = None
    try:
        print(f"Versuche, serielle Verbindung zu {SERIAL_PORT} @ {SERIAL_BAUDRATE} Baud zu öffnen...")
        ser = serial.Serial(SERIAL_PORT, SERIAL_BAUDRATE, timeout=1)
        print(f"Verbunden mit {SERIAL_PORT} @ {SERIAL_BAUDRATE} Baud.")
        time.sleep(2) # Warte auf ESP32 Initialisierung
        ser.flushInput()
        ser.flushOutput()

        # Hauptmenü
        while True:
            status_text = "NICHT AKTIV"
            if session_key:
                status_text = "SITZUNGSSCHLÜSSEL ETABLIERT"
            if authenticated_group_token:
                status_text += f" (Authentifiziert für Gruppe: {active_group_id_on_pc})"

            print("\n--- HSM-Client Optionen ---")
            print(f"Status: {status_text}")
            print("1. ECDH Schlüsselaustausch (Kanalverschlüsselung initialisieren)")
            print("2. Authentifizieren (für Dateizugriff / SK-Anforderung)")
            # print("3. Sitzungsschlüssel vom ESP32 anfordern (erfordert Authentifizierung)") # Wird aktuell nicht direkt angeboten, da Authentifizierung SK mitbringt
            print("3. Datei auf ESP32 verschlüsseln")
            print("4. Datei auf ESP32 entschlüsseln")
            print("4.1. Datei LOKAL verschlüsseln (Demo-FEKs)")
            print("4.2. Datei LOKAL entschlüsseln (Demo-FEKs)")
            print("5. Sitzung zurücksetzen (Session Key / Authentifizierung löschen)")
            print("6. Beenden")

            choice = input("Wählen Sie eine Option: ")

            if choice == '1':
                ecdh_key_exchange(ser)
            elif choice == '2':
                authenticate_group(ser)
            # elif choice == '3':
            #     if authenticated_group_token:
            #         request_session_key_from_esp32(ser, active_group_id_on_pc)
            #     else:
            #         print("Bitte zuerst authentifizieren (Option 2).")
            elif choice == '3':
                if session_key and authenticated_group_token:
                    file_to_encrypt = input("Pfad zur Datei, die verschlüsselt werden soll: ")
                    group_for_file = input(f"Für welche Gruppe soll die Datei verschlüsselt werden ({', '.join(DEMO_FEKS.keys())})? ")
                    encrypt_file_for_group_remote(ser, file_to_encrypt, group_for_file)
                else:
                    print("FEHLER: Session Key und Authentifizierung sind für diese Aktion erforderlich. Bitte Optionen 1 und 2 ausführen.")
            elif choice == '4':
                if session_key and authenticated_group_token:
                    file_to_decrypt = input("Pfad zur Datei, die entschlüsselt werden soll: ")
                    group_for_file = input(f"Für welche Gruppe wurde die Datei verschlüsselt ({', '.join(DEMO_FEKS.keys())})? ")
                    decrypt_file_remote(ser, file_to_decrypt, group_for_file)
                else:
                    print("FEHLER: Session Key und Authentifizierung sind für diese Aktion erforderlich. Bitte Optionen 1 und 2 ausführen.")
            elif choice == '4.1':
                file_to_encrypt = input("Pfad zur Datei, die lokal verschlüsselt werden soll: ")
                group_for_file = input(f"Für welche Gruppe soll die Datei verschlüsselt werden ({', '.join(DEMO_FEKS.keys())})? ")
                encrypt_file_for_group_local(file_to_encrypt, group_for_file)
            elif choice == '4.2':
                file_to_decrypt = input("Pfad zur Datei, die lokal entschlüsselt werden soll: ")
                group_for_file = input(f"Für welche Gruppe wurde die Datei verschlüsselt ({', '.join(DEMO_FEKS.keys())})? ")
                decrypt_file_for_group_local(file_to_decrypt, group_for_file)
            elif choice == '5':
                session_key = None
                authenticated_group_token = None
                active_group_id_on_pc = None
                print("Sitzung erfolgreich zurückgesetzt.")
            elif choice == '6':
                print("Beende Skript.")
                break
            else:
                print("Ungültige Option oder Aktion nicht erlaubt im aktuellen Zustand.")

    except serial.SerialException as e:
        print(f"FEHLER bei der seriellen Verbindung: {e}")
        print("Stellen Sie sicher, dass der ESP32 angeschlossen ist und der korrekte COM-Port ausgewählt ist.")
    except Exception as e:
        print(f"Ein unerwarteter Fehler ist aufgetreten: {e}")
    finally:
        if ser is not None and ser.is_open:
            ser.close()
            print("Serielle Verbindung geschlossen.")

if __name__ == '__main__':
    main()