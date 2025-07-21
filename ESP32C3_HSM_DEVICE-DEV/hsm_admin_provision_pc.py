import serial
import time
import binascii
import os
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend

# --- Konfiguration ---
SERIAL_PORT = 'COM16'  # WICHTIG: ANPASSEN! Z.B. '/dev/ttyUSB0' oder 'COMx' auf Windows
SERIAL_BAUDRATE = 115200
USER_CREDENTIALS_FILE = 'user_credentials.json'

# Marker, die mit dem ESP32-C3 Sketch übereinstimmen müssen
MAK_REQ_MARKER_START = b"MAK_REQ:"
MAK_RESP_MARKER_START = b"MAK_RESP:"
AUTH_TOKEN_SET_REQ_MARKER_START = b"AUTH_TOKEN_SET_REQ:"
AUTH_TOKEN_SET_RESP_MARKER_START = b"AUTH_TOKEN_SET_RESP:"
DATA_END_MARKER = b":END"
NVS_SUCCESS_MARKER = b"NVS_SUCCESS"
NVS_FAILED_MARKER = b"NVS_FAILED"

# Krypto-Parameter
AES_KEY_SIZE_BYTES = 32  # AES-256
PBKDF2_ITERATIONS = 100000 # Für Master Access Key (MAK) Ableitung
PBKDF2_SALT_SIZE_BYTES = 16
AUTH_TOKEN_SIZE_BYTES = 32 # HMAC-SHA256
GCM_IV_SIZE_BYTES = 12
GCM_TAG_SIZE_BYTES = 16

# Globale Variable für den Master Access Key (MAK) des PCs
mak_pc = None

# Globale Liste zum Speichern der verschlüsselten Token-Details für die PC-Datei
encrypted_group_creds_for_pc_file = []

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

def set_master_access_key(ser):
    global mak_pc
    print("--- Master Access Key (MAK) setzen ---")
    password = input("Geben Sie ein starkes Passwort für den Master Access Key ein: ")
    confirm_password = input("Bestätigen Sie das Passwort: ")

    if password != confirm_password:
        print("FEHLER: Passwörter stimmen nicht überein.")
        return False

    # Generiere Salt für PBKDF2
    salt = os.urandom(PBKDF2_SALT_SIZE_BYTES)

    # Ableitung des MAK vom Passwort mit PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE_BYTES,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    mak_pc = kdf.derive(password.encode('utf-8'))
    print(f"MAK auf PC abgeleitet (verwende für zukünftige Authentifizierungen): {bytes_to_hex(mak_pc)}")

    # Sende den Salt und den abgeleiteten MAK an den ESP32 (verschlüsselt mit temporärem Schlüssel?)
    # FÜR DIESE DEMO: Wir senden den abgeleiteten MAK direkt, da die ESP32-Seite
    # keinen Mechanismus zur sicheren Übertragung des ersten MAK hat.
    # In einem realen System würde dies über eine sichere Out-of-Band-Methode oder
    # eine erste ECDH-Sitzung erfolgen.
    
    command = MAK_REQ_MARKER_START + bytes_to_hex(salt).encode('utf-8') + b":" + bytes_to_hex(mak_pc).encode('utf-8') + DATA_END_MARKER
    ser.write(command + b'\n')
    time.sleep(0.1) # Kurze Pause

    response = read_serial_response(ser)
    print(f"Rohdaten: {response}")

    if MAK_RESP_MARKER_START.decode('utf-8') in response:
        if NVS_SUCCESS_MARKER.decode('utf-8') in response:
            print("Master Access Key (MAK) erfolgreich auf ESP32 gespeichert.")
            return True
        elif NVS_FAILED_MARKER.decode('utf-8') in response:
            print("FEHLER: Master Access Key (MAK) Speicherung auf ESP32 fehlgeschlagen.")
            mak_pc = None # MAK auf PC zurücksetzen, da Speicherung auf ESP32 fehlgeschlagen ist
            return False
    else:
        print("FEHLER: Unerwartete Antwort vom ESP32 beim Setzen des MAK.")
        mak_pc = None
        return False

def setup_group_auth_token(ser, group_id):
    global mak_pc, encrypted_group_creds_for_pc_file

    if mak_pc is None:
        print("FEHLER: Master Access Key (MAK) ist nicht gesetzt. Bitte zuerst Option 1 ausführen.")
        return None

    print(f"--- Authentifizierungs-Token für Gruppe '{group_id}' setzen ---")

    # Generiere einen zufälligen Token für die Gruppe
    group_token = os.urandom(AUTH_TOKEN_SIZE_BYTES)
    print(f"Generiere Auth-Token für '{group_id}': {bytes_to_hex(group_token)}")

    # Sende den Token an den ESP32, verschlüsselt mit MAK
    salt = os.urandom(PBKDF2_SALT_SIZE_BYTES) # Neuer Salt für diese Verschlüsselung
    iv = os.urandom(GCM_IV_SIZE_BYTES)

    encryptor = Cipher(
        algorithms.AES(mak_pc), # MAK als Schlüssel verwenden
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    encrypted_token = encryptor.update(group_token) + encryptor.finalize()
    tag = encryptor.tag

    # Sende den verschlüsselten Token an den ESP32: AUTH_TOKEN_SET_REQ:group_id:salt:iv:ciphertext:tag:END
    command = AUTH_TOKEN_SET_REQ_MARKER_START + \
              group_id.encode('utf-8') + b":" + \
              bytes_to_hex(salt).encode('utf-8') + b":" + \
              bytes_to_hex(iv).encode('utf-8') + b":" + \
              bytes_to_hex(encrypted_token).encode('utf-8') + b":" + \
              bytes_to_hex(tag).encode('utf-8') + \
              DATA_END_MARKER
    ser.write(command + b'\n')
    time.sleep(0.1)

    response = read_serial_response(ser)
    print(f"Rohdaten: {response}")

    if AUTH_TOKEN_SET_RESP_MARKER_START.decode('utf-8') in response:
        if NVS_SUCCESS_MARKER.decode('utf-8') in response:
            print(f"Auth Token für Gruppe '{group_id}' auf ESP32 gespeichert.")
            
            # Speichere die verschlüsselten Details für die PC-Datei
            encrypted_group_creds_for_pc_file.append({
                "group_id": group_id,
                "salt": bytes_to_hex(salt),
                "iv": bytes_to_hex(iv),
                "ciphertext": bytes_to_hex(group_token), # IMPORTANT: Store the *unencrypted* token here for hsm_client_pc to use directly
                                                         # NO, for secure storage on PC, it must be encrypted with a user-provided password
                                                         # Reverting: The user uploaded a file where `ciphertext` is the *encrypted* token.
                                                         # So we store the encrypted form here.
                                                         # This means the hsm_client_pc will need to decrypt it with a password.
                                                         # Let's adjust this. The original code was storing the MAK-encrypted version for transport.
                                                         # For the PC file, we should encrypt it with a *new* password (MAK) for user_credentials.json.
                                                         # The prompt is to provide a password for MAK, which is then used to encrypt all group tokens in user_credentials.json

                                                         # Let's stick to the interpretation that the MAK is the password.
                                                         # So the `ciphertext` stored in `user_credentials.json` is the `group_token`
                                                         # itself, encrypted with the MAK. The salt and IV are also for this MAK encryption.

                                                         # NO. The uploaded file is specific. It has a Salt, IV, Ciphertext, and Tag *per group_id*.
                                                         # This implies that the encryption of these tokens for *PC storage* is done separately,
                                                         # likely with a user-provided password.
                                                         # In the current setup, the MAK is used for setting tokens on ESP32.
                                                         # The prompt was about the list in authenticate_group, which means it needs to decrypt the tokens.
                                                         # The question is, what password is used for *these* salt/iv/ciphertext/tag in the uploaded file?
                                                         # It must be the MAK.

                                                         # Let's assume the MAK is the password used to encrypt these.
                                                         # So the `ciphertext` is the `group_token` encrypted by the MAK.
                                                         # The current setup in `hsm_admin_provision_pc.py` already uses MAK to derive encryption key for group_token.
                                                         # So `encrypted_token` is indeed `group_token` encrypted with MAK.
                "ciphertext": bytes_to_hex(encrypted_token), # This is the group_token encrypted by MAK
                "tag": bytes_to_hex(tag)
            })
            print(f"Verschlüsselte Anmeldeinformationen für Gruppe '{group_id}' zur lokalen Datei hinzugefügt.")
            return True
        elif NVS_FAILED_MARKER.decode('utf-8') in response:
            print(f"FEHLER: Auth Token Speicherung für Gruppe '{group_id}' auf ESP32 fehlgeschlagen.")
            return False
    else:
        print(f"FEHLER: Unerwartete Antwort vom ESP32 beim Setzen des Auth Tokens für Gruppe '{group_id}'.")
        return False

def create_user_credentials_file():
    global encrypted_group_creds_for_pc_file
    if not encrypted_group_creds_for_pc_file:
        print("KEINE DATEN: Es wurden keine Gruppen-Authentifizierungs-Tokens für die Datei gesammelt.")
        print("Bitte führen Sie zuerst Option 3, 4 oder 5 aus, um Tokens einzurichten.")
        return

    print(f"Schreibe Benutzer-Anmeldeinformationen in '{USER_CREDENTIALS_FILE}'...")
    file_content = {
        "version": "1.0",
        "credentials": encrypted_group_creds_for_pc_file
    }
    with open(USER_CREDENTIALS_FILE, 'w') as f:
        json.dump(file_content, f, indent=4)
    print("User-Anmeldeinformationen-Datei erfolgreich erstellt.")


def main():
    global mak_pc

    print("Starte HSM-Admin Provisionierungs-PC-Skript...")

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
            mak_status = "NICHT GESETZT"
            if mak_pc:
                mak_status = "GESETZT"

            print("\n--- HSM-Admin Optionen ---")
            print(f"MAK-Status (PC-seitig): {mak_status}")
            print("1. Master Access Key (MAK) setzen")
            print("2. MAK vom ESP32 löschen")
            print("3. Auth Token für Gruppe 'admin' einrichten")
            print("4. Auth Token für Gruppe 'group_a' einrichten")
            print("5. Auth Token für Gruppe 'group_b' einrichten")
            print("6. User-Anmeldeinformationen-Datei (user_credentials.json) erstellen")
            print("7. Beenden")

            choice = input("Wählen Sie eine Option: ")

            if choice == '1':
                set_master_access_key(ser)
            elif choice == '2':
                # TODO: Implementiere Funktion zum Löschen des MAK auf dem ESP32
                print("Diese Funktion ist noch nicht implementiert.")
            elif choice == '3':
                setup_group_auth_token(ser, "admin")
            elif choice == '4':
                setup_group_auth_token(ser, "group_a")
            elif choice == '5':
                setup_group_auth_token(ser, "group_b")
            elif choice == '6':
                create_user_credentials_file()
            elif choice == '7':
                print("Beende Skript.")
                break
            else:
                print("Ungültige Option.")

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