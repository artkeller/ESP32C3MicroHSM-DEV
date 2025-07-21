# # ESP32-C3 HSM Device Example
Example of the ESP32-C3 serving as a hardware security module (HSM) device. It implements basic cryptographic functions and a serial control interface.

## Übersicht

Dieses Projekt ist ein Beispiel-Sketch für den ESP32-C3, der als Hardware Security Module (HSM)-Device dient.  
Es implementiert grundlegende kryptografische Funktionen und eine serielle Steuerungsschnittstelle.  

### Hauptfunktionen

- **Schlüsselverwaltung & Speicherung (NVS)**
- **ECDH Schlüsselaustausch mit elliptischen Kurven**
- **AES-256-GCM Verschlüsselung und Entschlüsselung**
- **PBKDF2 für Passwortbasierte Schlüsselableitung**
- **HKDF für Schlüsselableitung**
- **HMAC-SHA256 Authentifizierung**
- **Serielle Kommunikation mit definierten Marker-Befehlen**
  
### Unterstützte Befehle (via Serial)

- `NVS_SET_MAK:` – Master Authentication Key setzen  
- `AUTH_TOKEN_SET_REQ:` – Authentifizierungs-Token setzen  
- `ECDH_PUBKEY_REQ:` – Öffentlichen ECDH-Schlüssel anfordern  
- `AUTH_REQ_GROUP:` – Authentifizierungsanfrage  
- `ENCRYPT_FILE_REQ:` – Datei verschlüsseln  
- `DECRYPT_FILE_REQ:` – Datei entschlüsseln  

### Rückgabemarker

- `OK`  
- `NVS_FAILED`  
- `INVALID_INPUT`  
- `AUTH_FAILED`  
- `ENCRYPT_FAILED`  
- `DECRYPT_FAILED`  
- `INTERNAL_ERROR`  

## Abhängigkeiten

- ESP32 Arduino Core  
- `Preferences`-Bibliothek  
- `mbedTLS` (bereits im ESP32 Core enthalten)  

## Getestet mit

- **ESP32-C3** Dev Board  
- Arduino IDE 2.x / PlatformIO  

## Lizenz

Dieses Projekt dient ausschließlich Demonstrations- und Testzwecken.  
Keine Gewährleistung oder Sicherheitsgarantie.  

---

*Erstellt als internes Test- und Beispielprojekt für sichere IoT-Anwendungen.*

