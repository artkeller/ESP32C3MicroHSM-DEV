# ESP32-C3 HSM Provisioning Tool (PC-Skript)

## Übersicht

Dieses Python-Skript dient zur **Initialisierung** und **Provisionierung** eines ESP32-C3 HSM-Devices über die serielle Schnittstelle.  
Es ermöglicht die sichere Verwaltung von Authentifizierungs-Schlüsseln und Tokens zwischen PC und ESP32-C3.  

---

## Hauptfunktionen

- **Master Access Key (MAK) setzen**
  - Wird aus einem Benutzerpasswort per **PBKDF2** abgeleitet  
  - Per Serial-Befehl an den ESP32-C3 übertragen  
  - Grundlage für weitere Schlüsseloperationen  

- **Gruppen-Authentifizierungstokens erstellen**
  - Tokens werden zufällig generiert  
  - Mit dem MAK verschlüsselt und an den ESP32-C3 gesendet  
  - Gruppen: `admin`, `group_a`, `group_b`  
  - Serielle Kommunikation über definierte Marker  

- **Benutzer-Anmeldeinformationen speichern**
  - Speicherung verschlüsselter Tokens in `user_credentials.json`  
  - Ermöglicht spätere Verwendung durch Client-Software  

---

## Verwendung

1. **Seriellen Port konfigurieren**
   ```python
   SERIAL_PORT = 'COMx'  # Anpassen!

