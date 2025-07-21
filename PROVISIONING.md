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
   ```
2. **Skript starten**
   eriellen Port konfigurieren**
   ```bash
   python hsm_admin_provision_pc.py
   ```
2. **Menügesteuerte Optionen**

* 1 → Master Access Key setzen
* 2 → MAK auf ESP32 löschen (noch nicht implementiert)
* 3–5 → Auth-Token für Gruppen setzen
* 6 → Anmeldeinformationen-Datei erzeugen
* 7 → Beenden

   


## Wichtige Marker & Kommunikation

| Marker	      | Funktion     |
| :------------ | :----------- |
| MAK_REQ:	    | MAK setzen   |
| MAK_RESP:	    | Antwort auf MAK-Setzen |
| AUTH_TOKEN_SET_REQ:	|Token setzen |
| AUTH_TOKEN_SET_RESP:	|Antwort auf Token-Setzen|
| NVS_SUCCESS	|Erfolg|
| NVS_FAILED	|Fehler|
| :END	|Datenende|

## Abhängigkeiten

    pyserial

    cryptography (Python-Bibliothek)

Installierbar via:

pip install pyserial cryptography

## Hinweise

    MAK muss vor dem Setzen von Tokens gesetzt sein
    Das Skript führt keine sichere Schlüsselverteilung durch – für den produktiven Einsatz sind Erweiterungen nötig
    Token und MAK werden lokal gespeichert – Zugriffsschutz beachten

## Lizenz & Haftungsausschluss

Dieses Tool ist für Test- und Entwicklungszwecke gedacht.
Es übernimmt keine Garantie für Sicherheit oder Eignung für produktive Umgebungen.
