#include <WiFi.h>
#include <Preferences.h>
#include <mbedtls/gcm.h>
#include <mbedtls/aes.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/sha256.h>
#include <mbedtls/pkcs5.h> // Für PBKDF2
#include <mbedtls/build_info.h> // Für MBEDTLS_NO_PLATFORM_ENTROPY
#include <mbedtls/md.h> // Für HMAC, md_info_from_type, md_get_size
#include <mbedtls/hkdf.h> // Für HKDF
#include <mbedtls/pk.h>   // Neu hinzugefügt für Public Key und Private Key Operationen
#include <mbedtls/ecp.h>  // Neu hinzugefügt für Elliptic Curve Point Operationen
#include <vector>         // Neu hinzugefügt für std::vector

// Zusätzliche Standard-Includes für allgemeine Funktionen
#include <string.h> // Für strlen
#include <stdlib.h> // Für strtol
#include <stdio.h>  // Für printf (obwohl Serial.printf oft ausreicht)

// Konstanten
// Schlüsselgrößen, IV und Tag für GCM
#define AES_KEY_SIZE_BYTES 32 // 256-Bit-Schlüssel
#define GCM_IV_SIZE_BYTES 12 // Standard-IV-Größe für GCM
#define GCM_TAG_SIZE_BYTES 16 // Standard-Tag-Größe für GCM
// Keine Notwendigkeit für AES_WRAP_BLOCK_SIZE, da wir GCM verwenden
#define PBKDF2_ITERATIONS 100000 // Muss mit PC-Skripten übereinstimmen
#define PBKDF2_SALT_SIZE_BYTES 16 // Salzgröße für PBKDF2
#define AUTH_TOKEN_SIZE_BYTES 32 // Größe des Authentifizierungs-Tokens (HMAC-SHA256)
#define CHALLENGE_SIZE_BYTES 16 // Größe der Challenge für Authentifizierung
#define ECDH_PUBLIC_KEY_SIZE_BYTES 64 // ECDH P-256 Public Key (X und Y Koordinaten, jeweils 32 Bytes)
#define MAX_COMMAND_LENGTH 1024 // Maximale Länge eines seriellen Befehls

// Marker für serielle Kommunikation
#define NVS_SET_MAK_MARKER_START "NVS_SET_MAK:"
#define AUTH_TOKEN_SET_REQ_MARKER_START "AUTH_TOKEN_SET_REQ:"
#define ECDH_PUBKEY_REQ_MARKER_START "ECDH_PUBKEY_REQ:"
#define AUTH_REQ_GROUP_MARKER_START "AUTH_REQ_GROUP:"
#define AUTH_RESPONSE_MARKER_START "AUTH_RESPONSE:"
#define ENCRYPT_FILE_REQ_MARKER_START "ENCRYPT_FILE_REQ:"
#define DECRYPT_FILE_REQ_MARKER_START "DECRYPT_FILE_REQ:"

#define OK_MARKER "OK"
#define NVS_FAILED_MARKER "NVS_FAILED"
#define INVALID_INPUT_MARKER "INVALID_INPUT"
#define AUTH_FAILED_MARKER "AUTH_FAILED"
#define DECRYPT_FAILED_MARKER "DECRYPT_FAILED"
#define ENCRYPT_FAILED_MARKER "ENCRYPT_FAILED"
#define INTERNAL_ERROR_MARKER "INTERNAL_ERROR"
#define NOT_FOUND_MARKER "NOT_FOUND"

#define ECDH_PUBKEY_RESP_MARKER_START "ECDH_PUBKEY_RESP:"
#define AUTH_CHALLENGE_RESP_MARKER_START "AUTH_CHALLENGE_RESP:"
#define AUTH_SUCCESS_RESP_MARKER_START "AUTH_SUCCESS_RESP:"
#define ENCRYPT_FILE_RESP_MARKER_START "ENCRYPT_FILE_RESP:"
#define DECRYPT_FILE_RESP_MARKER_START "DECRYPT_FILE_RESP:"

#define DATA_END_MARKER ":END"

// Globale Variablen für mbedTLS Kontexte
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg_ctx;
Preferences preferences; // Für NVS-Speicher
mbedtls_gcm_context gcm_ctx; // GCM Kontext für Verschlüsselungsoperationen
mbedtls_aes_context aes_ctx; // AES Kontext für Key Wrap/Unwrap

// Buffer für MAK (Master Authentication Key)
unsigned char master_auth_key[AES_KEY_SIZE_BYTES];
bool mak_loaded = false;

// Hilfsfunktion zum Konvertieren von Bytes in Hex-String
String bytes_to_hex_string(const unsigned char* bytes, size_t len) {
    String hex_string = "";
    for (size_t i = 0; i < len; i++) {
        char buf[3];
        sprintf(buf, "%02X", bytes[i]);
        hex_string += buf;
    }
    return hex_string;
}

// Hilfsfunktion zum Konvertieren von Hex-String in Bytes
size_t hex_to_bytes(const char* hex_string, unsigned char* byte_array, size_t max_len) {
    size_t len = strlen(hex_string);
    if (len % 2 != 0 || len / 2 > max_len) {
        return 0; // Ungültige Länge oder zu groß für den Puffer
    }
    for (size_t i = 0; i < len / 2; i++) {
        sscanf(hex_string + 2 * i, "%2hhX", &byte_array[i]);
    }
    return len / 2;
}

// Hilfsfunktion zum Drucken von Hex-Werten (nur für Debugging)
void print_hex(const char* title, const unsigned char* buf, size_t len) {
    Serial.printf("%s: ", title);
    for (size_t i = 0; i < len; i++) {
        Serial.printf("%02X", buf[i]);
    }
    Serial.println();
}

// Schlüsselableitung mit PBKDF2
int derive_key_pbkdf2(const char* password, const unsigned char* salt, size_t salt_len,
                       unsigned char* output_key, size_t output_key_len) {
    // Korrektur: mbedtls_pkcs5_pbkdf2_hmac wurde zu mbedtls_pkcs5_pbkdf2_hmac_ext
    return mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
                                          (const unsigned char*)password, strlen(password),
                                          salt, salt_len,
                                          PBKDF2_ITERATIONS,
                                          output_key_len, output_key);
}

/**
 * @brief Wraps (encrypts) a key using AES-GCM.
 * The output format will be IV || Ciphertext || Tag.
 *
 * @param wrapping_key The key used to wrap (encrypt) the plaintext key. (e.g., MAK)
 * @param plaintext_key The key to be wrapped (encrypted).
 * @param plaintext_key_len The length of the plaintext key in bytes.
 * @param wrapped_key_out Buffer to store the wrapped key (IV || Ciphertext || Tag).
 * Must be large enough: GCM_IV_SIZE_BYTES + plaintext_key_len + GCM_TAG_SIZE_BYTES.
 * @return 0 on success, MBEDTLS_ERR_GCM_AUTH_FAILED on authentication failure, or other MBEDTLS_ERR_XXX on error.
 */
int aes_key_wrap(const unsigned char *wrapping_key, const unsigned char *plaintext_key, size_t plaintext_key_len, unsigned char *wrapped_key_out) {
    mbedtls_gcm_context gcm_ctx;
    unsigned char iv[GCM_IV_SIZE_BYTES];
    int ret;

    // Initialisiere GCM-Kontext
    mbedtls_gcm_init(&gcm_ctx);

    // Setze den Wrapping-Schlüssel
    ret = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, wrapping_key, AES_KEY_SIZE_BYTES * 8);
    if (ret != 0) {
        Serial.printf("ERR: GCM Setkey (wrap) fehlgeschlagen! 0x%04X\n", ret);
        mbedtls_gcm_free(&gcm_ctx);
        return ret;
    }

    // Generiere einen zufälligen IV
    ret = mbedtls_ctr_drbg_random(&ctr_drbg_ctx, iv, GCM_IV_SIZE_BYTES);
    if (ret != 0) {
        Serial.printf("ERR: IV-Generierung (wrap) fehlgeschlagen! 0x%04X\n", ret);
        mbedtls_gcm_free(&gcm_ctx);
        return ret;
    }

    // Verschlüssele den Klartext-Schlüssel und generiere den Tag
    // wrapped_key_out Layout: IV (12B) | Ciphertext (plaintext_key_len) | Tag (16B)
    memcpy(wrapped_key_out, iv, GCM_IV_SIZE_BYTES); // Kopiere IV an den Anfang

    unsigned char *ciphertext_out = wrapped_key_out + GCM_IV_SIZE_BYTES;
    unsigned char *tag_out = ciphertext_out + plaintext_key_len;

    ret = mbedtls_gcm_crypt_and_tag(&gcm_ctx, MBEDTLS_GCM_ENCRYPT, plaintext_key_len,
                                     iv, GCM_IV_SIZE_BYTES,
                                     NULL, 0, // Keine zusätzlichen Authentifizierungsdaten (AAD)
                                     plaintext_key, ciphertext_out,
                                     GCM_TAG_SIZE_BYTES, tag_out);

    mbedtls_gcm_free(&gcm_ctx);

    if (ret != 0) {
        Serial.printf("ERR: GCM Encrypt (wrap) fehlgeschlagen! 0x%04X\n", ret);
        return ret;
    }

    return 0; // Erfolg
}

/**
 * @brief Unwraps (decrypts) a key using AES-GCM.
 * Expects input format IV || Ciphertext || Tag.
 *
 * @param unwrapping_key The key used to unwrap (decrypt) the wrapped key. (e.g., MAK)
 * @param wrapped_key_in Buffer containing the wrapped key (IV || Ciphertext || Tag).
 * @param wrapped_key_len The total length of the wrapped key (IV + Ciphertext + Tag).
 * @param plaintext_key_out Buffer to store the unwrapped (plaintext) key.
 * Must be large enough: wrapped_key_len - GCM_IV_SIZE_BYTES - GCM_TAG_SIZE_BYTES.
 * @return 0 on success, MBEDTLS_ERR_GCM_AUTH_FAILED on authentication failure, or other MBEDTLS_ERR_XXX on error.
 */
int aes_key_unwrap(const unsigned char *unwrapping_key, const unsigned char *wrapped_key_in, size_t wrapped_key_len, unsigned char *plaintext_key_out) {
    mbedtls_gcm_context gcm_ctx;
    unsigned char iv[GCM_IV_SIZE_BYTES];
    unsigned char tag[GCM_TAG_SIZE_BYTES];
    size_t ciphertext_len;
    int ret;

    if (wrapped_key_len < (GCM_IV_SIZE_BYTES + GCM_TAG_SIZE_BYTES)) {
        Serial.println("ERR: Wrapped key zu kurz für GCM IV und Tag.");
        return -1; // Ungültige Eingabelänge
    }

    // Extrahiere IV, Ciphertext und Tag
    memcpy(iv, wrapped_key_in, GCM_IV_SIZE_BYTES);
    ciphertext_len = wrapped_key_len - GCM_IV_SIZE_BYTES - GCM_TAG_SIZE_BYTES;
    const unsigned char *ciphertext_in = wrapped_key_in + GCM_IV_SIZE_BYTES;
    memcpy(tag, wrapped_key_in + GCM_IV_SIZE_BYTES + ciphertext_len, GCM_TAG_SIZE_BYTES);

    // Initialisiere GCM-Kontext
    mbedtls_gcm_init(&gcm_ctx);

    // Setze den Unwrapping-Schlüssel
    ret = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, unwrapping_key, AES_KEY_SIZE_BYTES * 8);
    if (ret != 0) {
        Serial.printf("ERR: GCM Setkey (unwrap) fehlgeschlagen! 0x%04X\n", ret);
        mbedtls_gcm_free(&gcm_ctx);
        return ret;
    }

    // Entschlüssele den Schlüssel und verifiziere den Tag
    ret = mbedtls_gcm_crypt_and_tag(&gcm_ctx, MBEDTLS_GCM_DECRYPT, ciphertext_len,
                                     iv, GCM_IV_SIZE_BYTES,
                                     NULL, 0, // Keine zusätzlichen Authentifizierungsdaten (AAD)
                                     ciphertext_in, plaintext_key_out,
                                     GCM_TAG_SIZE_BYTES, tag);

    mbedtls_gcm_free(&gcm_ctx);

    if (ret != 0) {
        Serial.printf("ERR: GCM Decrypt (unwrap) fehlgeschlagen oder Tag ungültig! 0x%04X\n", ret);
        return ret;
    }

    return 0; // Erfolg
}

// Initialisierung des HSM (Hardware Security Module)
void hsm_init() {
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg_ctx);

    const char* pers = "hsm_device_entropy";
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy,
                                      (const unsigned char*) pers, strlen(pers));
    if (ret != 0) {
        Serial.printf("ERR: mbedtls_ctr_drbg_seed fehlgeschlagen! 0x%04X\n", ret);
        while(1); // Fatal error, halt
    }
    Serial.println("HSM RNG Seeded.");

    preferences.begin("hsm-storage", false); // NVS im Read/Write-Modus starten

    // Versuch, MAK aus NVS zu laden
    size_t read_bytes = preferences.getBytes("master_auth_key", master_auth_key, AES_KEY_SIZE_BYTES);
    if (read_bytes == AES_KEY_SIZE_BYTES) {
        mak_loaded = true;
        Serial.println("MAK aus NVS geladen.");
    } else {
        Serial.println("MAK nicht in NVS gefunden. Muss neu gesetzt werden.");
        mak_loaded = false;
    }

    mbedtls_gcm_init(&gcm_ctx); // GCM Kontext initialisieren
    mbedtls_aes_init(&aes_ctx); // AES Kontext initialisieren
}

// --- Handler Funktionen für serielle Befehle ---

void handleSetMAK(String command) {
    if (mak_loaded) {
        Serial.print(NVS_SET_MAK_MARKER_START); Serial.print(INVALID_INPUT_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: MAK ist bereits gesetzt und kann nicht überschrieben werden.");
        return;
    }

    int colon_idx = command.indexOf(':');
    int data_end_idx = command.indexOf(DATA_END_MARKER);

    if (colon_idx == -1 || data_end_idx == -1 || data_end_idx <= colon_idx) {
        Serial.print(NVS_SET_MAK_MARKER_START); Serial.print(INVALID_INPUT_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: Ungültiges Format für NVS_SET_MAK.");
        return;
    }

    String mak_hex = command.substring(colon_idx + 1, data_end_idx);
    if (mak_hex.length() != AES_KEY_SIZE_BYTES * 2) {
        Serial.print(NVS_SET_MAK_MARKER_START); Serial.print(INVALID_INPUT_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: Ungültige Länge des MAK Hex-Strings.");
        return;
    }

    if (hex_to_bytes(mak_hex.c_str(), master_auth_key, AES_KEY_SIZE_BYTES) == 0) {
        Serial.print(NVS_SET_MAK_MARKER_START); Serial.print(INVALID_INPUT_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: Konvertierung von MAK Hex zu Bytes fehlgeschlagen.");
        return;
    }

    if (preferences.putBytes("master_auth_key", master_auth_key, AES_KEY_SIZE_BYTES) == 0) {
        Serial.print(NVS_SET_MAK_MARKER_START); Serial.print(NVS_FAILED_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: Speichern des MAK in NVS fehlgeschlagen.");
        return;
    }

    mak_loaded = true;
    Serial.print(NVS_SET_MAK_MARKER_START); Serial.print(OK_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
    Serial.println("MAK erfolgreich in NVS gespeichert.");
    print_hex("Gesetzter MAK", master_auth_key, AES_KEY_SIZE_BYTES);
}

void handleSetAuthToken(String command) {
    if (!mak_loaded) {
        Serial.print(AUTH_TOKEN_SET_REQ_MARKER_START); Serial.print(NVS_FAILED_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: MAK nicht geladen. Kann Auth Token nicht setzen.");
        return;
    }

    // AUTH_TOKEN_SET_REQ:group_id:password_hex:salt_hex:END
    int first_colon = command.indexOf(':');
    int second_colon = command.indexOf(':', first_colon + 1);
    int third_colon = command.indexOf(':', second_colon + 1);
    int data_end_idx = command.indexOf(DATA_END_MARKER);

    if (first_colon == -1 || second_colon == -1 || third_colon == -1 || data_end_idx == -1 ||
        third_colon >= data_end_idx) {
        Serial.print(AUTH_TOKEN_SET_REQ_MARKER_START); Serial.print(INVALID_INPUT_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: Ungültiges Format für AUTH_TOKEN_SET_REQ.");
        return;
    }

    String group_id = command.substring(first_colon + 1, second_colon);
    String password_hex = command.substring(second_colon + 1, third_colon);
    String salt_hex = command.substring(third_colon + 1, data_end_idx);

    if (group_id.length() == 0 || password_hex.length() == 0 || salt_hex.length() != PBKDF2_SALT_SIZE_BYTES * 2) {
        Serial.print(AUTH_TOKEN_SET_REQ_MARKER_START); Serial.print(INVALID_INPUT_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: Ungültige Länge von Group ID, Passwort oder Salt.");
        return;
    }

    unsigned char salt[PBKDF2_SALT_SIZE_BYTES];
    if (hex_to_bytes(salt_hex.c_str(), salt, PBKDF2_SALT_SIZE_BYTES) == 0) {
        Serial.print(AUTH_TOKEN_SET_REQ_MARKER_START); Serial.print(INVALID_INPUT_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: Konvertierung von Salt Hex zu Bytes fehlgeschlagen.");
        return;
    }

    unsigned char derived_key[AES_KEY_SIZE_BYTES];
    if (derive_key_pbkdf2(password_hex.c_str(), salt, PBKDF2_SALT_SIZE_BYTES, derived_key, AES_KEY_SIZE_BYTES) != 0) {
        Serial.print(AUTH_TOKEN_SET_REQ_MARKER_START); Serial.print(INTERNAL_ERROR_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: PBKDF2 Schlüsselableitung fehlgeschlagen.");
        return;
    }

    unsigned char wrapped_token[AES_KEY_SIZE_BYTES + 8]; // Key-Wrap fügt 8 Bytes hinzu
    int ret = aes_key_wrap(master_auth_key, derived_key, AES_KEY_SIZE_BYTES, wrapped_token);
    if (ret != 0) {
        Serial.printf("ERR: AES Key Wrap fehlgeschlagen! 0x%04X\n", ret);
        Serial.print(AUTH_TOKEN_SET_REQ_MARKER_START); Serial.print(INTERNAL_ERROR_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        return;
    }

    String wrapped_token_hex = bytes_to_hex_string(wrapped_token, AES_KEY_SIZE_BYTES + 8);

    String nvs_key = "auth_" + group_id;
    if (!preferences.putString(nvs_key.c_str(), wrapped_token_hex)) {
        Serial.print(AUTH_TOKEN_SET_REQ_MARKER_START); Serial.print(NVS_FAILED_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.printf("ERR: Speichern des Auth Tokens für Gruppe '%s' in NVS fehlgeschlagen.\n", group_id.c_str());
        return;
    }

    Serial.print(AUTH_TOKEN_SET_REQ_MARKER_START); Serial.print(OK_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
    Serial.printf("Auth Token für Gruppe '%s' erfolgreich gesetzt.\n", group_id.c_str());
}

void handleEcdhRequest(String command) {
    if (!mak_loaded) {
        Serial.print(ECDH_PUBKEY_REQ_MARKER_START); Serial.print(NVS_FAILED_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: MAK nicht geladen. Kann ECDH Schlüsselpaar nicht generieren.");
        return;
    }

    mbedtls_pk_context pk_ctx;
    mbedtls_pk_init(&pk_ctx);
    int ret;

    // Generiere ein neues EC-Schlüsselpaar (P-256)
    ret = mbedtls_pk_setup(&pk_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret != 0) {
        Serial.printf("ERR: mbedtls_pk_setup fehlgeschlagen! 0x%04X\n", ret);
        Serial.print(ECDH_PUBKEY_REQ_MARKER_START); Serial.print(INTERNAL_ERROR_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        mbedtls_pk_free(&pk_ctx);
        return;
    }

    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk_ctx), mbedtls_ctr_drbg_random, &ctr_drbg_ctx);
    if (ret != 0) {
        Serial.printf("ERR: mbedtls_ecp_gen_key fehlgeschlagen! 0x%04X\n", ret);
        Serial.print(ECDH_PUBKEY_REQ_MARKER_START); Serial.print(INTERNAL_ERROR_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        mbedtls_pk_free(&pk_ctx);
        return;
    }

    unsigned char public_key_der[100]; // Genug Platz für DER-kodierten P-256 Public Key
    size_t public_key_len = 0;
    ret = mbedtls_pk_write_pubkey_der(&pk_ctx, public_key_der, sizeof(public_key_der));
    if (ret < 0) {
        Serial.printf("ERR: mbedtls_pk_write_pubkey_der fehlgeschlagen! 0x%04X\n", ret);
        Serial.print(ECDH_PUBKEY_REQ_MARKER_START); Serial.print(INTERNAL_ERROR_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        mbedtls_pk_free(&pk_ctx);
        return;
    }
    public_key_len = ret;
    // Der DER-kodierte Schlüssel wird vom Ende des Puffers geschrieben, also passen wir den Zeiger an.
    unsigned char* actual_public_key_der = public_key_der + sizeof(public_key_der) - public_key_len;
    String public_key_hex = bytes_to_hex_string(actual_public_key_der, public_key_len);


    unsigned char private_key_der[100]; // Genug Platz für DER-kodierten P-256 Private Key
    size_t private_key_len = 0;
    ret = mbedtls_pk_write_key_der(&pk_ctx, private_key_der, sizeof(private_key_der));
    if (ret < 0) {
        Serial.printf("ERR: mbedtls_pk_write_key_der fehlgeschlagen! 0x%04X\n", ret);
        Serial.print(ECDH_PUBKEY_REQ_MARKER_START); Serial.print(INTERNAL_ERROR_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        mbedtls_pk_free(&pk_ctx);
        return;
    }
    private_key_len = ret;
    // Der DER-kodierte Schlüssel wird vom Ende des Puffers geschrieben, also passen wir den Zeiger an.
    unsigned char* actual_private_key_der = private_key_der + sizeof(private_key_der) - private_key_len;
    String private_key_hex = bytes_to_hex_string(actual_private_key_der, private_key_len);

    // Speichere den privaten Schlüssel verschlüsselt in NVS
    unsigned char wrapped_priv_key[private_key_len + 8]; // Key-Wrap fügt 8 Bytes hinzu
    ret = aes_key_wrap(master_auth_key, actual_private_key_der, private_key_len, wrapped_priv_key);
    if (ret != 0) {
        Serial.printf("ERR: Wrapping des privaten Schlüssels fehlgeschlagen! 0x%04X\n", ret);
        Serial.print(ECDH_PUBKEY_REQ_MARKER_START); Serial.print(INTERNAL_ERROR_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        mbedtls_pk_free(&pk_ctx);
        return;
    }
    String wrapped_priv_key_hex = bytes_to_hex_string(wrapped_priv_key, private_key_len + 8);

    if (!preferences.putString("ecdh_priv_key", wrapped_priv_key_hex)) {
        Serial.print(ECDH_PUBKEY_REQ_MARKER_START); Serial.print(NVS_FAILED_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: Speichern des verschlüsselten privaten ECDH-Schlüssels in NVS fehlgeschlagen.");
        mbedtls_pk_free(&pk_ctx);
        return;
    }

    Serial.print(ECDH_PUBKEY_RESP_MARKER_START); Serial.print(public_key_hex); Serial.print(DATA_END_MARKER); Serial.println();
    Serial.println("ECDH Public Key generiert und privater Schlüssel gespeichert.");

    mbedtls_pk_free(&pk_ctx); // Kontext freigeben
}

void handleAuthRequest(String command) {
    if (!mak_loaded) {
        Serial.print(AUTH_REQ_GROUP_MARKER_START); Serial.print(NVS_FAILED_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: MAK nicht geladen. Kann Authentifizierung nicht durchführen.");
        return;
    }

    // AUTH_REQ_GROUP:group_id:END
    int first_colon = command.indexOf(':');
    int data_end_idx = command.indexOf(DATA_END_MARKER);

    if (first_colon == -1 || data_end_idx == -1 || data_end_idx <= first_colon) {
        Serial.print(AUTH_REQ_GROUP_MARKER_START); Serial.print(INVALID_INPUT_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: Ungültiges Format für AUTH_REQ_GROUP.");
        return;
    }

    String group_id = command.substring(first_colon + 1, data_end_idx);
    if (group_id.length() == 0) {
        Serial.print(AUTH_REQ_GROUP_MARKER_START); Serial.print(INVALID_INPUT_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: Leere Group ID.");
        return;
    }

    String nvs_key = "auth_" + group_id;
    String wrapped_token_hex = preferences.getString(nvs_key.c_str());

    if (wrapped_token_hex.length() == 0) {
        Serial.print(AUTH_REQ_GROUP_MARKER_START); Serial.print(NOT_FOUND_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.printf("ERR: Auth Token für Gruppe '%s' nicht gefunden.\n", group_id.c_str());
        return;
    }

    unsigned char wrapped_token[wrapped_token_hex.length() / 2];
    if (hex_to_bytes(wrapped_token_hex.c_str(), wrapped_token, sizeof(wrapped_token)) == 0) {
        Serial.print(AUTH_REQ_GROUP_MARKER_START); Serial.print(INTERNAL_ERROR_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: Konvertierung von Wrapped Token Hex zu Bytes fehlgeschlagen.");
        return;
    }

    // Generiere Challenge
    unsigned char challenge[CHALLENGE_SIZE_BYTES];
    mbedtls_ctr_drbg_random(&ctr_drbg_ctx, challenge, CHALLENGE_SIZE_BYTES);
    String challenge_hex = bytes_to_hex_string(challenge, CHALLENGE_SIZE_BYTES);

    // Speichere die Challenge temporär in NVS für spätere Überprüfung
    String challenge_nvs_key = "chall_" + group_id;
    if (!preferences.putString(challenge_nvs_key.c_str(), challenge_hex)) {
        Serial.print(AUTH_REQ_GROUP_MARKER_START); Serial.print(NVS_FAILED_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.printf("ERR: Speichern der Challenge für Gruppe '%s' in NVS fehlgeschlagen.\n", group_id.c_str());
        return;
    }

    Serial.print(AUTH_CHALLENGE_RESP_MARKER_START); Serial.print(group_id); Serial.print(":"); Serial.print(challenge_hex); Serial.print(DATA_END_MARKER); Serial.println();
    Serial.printf("Challenge für Gruppe '%s' gesendet.\n", group_id.c_str());
}

void handleAuthResponse(String command) {
    if (!mak_loaded) {
        Serial.print(AUTH_RESPONSE_MARKER_START); Serial.print(NVS_FAILED_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: MAK nicht geladen. Kann Authentifizierung nicht prüfen.");
        return;
    }

    // AUTH_RESPONSE:group_id:response_token_hex:END
    int first_colon = command.indexOf(':');
    int second_colon = command.indexOf(':', first_colon + 1);
    int data_end_idx = command.indexOf(DATA_END_MARKER);

    if (first_colon == -1 || second_colon == -1 || data_end_idx == -1 || second_colon >= data_end_idx) {
        Serial.print(AUTH_RESPONSE_MARKER_START); Serial.print(INVALID_INPUT_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: Ungültiges Format für AUTH_RESPONSE.");
        return;
    }

    String group_id = command.substring(first_colon + 1, second_colon);
    String response_token_hex = command.substring(second_colon + 1, data_end_idx);

    if (group_id.length() == 0 || response_token_hex.length() != AUTH_TOKEN_SIZE_BYTES * 2) {
        Serial.print(AUTH_RESPONSE_MARKER_START); Serial.print(INVALID_INPUT_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: Ungültige Länge von Group ID oder Response Token.");
        return;
    }

    String nvs_key = "auth_" + group_id;
    String wrapped_token_hex = preferences.getString(nvs_key.c_str());
    if (wrapped_token_hex.length() == 0) {
        Serial.print(AUTH_RESPONSE_MARKER_START); Serial.print(NOT_FOUND_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.printf("ERR: Auth Token für Gruppe '%s' nicht gefunden.\n", group_id.c_str());
        return;
    }

    unsigned char wrapped_token[wrapped_token_hex.length() / 2];
    if (hex_to_bytes(wrapped_token_hex.c_str(), wrapped_token, sizeof(wrapped_token)) == 0) {
        Serial.print(AUTH_RESPONSE_MARKER_START); Serial.print(INTERNAL_ERROR_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: Konvertierung von Wrapped Token Hex zu Bytes fehlgeschlagen.");
        return;
    }

    unsigned char unwrapped_token[AES_KEY_SIZE_BYTES];
    int ret = aes_key_unwrap(master_auth_key, wrapped_token, sizeof(wrapped_token), unwrapped_token);
    if (ret != 0) {
        Serial.printf("ERR: AES Key Unwrap fehlgeschlagen! 0x%04X\n", ret);
        Serial.print(AUTH_RESPONSE_MARKER_START); Serial.print(INTERNAL_ERROR_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        return;
    }

    String challenge_nvs_key = "chall_" + group_id;
    String challenge_hex = preferences.getString(challenge_nvs_key.c_str());
    if (challenge_hex.length() == 0) {
        Serial.print(AUTH_RESPONSE_MARKER_START); Serial.print(NOT_FOUND_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.printf("ERR: Challenge für Gruppe '%s' nicht gefunden.\n", group_id.c_str());
        return;
    }

    unsigned char challenge[CHALLENGE_SIZE_BYTES];
    if (hex_to_bytes(challenge_hex.c_str(), challenge, CHALLENGE_SIZE_BYTES) == 0) {
        Serial.print(AUTH_RESPONSE_MARKER_START); Serial.print(INTERNAL_ERROR_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: Konvertierung von Challenge Hex zu Bytes fehlgeschlagen.");
        return;
    }

    // Berechne den erwarteten Response Token (HMAC-SHA256(unwrapped_token, challenge))
    unsigned char expected_response[AUTH_TOKEN_SIZE_BYTES];
    mbedtls_md_context_t hmac_ctx;
    mbedtls_md_init(&hmac_ctx);
    mbedtls_md_setup(&hmac_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1); // 1 für HMAC

    mbedtls_md_hmac_starts(&hmac_ctx, unwrapped_token, AES_KEY_SIZE_BYTES);
    mbedtls_md_hmac_update(&hmac_ctx, challenge, CHALLENGE_SIZE_BYTES);
    mbedtls_md_hmac_finish(&hmac_ctx, expected_response);
    mbedtls_md_free(&hmac_ctx);

    unsigned char actual_response[AUTH_TOKEN_SIZE_BYTES];
    if (hex_to_bytes(response_token_hex.c_str(), actual_response, AUTH_TOKEN_SIZE_BYTES) == 0) {
        Serial.print(AUTH_RESPONSE_MARKER_START); Serial.print(INVALID_INPUT_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.println("ERR: Konvertierung von Response Token Hex zu Bytes fehlgeschlagen.");
        return;
    }

    if (memcmp(expected_response, actual_response, AUTH_TOKEN_SIZE_BYTES) == 0) {
        Serial.print(AUTH_SUCCESS_RESP_MARKER_START); Serial.print(group_id); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.printf("Authentifizierung für Gruppe '%s' erfolgreich.\n", group_id.c_str());
    } else {
        Serial.print(AUTH_RESPONSE_MARKER_START); Serial.print(AUTH_FAILED_MARKER); Serial.print(DATA_END_MARKER); Serial.println();
        Serial.printf("Authentifizierung für Gruppe '%s' fehlgeschlagen.\n", group_id.c_str());
    }

    // Lösche die Challenge nach Gebrauch
    preferences.remove(challenge_nvs_key.c_str());
}

void handleEncryptFileRequest(String command) {
    // Variablen deklarieren und initialisieren
    String hex_encrypted_session_key;
    String hex_encrypted_plaintext;
    std::vector<unsigned char> encrypted_session_key_bytes;
    std::vector<unsigned char> encrypted_plaintext_bytes; // <-- Diese Zeile wurde hinzugefügt/korrigiert
    String encrypted_fek_metadata_hex;
    String encrypted_content_hex;

    if (!mak_loaded) {
        Serial.print(ENCRYPT_FILE_RESP_MARKER_START);
        Serial.print(NVS_FAILED_MARKER);
        Serial.print(DATA_END_MARKER);
        Serial.println();
        Serial.println("ERR: MAK nicht geladen. Kann Datei nicht verschlüsseln.");
        return;
    }

    // ENCRYPT_FILE_REQ:group_id:hex_encrypted_session_key:hex_encrypted_plaintext:END
    int first_colon = command.indexOf(':');
    int second_colon = command.indexOf(':', first_colon + 1);
    int third_colon = command.indexOf(':', second_colon + 1);
    int data_end_idx = command.indexOf(DATA_END_MARKER);

    if (first_colon == -1 || second_colon == -1 || third_colon == -1 || data_end_idx == -1 || third_colon >= data_end_idx) {
        Serial.print(ENCRYPT_FILE_RESP_MARKER_START);
        Serial.print(INVALID_INPUT_MARKER);
        Serial.print(DATA_END_MARKER);
        Serial.println();
        Serial.println("ERR: Ungültiges Format für ENCRYPT_FILE_REQ.");
        return;
    }

    String group_id = command.substring(first_colon + 1, second_colon);
    hex_encrypted_session_key = command.substring(second_colon + 1, third_colon);
    hex_encrypted_plaintext = command.substring(third_colon + 1, data_end_idx);

    if (group_id.length() == 0 || hex_encrypted_session_key.length() == 0 || hex_encrypted_plaintext.length() == 0) {
        Serial.print(ENCRYPT_FILE_RESP_MARKER_START);
        Serial.print(INVALID_INPUT_MARKER);
        Serial.print(DATA_END_MARKER);
        Serial.println();
        Serial.println("ERR: Leere Group ID, verschlüsselter Session Key oder Plaintext.");
        return;
    }

    if (hex_encrypted_session_key.length() % 2 != 0) {
        Serial.println("ERR: Ungültige Länge des verschlüsselten Sitzungsschlüssels.");
        Serial.print(ENCRYPT_FILE_RESP_MARKER_START);
        Serial.print(ENCRYPT_FAILED_MARKER);
        Serial.print(DATA_END_MARKER);
        Serial.println();
        return;
    }

    encrypted_session_key_bytes.resize(hex_encrypted_session_key.length() / 2);
    if (hex_to_bytes(hex_encrypted_session_key.c_str(), encrypted_session_key_bytes.data(), encrypted_session_key_bytes.size()) == 0) {
        Serial.print(ENCRYPT_FILE_RESP_MARKER_START);
        Serial.print(INVALID_INPUT_MARKER);
        Serial.print(DATA_END_MARKER);
        Serial.println();
        Serial.println("ERR: Konvertierung von verschlüsseltem Session Key Hex zu Bytes fehlgeschlagen.");
        return;
    }

    unsigned char session_key[AES_KEY_SIZE_BYTES];
    int ret = aes_key_unwrap(master_auth_key, encrypted_session_key_bytes.data(), encrypted_session_key_bytes.size(), session_key);
    if (ret != 0) {
        Serial.printf("ERR: AES Key Unwrap für Session Key fehlgeschlagen! 0x%04X\n", ret);
        Serial.print(ENCRYPT_FILE_RESP_MARKER_START);
        Serial.print(INTERNAL_ERROR_MARKER);
        Serial.print(DATA_END_MARKER);
        Serial.println();
        return;
    }

    if (hex_encrypted_plaintext.length() % 2 != 0) {
        Serial.println("ERR: Ungültige Länge des zu verschlüsselnden Plaintexts (IV+Ciphertext+Tag).");
        Serial.print(ENCRYPT_FILE_RESP_MARKER_START);
        Serial.print(ENCRYPT_FAILED_MARKER);
        Serial.print(DATA_END_MARKER);
        Serial.println();
        return;
    }

    encrypted_plaintext_bytes.resize(hex_encrypted_plaintext.length() / 2);
    if (hex_to_bytes(hex_encrypted_plaintext.c_str(), encrypted_plaintext_bytes.data(), encrypted_plaintext_bytes.size()) == 0) {
        Serial.print(ENCRYPT_FILE_RESP_MARKER_START);
        Serial.print(INVALID_INPUT_MARKER);
        Serial.print(DATA_END_MARKER);
        Serial.println();
        Serial.println("ERR: Konvertierung von Plaintext Hex zu Bytes fehlgeschlagen.");
        return;
    }

    // ACHTUNG: Der folgende Teil der Logik (GCM-Verschlüsselung) war im Original-Snippet unvollständig.
    // Sie müssen hier die eigentliche Implementierung der GCM-Verschlüsselung mit dem
    // `session_key` und `encrypted_plaintext_bytes` (dem Klartext, der verschlüsselt werden soll) hinzufügen.
    // Die Platzhalter-Ausgabe unten dient nur dazu, den Kompilierungsfehler zu beheben.

    Serial.print(ENCRYPT_FILE_RESP_MARKER_START);
    Serial.print(group_id); // Annahme: group_id wird zurückgegeben
    Serial.print(":");
    Serial.print(OK_MARKER); // Dies ist ein Platzhalter und muss durch die echten verschlüsselten Daten ersetzt werden
    Serial.print(DATA_END_MARKER);
    Serial.println();
    Serial.printf("Dateiverschlüsselungsanfrage für Gruppe '%s' bearbeitet (weitere GCM-Implementierung nötig).\n", group_id.c_str());
}

void handleDecryptFileRequest(String command) {
    // Variablen deklarieren und initialisieren
    String hex_encrypted_fek_metadata;
    String hex_encrypted_file_content;
    std::vector<unsigned char> encrypted_fek_meta_bytes;
    std::vector<unsigned char> fek_ciphertext;
    std::vector<unsigned char> encrypted_file_content_bytes;
    std::vector<unsigned char> iv_from_pc;
    std::vector<unsigned char> tag_from_pc;
    std::vector<unsigned char> actual_ciphertext_to_decrypt;
    std::vector<unsigned char> plaintext_dec_buffer;
    String decrypted_file_content_hex;

    if (!mak_loaded) {
        Serial.print(DECRYPT_FILE_RESP_MARKER_START);
        Serial.print(NVS_FAILED_MARKER);
        Serial.print(DATA_END_MARKER);
        Serial.println();
        Serial.println("ERR: MAK nicht geladen. Kann Datei nicht entschlüsseln.");
        return;
    }

    // DECRYPT_FILE_REQ:group_id:hex_encrypted_fek_metadata:hex_encrypted_file_content:END
    int first_colon = command.indexOf(':');
    int second_colon = command.indexOf(':', first_colon + 1);
    int third_colon = command.indexOf(':', second_colon + 1);
    int data_end_idx = command.indexOf(DATA_END_MARKER);

    if (first_colon == -1 || second_colon == -1 || third_colon == -1 || data_end_idx == -1 || third_colon >= data_end_idx) {
        Serial.print(DECRYPT_FILE_RESP_MARKER_START);
        Serial.print(INVALID_INPUT_MARKER);
        Serial.print(DATA_END_MARKER);
        Serial.println();
        Serial.println("ERR: Ungültiges Format für DECRYPT_FILE_REQ.");
        return;
    }

    String group_id = command.substring(first_colon + 1, second_colon);
    hex_encrypted_fek_metadata = command.substring(second_colon + 1, third_colon);
    hex_encrypted_file_content = command.substring(third_colon + 1, data_end_idx);

    if (group_id.length() == 0 || hex_encrypted_fek_metadata.length() == 0 || hex_encrypted_file_content.length() == 0) {
        Serial.print(DECRYPT_FILE_RESP_MARKER_START);
        Serial.print(INVALID_INPUT_MARKER);
        Serial.print(DATA_END_MARKER);
        Serial.println();
        Serial.println("ERR: Leere Group ID, verschlüsselte FEK Metadaten oder verschlüsselter Dateiinhalte.");
        return;
    }

    // Konvertiere hex_encrypted_fek_metadata zu Bytes
    size_t full_fek_meta_len = hex_encrypted_fek_metadata.length() / 2;
    if (full_fek_meta_len == 0) {
        Serial.print(DECRYPT_FILE_RESP_MARKER_START);
        Serial.print(INVALID_INPUT_MARKER);
        Serial.print(DATA_END_MARKER);
        Serial.println();
        Serial.println("ERR: Ungültige Länge der FEK Metadaten (muss > 0 sein).");
        return;
    }
    encrypted_fek_meta_bytes.resize(full_fek_meta_len);
    if (hex_to_bytes(hex_encrypted_fek_metadata.c_str(), encrypted_fek_meta_bytes.data(), full_fek_meta_len) == 0) {
        Serial.print(DECRYPT_FILE_RESP_MARKER_START);
        Serial.print(INVALID_INPUT_MARKER);
        Serial.print(DATA_END_MARKER);
        Serial.println();
        Serial.println("ERR: Konvertierung von verschlüsselten FEK Metadaten Hex zu Bytes fehlgeschlagen.");
        return;
    }

    // Entschlüsseln des FEK mit dem Master Access Key (MAK)
    fek_ciphertext.resize(AES_KEY_SIZE_BYTES); // Annahme: FEK hat AES_KEY_SIZE_BYTES
    int ret = aes_key_unwrap(master_auth_key, encrypted_fek_meta_bytes.data(), full_fek_meta_len, fek_ciphertext.data());
    if (ret != 0) {
        Serial.printf("ERR: AES Key Unwrap für FEK fehlgeschlagen! 0x%04X\n", ret);
        Serial.print(DECRYPT_FILE_RESP_MARKER_START);
        Serial.print(INTERNAL_ERROR_MARKER);
        Serial.print(DATA_END_MARKER);
        Serial.println();
        return;
    }
    unsigned char file_encryption_key[AES_KEY_SIZE_BYTES];
    memcpy(file_encryption_key, fek_ciphertext.data(), AES_KEY_SIZE_BYTES);


    // Konvertiere hex_encrypted_file_content zu Bytes
    size_t ciphertext_from_pc_len = hex_encrypted_file_content.length() / 2;
    if (ciphertext_from_pc_len == 0 || ciphertext_from_pc_len < (GCM_IV_SIZE_BYTES + GCM_TAG_SIZE_BYTES)) {
        Serial.print(DECRYPT_FILE_RESP_MARKER_START);
        Serial.print(INVALID_INPUT_MARKER);
        Serial.print(DATA_END_MARKER);
        Serial.println();
        Serial.println("ERR: Ungültige Länge des verschlüsselten Dateiinhalts.");
        return;
    }
    encrypted_file_content_bytes.resize(ciphertext_from_pc_len);
    if (hex_to_bytes(hex_encrypted_file_content.c_str(), encrypted_file_content_bytes.data(), ciphertext_from_pc_len) == 0) {
        Serial.print(DECRYPT_FILE_RESP_MARKER_START);
        Serial.print(INVALID_INPUT_MARKER);
        Serial.print(DATA_END_MARKER);
        Serial.println();
        Serial.println("ERR: Konvertierung von verschlüsseltem Dateiinhalte Hex zu Bytes fehlgeschlagen.");
        return;
    }

    // Trennen von IV, Ciphertext und Tag
    iv_from_pc.resize(GCM_IV_SIZE_BYTES);
    memcpy(iv_from_pc.data(), encrypted_file_content_bytes.data(), GCM_IV_SIZE_BYTES);

    tag_from_pc.resize(GCM_TAG_SIZE_BYTES);
    memcpy(tag_from_pc.data(), encrypted_file_content_bytes.data() + ciphertext_from_pc_len - GCM_TAG_SIZE_BYTES, GCM_TAG_SIZE_BYTES);

    actual_ciphertext_to_decrypt.resize(ciphertext_from_pc_len - GCM_IV_SIZE_BYTES - GCM_TAG_SIZE_BYTES);
    memcpy(actual_ciphertext_to_decrypt.data(), encrypted_file_content_bytes.data() + GCM_IV_SIZE_BYTES, actual_ciphertext_to_decrypt.size());

    // GCM-Entschlüsselung des Dateiinhalts
    mbedtls_gcm_context gcm_ctx;
    mbedtls_gcm_init(&gcm_ctx);

    ret = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, file_encryption_key, AES_KEY_SIZE_BYTES * 8);
    if (ret != 0) {
        Serial.printf("ERR: GCM Setkey fehlgeschlagen! 0x%04X\n", ret);
        Serial.print(DECRYPT_FILE_RESP_MARKER_START);
        Serial.print(INTERNAL_ERROR_MARKER);
        Serial.print(DATA_END_MARKER);
        Serial.println();
        mbedtls_gcm_free(&gcm_ctx);
        return;
    }

    plaintext_dec_buffer.resize(actual_ciphertext_to_decrypt.size()); // Puffer für den entschlüsselten Klartext
    ret = mbedtls_gcm_crypt_and_tag(&gcm_ctx, MBEDTLS_GCM_DECRYPT, actual_ciphertext_to_decrypt.size(),
                                     iv_from_pc.data(), iv_from_pc.size(),
                                     NULL, 0, // Keine zusätzlichen Authentifizierungsdaten (AAD)
                                     actual_ciphertext_to_decrypt.data(), plaintext_dec_buffer.data(),
                                     tag_from_pc.size(), tag_from_pc.data());
    mbedtls_gcm_free(&gcm_ctx);

    if (ret != 0) {
        Serial.printf("ERR: GCM Decrypt fehlgeschlagen oder Tag ungültig! 0x%04X\n", ret);
        Serial.print(DECRYPT_FILE_RESP_MARKER_START);
        Serial.print(DECRYPT_FAILED_MARKER);
        Serial.print(DATA_END_MARKER);
        Serial.println();
        return;
    }

    decrypted_file_content_hex = bytes_to_hex_string(plaintext_dec_buffer.data(), plaintext_dec_buffer.size());

    Serial.print(DECRYPT_FILE_RESP_MARKER_START);
    Serial.print(group_id); // Annahme: group_id wird zurückgegeben
    Serial.print(":");
    Serial.print(decrypted_file_content_hex);
    Serial.print(DATA_END_MARKER);
    Serial.println();
    Serial.printf("Dateientschlüsselungsanfrage für Gruppe '%s' erfolgreich bearbeitet.\n", group_id.c_str());
}

void setup() {
    Serial.begin(115200);
    while (!Serial && millis() < 5000) {
        // Warte auf serielle Verbindung
    }
    hsm_init();
    Serial.println("ESP32-C3 HSM Device bereit.");
}

void loop() {
    if (Serial.available()) {
        String command = Serial.readStringUntil('\n');
        command.trim(); // Remove any whitespace

        Serial.printf("Empfangen: '%s'\n", command.c_str());

        if (command.startsWith(NVS_SET_MAK_MARKER_START)) {
            handleSetMAK(command);
        } else if (command.startsWith(AUTH_TOKEN_SET_REQ_MARKER_START)) {
            handleSetAuthToken(command);
        } else if (command.startsWith(ECDH_PUBKEY_REQ_MARKER_START)) {
            handleEcdhRequest(command);
        } else if (command.startsWith(AUTH_REQ_GROUP_MARKER_START)) {
            handleAuthRequest(command);
        } else if (command.startsWith(AUTH_RESPONSE_MARKER_START)) {
            handleAuthResponse(command);
        } else if (command.startsWith(ENCRYPT_FILE_REQ_MARKER_START)) {
            handleEncryptFileRequest(command);
        } else if (command.startsWith(DECRYPT_FILE_REQ_MARKER_START)) {
            handleDecryptFileRequest(command);
        } else {
            Serial.print("UNKNOW_COMMAND");
            Serial.print(DATA_END_MARKER);
            Serial.println();
        }
    }
}