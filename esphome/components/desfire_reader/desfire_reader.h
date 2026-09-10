#pragma once
//
//  desfire_reader.h  --  ESPHome external component
//
//  Secure MIFARE DESFire EV1/EV2/EV3 reader built on ESP32 + PN532 (I2C).
//
//  Implemented here:
//    * low level PN532 transport (normal information frame, I2C)
//    * InListPassiveTarget / InDataExchange / InRelease
//    * DESFire native protocol (the status is the FIRST response byte)
//    * 3-pass mutual authentication with AES-128 (cmd 0xAA) on top of mbedtls
//    * 3-pass mutual authentication for legacy D40 DES and 2K3DES (cmd 0x0A)
//    * AES-CMAC (RFC 4493) to keep the session IV chain in sync (EV1 new
//      authentication scheme)
//    * CRC32 (JAMCRC) and CRC16 (ISO 14443-A) cryptograms for ChangeKey
//    * SelectApplication / CreateApplication / CreateStdDataFile / WriteData /
//      ReadData / ChangeKey / FormatPICC
//
//  Cards in factory state:
//    A brand new card ships with a DES PICC master key (16 zero bytes where
//    K1 == K2), so AuthenticateAES (0xAA) simply fails on it. This component
//    handles that: when no AES key is accepted it authenticates with the
//    factory DES key over the legacy D40 protocol and migrates the master key
//    to AES on its own. No external tooling is required.
//
//  A full format returns the card to its exact factory state: FormatPICC wipes
//  the applications, then the master key is changed back to the zero DES key.
//
//  The legacy path needs DES in mbedtls. Under esp-idf enable it with:
//    esp32: framework: sdkconfig_options: CONFIG_MBEDTLS_DES_C: y
//  Without DES the component still works, but only accepts cards that have
//  already been migrated to AES.
//
#include "esphome/core/component.h"
#include "esphome/core/helpers.h"
#include "esphome/core/log.h"
#include "esphome/core/hal.h"
#include "esphome/core/automation.h"
#include "esphome/components/i2c/i2c.h"
#include "esphome/components/text_sensor/text_sensor.h"

#include <mbedtls/aes.h>
#include <mbedtls/des.h>

// The legacy D40 mode needs DES, enabled in ESP-IDF through CONFIG_MBEDTLS_DES_C.
// When the build has no DES the component stays fully functional for AES cards
// and only refuses cards in factory state, with an explicit log message.
#if defined(MBEDTLS_DES_C)
#define DESFIRE_HAS_LEGACY_DES 1
#else
#define DESFIRE_HAS_LEGACY_DES 0
#endif

#include <cstring>
#include <string>
#include <vector>

namespace esphome {
namespace desfire_reader {

static const char *const TAG = "desfire_reader";

// ------------------------------------------------------------------ PN532 ---
static const uint8_t PN532_HOSTTOPN532 = 0xD4;
static const uint8_t PN532_PN532TOHOST = 0xD5;

static const uint8_t PN532_CMD_GET_FIRMWARE_VERSION = 0x02;
static const uint8_t PN532_CMD_SAM_CONFIGURATION = 0x14;
static const uint8_t PN532_CMD_RF_CONFIGURATION = 0x32;
static const uint8_t PN532_CMD_IN_DATA_EXCHANGE = 0x40;
static const uint8_t PN532_CMD_IN_LIST_PASSIVE_TARGET = 0x4A;
static const uint8_t PN532_CMD_IN_RELEASE = 0x52;

// ---------------------------------------------------------------- DESFire ---
enum DesfireCommand : uint8_t {
  DF_CMD_AUTHENTICATE_LEGACY = 0x0A,  ///< D40: DES / 2K3DES
  DF_CMD_AUTHENTICATE_AES = 0xAA,
  DF_CMD_ADDITIONAL_FRAME = 0xAF,
  DF_CMD_SELECT_APPLICATION = 0x5A,
  DF_CMD_CREATE_APPLICATION = 0xCA,
  DF_CMD_DELETE_APPLICATION = 0xDA,
  DF_CMD_CREATE_STD_DATA_FILE = 0xCD,
  DF_CMD_WRITE_DATA = 0x3D,
  DF_CMD_READ_DATA = 0xBD,
  DF_CMD_CHANGE_KEY = 0xC4,
  DF_CMD_FORMAT_PICC = 0xFC,
};

enum DesfireStatus : uint8_t {
  DF_ST_SUCCESS = 0x00,
  DF_ST_NO_CHANGES = 0x0C,
  DF_ST_OUT_OF_MEMORY = 0x0E,
  DF_ST_ILLEGAL_COMMAND = 0x1C,
  DF_ST_LENGTH_ERROR = 0x7E,
  DF_ST_PERMISSION_DENIED = 0x9D,
  DF_ST_APPLICATION_NOT_FOUND = 0xA0,
  DF_ST_AUTHENTICATION_ERROR = 0xAE,
  DF_ST_ADDITIONAL_FRAME = 0xAF,
  DF_ST_DUPLICATE_ERROR = 0xDE,
  DF_ST_FILE_NOT_FOUND = 0xF0,
  DF_ST_TRANSPORT_ERROR = 0xFB,  // local code: exchange with the PN532 or card failed
};

/// Operating modes of the state machine.
enum DesfireMode : uint8_t {
  MODE_READ = 0,    ///< Mode 0: normal authorisation (default)
  MODE_ADD = 1,     ///< Mode 1: enrol a card with an ID taken from Home Assistant
  MODE_FORMAT = 2,  ///< Mode 2: full format (FormatPICC)
};

/// Factory (transport) AES key: 16 zero bytes.
static const uint8_t DEFAULT_AES_KEY[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

/// Factory DES key of a brand new card: 16 zero bytes where K1 == K2.
/// DESFire stores a single DES key exactly like a 2K3DES key with equal halves.
static const uint8_t DEFAULT_DES_KEY[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

class DesfireReader : public PollingComponent, public i2c::I2CDevice {
 public:
  // ------------------------------------------------------------ configuration
  void set_master_key(const std::vector<uint8_t> &key) { memcpy(this->master_key_, key.data(), 16); }
  void set_app_id(const std::vector<uint8_t> &aid) { memcpy(this->app_id_, aid.data(), 3); }
  void set_key_number(uint8_t n) { this->key_number_ = n; }
  void set_file_id(uint8_t id) { this->file_id_ = id; }
  void set_file_size(uint8_t size) { this->file_size_ = size; }
  void set_mode_timeout(uint32_t ms) { this->mode_timeout_ = ms; }
  void set_harden_picc_master_key(bool v) { this->harden_picc_master_key_ = v; }
  void set_target_id_sensor(text_sensor::TextSensor *s) { this->target_id_sensor_ = s; }

  void add_on_tag_callback(std::function<void(std::string)> &&cb) { this->tag_callback_.add(std::move(cb)); }
  void add_on_status_callback(std::function<void(std::string)> &&cb) { this->status_callback_.add(std::move(cb)); }

  float get_setup_priority() const override { return setup_priority::DATA; }

  // ------------------------------------------------------------------ setup -
  void setup() override {
    ESP_LOGCONFIG(TAG, "Setting up PN532...");
    std::vector<uint8_t> resp;

    // Check that the chip answers at all.
    if (!this->pn532_command_({PN532_CMD_GET_FIRMWARE_VERSION}, resp, 500) || resp.size() < 5) {
      ESP_LOGE(TAG, "PN532 did not answer GetFirmwareVersion");
      this->mark_failed();
      return;
    }
    ESP_LOGCONFIG(TAG, "Found PN532 with firmware %u.%u", resp[2], resp[3]);

    // SAMConfiguration: normal mode, timeout 20 * 50 ms = 1 s, no IRQ pin.
    if (!this->pn532_command_({PN532_CMD_SAM_CONFIGURATION, 0x01, 0x14, 0x00}, resp, 500)) {
      ESP_LOGE(TAG, "SAMConfiguration failed");
      this->mark_failed();
      return;
    }

    // MaxRetries for InListPassiveTarget = 1, so polling does not block loop().
    this->pn532_command_({PN532_CMD_RF_CONFIGURATION, 0x05, 0xFF, 0x01, 0x01}, resp, 500);

    this->publish_status_("Ready (read mode)");
  }

  void dump_config() override {
    ESP_LOGCONFIG(TAG, "DESFire Reader:");
    ESP_LOGCONFIG(TAG, "  AID: %02X%02X%02X", this->app_id_[0], this->app_id_[1], this->app_id_[2]);
    ESP_LOGCONFIG(TAG, "  Key number: 0x%02X", this->key_number_);
    ESP_LOGCONFIG(TAG, "  File: 0x%02X (%u bytes)", this->file_id_, this->file_size_);
    ESP_LOGCONFIG(TAG, "  Mode timeout: %u ms", this->mode_timeout_);
    LOG_I2C_DEVICE(this);
    LOG_UPDATE_INTERVAL(this);
  }

  // -------------------------------------------------------------- public API -
  /// "Add card" button: switches to mode 1 for mode_timeout_ milliseconds.
  void start_add_mode() {
    if (this->target_id_sensor_ == nullptr) {
      this->publish_status_("Error: target_id is not configured");
      return;
    }
    // The ID is read once, at the moment the button is pressed, and frozen.
    std::string id = trim_string_(this->target_id_sensor_->state);
    if (id.empty()) {
      this->publish_status_("Cancelled: input_text is empty");
      return;
    }
    if (id.size() > this->file_size_) {
      this->publish_status_("Cancelled: ID longer than the file");
      return;
    }
    this->pending_id_ = id;
    this->enter_mode_(MODE_ADD);
    this->publish_status_("Write mode: present a card (" + std::to_string(this->mode_timeout_ / 1000) + " s)");
  }

  /// "Full card format" button: switches to mode 2.
  void start_format_mode() {
    this->enter_mode_(MODE_FORMAT);
    this->publish_status_("Format mode: present a card (" + std::to_string(this->mode_timeout_ / 1000) + " s)");
  }

  /// Return to mode 0 before the timeout expires.
  void cancel_mode() {
    this->enter_mode_(MODE_READ);
    this->publish_status_("Ready (read mode)");
  }

  DesfireMode get_mode() const { return this->mode_; }

  // ----------------------------------------------------------- main polling --
  void update() override {
    // Timeout of the special modes.
    if (this->mode_ != MODE_READ && (millis() - this->mode_started_) > this->mode_timeout_) {
      this->enter_mode_(MODE_READ);
      this->publish_status_("Timed out. Ready (read mode)");
    }

    std::vector<uint8_t> uid;
    if (!this->detect_card_(uid)) {
      this->card_present_ = false;
      return;
    }

    // Debounce: the same card is processed at most once every 2 seconds.
    bool same_card = (uid == this->last_uid_) && (millis() - this->last_seen_ < 2000);
    this->last_uid_ = uid;
    this->last_seen_ = millis();
    if (same_card && this->card_present_) {
      this->release_card_();
      return;
    }
    this->card_present_ = true;

    ESP_LOGD(TAG, "Card detected: %s", format_hex_pretty(uid).c_str());

    switch (this->mode_) {
      case MODE_ADD:
        this->handle_add_mode_();
        break;
      case MODE_FORMAT:
        this->handle_format_mode_();
        break;
      case MODE_READ:
      default:
        this->handle_read_mode_();
        break;
    }

    this->release_card_();
  }

 protected:
  // ========================================================================
  //  Mode 0 - authorisation (reading)
  // ========================================================================
  void handle_read_mode_() {
    std::string id;
    if (!this->read_card_id_(id)) {
      // A foreign or invalid card is simply ignored, no events are sent to HA.
      ESP_LOGD(TAG, "Invalid card, ignoring");
      return;
    }
    ESP_LOGI(TAG, "Authorised: %s", id.c_str());
    this->tag_callback_.call(id);  // -> homeassistant.tag_scanned
    this->publish_status_("Read: " + id);
  }

  /// SelectApplication -> AuthenticateAES -> ReadData -> string.
  bool read_card_id_(std::string &out) {
    std::vector<uint8_t> aid(this->app_id_, this->app_id_ + 3);
    if (!this->select_application_(aid)) {
      ESP_LOGD(TAG, "Application %02X%02X%02X not found", aid[0], aid[1], aid[2]);
      return false;
    }
    if (!this->authenticate_aes_(this->key_number_, this->master_key_)) {
      ESP_LOGW(TAG, "Authentication with key 0x%02X failed", this->key_number_);
      return false;
    }

    // ReadData: fileNo, offset (3 bytes, LSB first), length (3 bytes, LSB first)
    std::vector<uint8_t> req = {this->file_id_, 0x00, 0x00, 0x00, this->file_size_, 0x00, 0x00};
    std::vector<uint8_t> data;
    uint8_t st = this->df_command_(DF_CMD_READ_DATA, req, data);
    if (st != DF_ST_SUCCESS || data.size() < this->file_size_) {
      ESP_LOGW(TAG, "ReadData failed with 0x%02X", st);
      return false;
    }

    // Bytes to string, dropping the zero padding.
    out.clear();
    for (uint8_t i = 0; i < this->file_size_; i++) {
      if (data[i] == 0x00)
        break;
      out.push_back(static_cast<char>(data[i]));
    }
    return !out.empty();
  }

  // ========================================================================
  //  Mode 1 - card creation and write
  // ========================================================================
  void handle_add_mode_() {
    const std::string id = this->pending_id_;
    if (this->write_card_(id)) {
      ESP_LOGI(TAG, "Card written: %s", id.c_str());
      this->publish_status_("Written: " + id);
    } else {
      this->publish_status_("Card write failed");
    }
    this->enter_mode_(MODE_READ);
  }

  bool write_card_(const std::string &id) {
    const std::vector<uint8_t> picc_aid = {0x00, 0x00, 0x00};
    const std::vector<uint8_t> app_aid(this->app_id_, this->app_id_ + 3);
    std::vector<uint8_t> resp;

    // --- 1. PICC level: AES zeros -> AES secret -> factory DES ---------------
    // A failed authentication ends the session, so the application is selected
    // again before every attempt.
    if (!this->select_application_(picc_aid))
      return this->fail_("SelectApplication(000000)");

    bool picc_was_default = true;
    if (!this->authenticate_aes_(0x00, DEFAULT_AES_KEY)) {
      this->select_application_(picc_aid);
      if (this->authenticate_aes_(0x00, this->master_key_)) {
        picc_was_default = false;
      } else {
        // Card in factory state: the master key is a DES key. Authenticate over
        // the legacy protocol and migrate the card to AES right away.
        this->select_application_(picc_aid);
        if (!this->authenticate_legacy_des_(0x00, DEFAULT_DES_KEY))
          return this->fail_("No PICC master key matched (AES zeros, AES secret, DES zeros)");

        const uint8_t *target = this->harden_picc_master_key_ ? this->master_key_ : DEFAULT_AES_KEY;
        if (!this->change_picc_key_legacy_to_aes_(target))
          return this->fail_("Migrating the PICC master key from DES to AES");
        ESP_LOGI(TAG, "Card migrated from the factory DES key to AES");

        this->select_application_(picc_aid);
        if (!this->authenticate_aes_(0x00, target))
          return this->fail_("Auth after the migration to AES");

        // If the key is already the secret one, step 8 is not needed.
        picc_was_default = !this->harden_picc_master_key_;
      }
    }
    ESP_LOGD(TAG, "PICC master key: %s", picc_was_default ? "factory" : "ours");

    // --- 2. CreateApplication -----------------------------------------------
    // keySettings 0xEF:
    //   bits 7..4 = 0xE -> a key is changed by authenticating with that very key
    //   bit 3 = 1 -> configuration is changeable
    //   bit 2 = 1 -> Create/DeleteFile without app master key authentication
    //   bit 1 = 1 -> free directory listing
    //   bit 0 = 1 -> app master key is changeable
    // numKeys: 0x80 marks AES, the low bits carry the number of keys.
    const uint8_t num_keys = 0x80 | uint8_t(this->key_number_ + 1);
    const std::vector<uint8_t> create = {app_aid[0], app_aid[1], app_aid[2], 0xEF, num_keys};
    uint8_t st = this->df_command_(DF_CMD_CREATE_APPLICATION, create, resp);

    if (st == DF_ST_DUPLICATE_ERROR) {
      // The card was enrolled before: drop the old application and start over.
      ESP_LOGW(TAG, "Application already exists, recreating it");
      if (this->df_command_(DF_CMD_DELETE_APPLICATION, app_aid, resp) != DF_ST_SUCCESS)
        return this->fail_("DeleteApplication");
      st = this->df_command_(DF_CMD_CREATE_APPLICATION, create, resp);
    }
    if (st != DF_ST_SUCCESS)
      return this->fail_("CreateApplication");

    // --- 3. Enter the application, authenticate with the factory key ---------
    if (!this->select_application_(app_aid))
      return this->fail_("SelectApplication(app)");
    if (!this->authenticate_aes_(this->key_number_, DEFAULT_AES_KEY))
      return this->fail_("Auth with the factory application key");

    // --- 4. CreateStdDataFile ------------------------------------------------
    // fileNo, commSettings (0x00 = plain), accessRights (2 bytes, LSB first),
    // size (3 bytes, LSB first).
    // accessRights: read / write / read&write use our key, changeAccess is key 0.
    const uint16_t rights = (uint16_t(this->key_number_) << 12) | (uint16_t(this->key_number_) << 8) |
                            (uint16_t(this->key_number_) << 4) | 0x0;
    const std::vector<uint8_t> file = {this->file_id_,   0x00, uint8_t(rights & 0xFF), uint8_t(rights >> 8),
                                       this->file_size_, 0x00, 0x00};
    st = this->df_command_(DF_CMD_CREATE_STD_DATA_FILE, file, resp);
    if (st != DF_ST_SUCCESS && st != DF_ST_DUPLICATE_ERROR)
      return this->fail_("CreateStdDataFile");

    // --- 5. WriteData: the ID, zero padded up to file_size_ ------------------
    std::vector<uint8_t> payload = {this->file_id_, 0x00, 0x00, 0x00, this->file_size_, 0x00, 0x00};
    for (uint8_t i = 0; i < this->file_size_; i++)
      payload.push_back(i < id.size() ? uint8_t(id[i]) : 0x00);
    if (this->df_command_(DF_CMD_WRITE_DATA, payload, resp) != DF_ST_SUCCESS)
      return this->fail_("WriteData");

    // --- 6. ChangeKey: application key, zeros -> secret from secrets.yaml ----
    // We are authenticated with that very key, so the "same key" cryptogram
    // format applies.
    if (!this->change_key_aes_(this->key_number_, this->master_key_, nullptr, false))
      return this->fail_("ChangeKey(application key)");

    // --- 7. Move the app master key (0x00) to the secret as well ------------
    if (!this->authenticate_aes_(0x00, DEFAULT_AES_KEY))
      return this->fail_("Auth app master key");
    if (!this->change_key_aes_(0x00, this->master_key_, nullptr, false))
      return this->fail_("ChangeKey(app master)");

    // --- 8. Optionally move the PICC master key from zeros to the secret ----
    if (this->harden_picc_master_key_ && picc_was_default) {
      if (!this->select_application_(picc_aid))
        return this->fail_("SelectApplication(000000) #2");
      if (!this->authenticate_aes_(0x00, DEFAULT_AES_KEY))
        return this->fail_("Auth PICC master #2");
      if (!this->change_key_aes_(0x00, this->master_key_, nullptr, true))
        return this->fail_("ChangeKey(PICC master)");
      ESP_LOGI(TAG, "PICC master key moved to the key from secrets.yaml");
    }

    return true;
  }

  // ========================================================================
  //  Mode 2 - full format (factory reset)
  // ========================================================================
  void handle_format_mode_() {
    if (this->format_card_()) {
      ESP_LOGI(TAG, "Card formatted");
      this->publish_status_("Card fully wiped");
    } else {
      this->publish_status_("Format failed");
    }
    this->enter_mode_(MODE_READ);
  }

  bool format_card_() {
    const std::vector<uint8_t> picc_aid = {0x00, 0x00, 0x00};
    std::vector<uint8_t> resp;

    if (!this->select_application_(picc_aid))
      return this->fail_("SelectApplication(000000)");

    // Our key first (the card is already ours), then AES zeros, then factory DES.
    bool legacy = false;
    if (!this->authenticate_aes_(0x00, this->master_key_)) {
      this->select_application_(picc_aid);
      if (!this->authenticate_aes_(0x00, DEFAULT_AES_KEY)) {
        this->select_application_(picc_aid);
        if (!this->authenticate_legacy_des_(0x00, DEFAULT_DES_KEY))
          return this->fail_("No PICC master key matched");
        legacy = true;
      }
    }

    // FormatPICC erases ALL applications and files but leaves the master key.
    // A legacy session carries no CMAC, which df_command_ takes into account.
    std::vector<uint8_t> empty;
    if (this->df_command_(DF_CMD_FORMAT_PICC, empty, resp) != DF_ST_SUCCESS)
      return this->fail_("FormatPICC");

    if (legacy) {
      // The key is the zero DES one already, the card is in factory state.
      ESP_LOGI(TAG, "Card already had the factory DES key");
      return true;
    }

    // Restore the master key to its exact factory shape: DES type, 16 zero
    // bytes (K1 == K2). That is how the card leaves the factory.
    if (!this->change_key_(0x00, DEFAULT_DES_KEY, 16, false, nullptr, true))
      return this->fail_("ChangeKey(PICC master -> factory DES)");
    ESP_LOGI(TAG, "PICC master key reset to the factory DES key");
    return true;
  }

  // ========================================================================
  //  DESFire: high level commands
  // ========================================================================
  bool select_application_(const std::vector<uint8_t> &aid) {
    // SelectApplication always resets the session. The flags are cleared BEFORE
    // the exchange so that no CMAC is computed for a command the card accepts
    // in plain mode.
    this->authenticated_ = false;
    this->legacy_session_ = false;
    std::vector<uint8_t> resp;
    return this->df_transceive_(DF_CMD_SELECT_APPLICATION, aid, resp) == DF_ST_SUCCESS;
  }

  /// 3-pass mutual authentication, AES-128 (EV1 new authentication scheme).
  bool authenticate_aes_(uint8_t key_no, const uint8_t key[16]) {
    this->authenticated_ = false;
    this->legacy_session_ = false;

    // --- Step 1: PCD -> PICC: 0xAA || keyNo;  PICC -> PCD: E(Kx, RndB) ------
    std::vector<uint8_t> resp;
    uint8_t st = this->df_transceive_(DF_CMD_AUTHENTICATE_AES, {key_no}, resp);
    if (st != DF_ST_ADDITIONAL_FRAME || resp.size() != 16) {
      ESP_LOGD(TAG, "Auth step 1 failed (0x%02X)", st);
      return false;
    }

    uint8_t iv[16] = {0};
    uint8_t rnd_b[16];
    // CBC decrypt with a zero IV; afterwards iv == E(RndB) through CBC chaining.
    this->aes_cbc_decrypt_(key, iv, resp.data(), rnd_b, 16);

    // --- Step 2: PCD -> PICC: E(Kx, RndA || rotl(RndB)) ---------------------
    uint8_t rnd_a[16];
    if (!random_bytes(rnd_a, 16)) {
      ESP_LOGE(TAG, "No source of random numbers");
      return false;
    }
    uint8_t token[32];
    memcpy(token, rnd_a, 16);
    rotate_left_(rnd_b, token + 16);

    uint8_t enc_token[32];
    this->aes_cbc_encrypt_(key, iv, token, enc_token, 32);  // iv -> last block

    const std::vector<uint8_t> frame(enc_token, enc_token + 32);
    st = this->df_transceive_(DF_CMD_ADDITIONAL_FRAME, frame, resp);
    if (st != DF_ST_SUCCESS || resp.size() != 16) {
      ESP_LOGD(TAG, "Auth step 2 failed (0x%02X)", st);
      return false;
    }

    // --- Step 3: verify that the card returned rotl(RndA) -------------------
    uint8_t rnd_a_rot[16];
    this->aes_cbc_decrypt_(key, iv, resp.data(), rnd_a_rot, 16);
    uint8_t expected[16];
    rotate_left_(rnd_a, expected);
    if (memcmp(expected, rnd_a_rot, 16) != 0) {
      ESP_LOGW(TAG, "Card failed the mutual authentication");
      return false;
    }

    // --- Session key: RndA[0..3] RndB[0..3] RndA[12..15] RndB[12..15] -------
    memcpy(this->session_key_ + 0, rnd_a + 0, 4);
    memcpy(this->session_key_ + 4, rnd_b + 0, 4);
    memcpy(this->session_key_ + 8, rnd_a + 12, 4);
    memcpy(this->session_key_ + 12, rnd_b + 12, 4);

    memset(this->iv_, 0, 16);
    this->generate_cmac_subkeys_();
    this->authenticated_ = true;
    this->auth_key_no_ = key_no;
    ESP_LOGD(TAG, "Authentication with key 0x%02X succeeded", key_no);
    return true;
  }

  ///
  /// Legacy D40 authentication (cmd 0x0A). This is what opens a card in factory
  /// state, whose master key is of DES type.
  ///
  /// key is 16 bytes (K1 || K2). For a single DES key both halves are equal.
  ///
  bool authenticate_legacy_des_(uint8_t key_no, const uint8_t key[16]) {
    this->authenticated_ = false;
    this->legacy_session_ = false;

#if !DESFIRE_HAS_LEGACY_DES
    (void) key_no;
    (void) key;
    ESP_LOGE(TAG, "Built without MBEDTLS_DES_C: cards in factory state are not supported. "
                  "Add sdkconfig_options: CONFIG_MBEDTLS_DES_C: y");
    return false;
#else

    // --- Step 1: PCD -> PICC: 0x0A || keyNo;  PICC -> PCD: E(Kx, RndB) ------
    std::vector<uint8_t> resp;
    uint8_t st = this->df_transceive_(DF_CMD_AUTHENTICATE_LEGACY, {key_no}, resp);
    if (st != DF_ST_ADDITIONAL_FRAME || resp.size() != 8) {
      ESP_LOGD(TAG, "Legacy auth step 1 failed (0x%02X)", st);
      return false;
    }

    uint8_t iv[8] = {0};
    uint8_t rnd_b[8];
    this->des_receive_(key, iv, resp.data(), rnd_b, 8);

    // --- Step 2: PCD -> PICC: dk(RndA) || dk(rotl(RndB) XOR dk(RndA)) -------
    uint8_t rnd_a[8];
    if (!random_bytes(rnd_a, 8)) {
      ESP_LOGE(TAG, "No source of random numbers");
      return false;
    }
    uint8_t token[16];
    memcpy(token, rnd_a, 8);
    rotate_left8_(rnd_b, token + 8);

    uint8_t enc[16];
    memset(iv, 0, 8);  // D40 zeroes the IV before every operation
    this->des_send_(key, iv, token, enc, 16);

    st = this->df_transceive_(DF_CMD_ADDITIONAL_FRAME, std::vector<uint8_t>(enc, enc + 16), resp);
    if (st != DF_ST_SUCCESS || resp.size() != 8) {
      ESP_LOGD(TAG, "Legacy auth step 2 failed (0x%02X)", st);
      return false;
    }

    // --- Step 3: the card has to return rotl(RndA) --------------------------
    uint8_t rnd_a_rot[8];
    memset(iv, 0, 8);
    this->des_receive_(key, iv, resp.data(), rnd_a_rot, 8);
    uint8_t expected[8];
    rotate_left8_(rnd_a, expected);
    if (memcmp(expected, rnd_a_rot, 8) != 0) {
      ESP_LOGW(TAG, "Card failed the legacy authentication");
      return false;
    }

    // --- Session key --------------------------------------------------------
    // RndA[0..3] || RndB[0..3], then RndA[4..7] || RndB[4..7] for a real 2K3DES
    // key. For a DES key (K1 == K2) the card simply duplicates the first 8 bytes.
    memcpy(this->session_des_key_ + 0, rnd_a, 4);
    memcpy(this->session_des_key_ + 4, rnd_b, 4);
    if (memcmp(key, key + 8, 8) == 0) {
      memcpy(this->session_des_key_ + 8, this->session_des_key_, 8);
    } else {
      memcpy(this->session_des_key_ + 8, rnd_a + 4, 4);
      memcpy(this->session_des_key_ + 12, rnd_b + 4, 4);
    }

    this->legacy_session_ = true;
    this->auth_key_no_ = key_no;
    ESP_LOGD(TAG, "Legacy authentication with key 0x%02X succeeded", key_no);
    return true;
#endif
  }

  ///
  /// ChangeKey inside a legacy session: migrates the PICC master key from DES
  /// to AES. It runs exactly once per new card.
  ///
  /// Differences from an AES session:
  ///   * the checksum is CRC16 (ISO 14443-A), not CRC32;
  ///   * the CRC covers ONLY the key data, without the command and key number;
  ///   * padding goes to a multiple of 8 bytes and the DES session key encrypts.
  ///
  bool change_picc_key_legacy_to_aes_(const uint8_t new_key[16]) {
    if (!this->legacy_session_)
      return false;

    const uint8_t wire_key_no = 0x80;  // AES marker plus key number 0

    std::vector<uint8_t> plain(new_key, new_key + 16);
    plain.push_back(0x00);  // AES key version

    uint8_t crc[2];
    crc16_a_(plain.data(), plain.size(), crc);
    plain.push_back(crc[0]);
    plain.push_back(crc[1]);

    while (plain.size() % 8 != 0)
      plain.push_back(0x00);

    std::vector<uint8_t> enc(plain.size());
    uint8_t iv[8] = {0};
    this->des_send_(this->session_des_key_, iv, plain.data(), enc.data(), plain.size());

    std::vector<uint8_t> payload;
    payload.push_back(wire_key_no);
    payload.insert(payload.end(), enc.begin(), enc.end());

    std::vector<uint8_t> resp;
    const uint8_t st = this->df_transceive_(DF_CMD_CHANGE_KEY, payload, resp);
    this->legacy_session_ = false;  // changing your own key ends the session
    return st == DF_ST_SUCCESS;
  }

  /// Shorthand for the common case where the new key is AES-128.
  bool change_key_aes_(uint8_t key_no, const uint8_t new_key[16], const uint8_t *old_key, bool picc_level) {
    return this->change_key_(key_no, new_key, 16, true, old_key, picc_level);
  }

  /// ChangeKey (0xC4) inside an authenticated AES session.
  ///   old_key == nullptr   -> change the key we are authenticated with ("same key")
  ///   new_key_is_aes       -> type of the new key; drives the marker in the key
  ///                           number and the presence of a version byte
  ///   picc_level == true   -> PICC master key (the key number carries the type
  ///                           marker: 0x80 for AES, 0x00 for DES/2K3DES)
  /// A DES key is sent as 16 bytes with equal halves (K1 == K2).
  bool change_key_(uint8_t key_no, const uint8_t *new_key, uint8_t new_key_len, bool new_key_is_aes,
                   const uint8_t *old_key, bool picc_level) {
    if (!this->authenticated_)
      return false;

    const uint8_t key_version = 0x00;
    const uint8_t type_bits = new_key_is_aes ? 0x80 : 0x00;
    const uint8_t wire_key_no = picc_level ? uint8_t(type_bits | key_no) : key_no;
    const bool same_key = (old_key == nullptr);

    std::vector<uint8_t> plain;  // the part that gets encrypted
    if (same_key) {
      plain.insert(plain.end(), new_key, new_key + new_key_len);
    } else {
      for (uint8_t i = 0; i < new_key_len; i++)
        plain.push_back(new_key[i] ^ old_key[i]);
    }
    if (new_key_is_aes)
      plain.push_back(key_version);  // the version byte exists for AES keys only

    // The first CRC32 covers cmd || keyNo || the plain data.
    std::vector<uint8_t> crc_src;
    crc_src.push_back(DF_CMD_CHANGE_KEY);
    crc_src.push_back(wire_key_no);
    crc_src.insert(crc_src.end(), plain.begin(), plain.end());
    append_le32_(plain, crc32_(crc_src.data(), crc_src.size()));

    // The second CRC32, only when the keys differ, covers the new key in clear.
    if (!same_key)
      append_le32_(plain, crc32_(new_key, new_key_len));

    // Zero padding to a multiple of 16, then encryption with the session key
    // (CBC send mode).
    while (plain.size() % 16 != 0)
      plain.push_back(0x00);
    std::vector<uint8_t> enc(plain.size());
    this->aes_cbc_encrypt_(this->session_key_, this->iv_, plain.data(), enc.data(), plain.size());

    std::vector<uint8_t> payload;
    payload.push_back(wire_key_no);
    payload.insert(payload.end(), enc.begin(), enc.end());

    // The CMAC in the response is computed on the new key context already, so it
    // is not verified: the session ends either way.
    std::vector<uint8_t> resp;
    const uint8_t st = this->df_command_(DF_CMD_CHANGE_KEY, payload, resp, false);

    if (same_key || key_no == this->auth_key_no_)
      this->authenticated_ = false;  // changing your own key breaks the session

    return st == DF_ST_SUCCESS;
  }

  // ========================================================================
  //  DESFire: secure messaging layer (CMAC and IV chain)
  // ========================================================================
  ///
  /// Wrapper around df_transceive_ for plain mode inside an authenticated
  /// session:
  ///   * the command CMAC is computed but NOT sent (that is what EV1 requires in
  ///     plain mode), yet it is needed to keep the session IV in sync with the card;
  ///   * the card appends 8 CMAC bytes to the response, which are verified and cut.
  ///
  uint8_t df_command_(uint8_t cmd, const std::vector<uint8_t> &data, std::vector<uint8_t> &out,
                      bool verify_response_cmac = true) {
    if (this->authenticated_) {
      std::vector<uint8_t> buf;
      buf.push_back(cmd);
      buf.insert(buf.end(), data.begin(), data.end());
      uint8_t mac[16];
      this->cmac_(buf.data(), buf.size(), mac);  // updates this->iv_
    }

    const uint8_t st = this->df_transceive_(cmd, data, out);

    if (this->authenticated_ && st == DF_ST_SUCCESS && out.size() >= 8) {
      std::vector<uint8_t> body(out.begin(), out.end() - 8);
      body.push_back(st);  // the CMAC covers "data || status"
      uint8_t mac[16];
      this->cmac_(body.data(), body.size(), mac);
      if (verify_response_cmac && memcmp(mac, out.data() + out.size() - 8, 8) != 0)
        ESP_LOGW(TAG, "Response CMAC mismatch (cmd 0x%02X)", cmd);
      out.resize(out.size() - 8);
    } else if (st != DF_ST_SUCCESS && st != DF_ST_ADDITIONAL_FRAME) {
      this->authenticated_ = false;  // any error is treated as a lost session
    }
    return st;
  }

  /// Raw native exchange: [cmd][data...] -> [status][data...]
  uint8_t df_transceive_(uint8_t cmd, const std::vector<uint8_t> &data, std::vector<uint8_t> &out) {
    std::vector<uint8_t> tx;
    tx.push_back(cmd);
    tx.insert(tx.end(), data.begin(), data.end());

    std::vector<uint8_t> rx;
    if (!this->pn532_in_data_exchange_(tx, rx) || rx.empty()) {
      out.clear();
      return DF_ST_TRANSPORT_ERROR;
    }
    out.assign(rx.begin() + 1, rx.end());
    return rx[0];
  }

  // ========================================================================
  //  Cryptography (mbedtls)
  // ========================================================================
  void aes_cbc_encrypt_(const uint8_t key[16], uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, len, iv, in, out);
    mbedtls_aes_free(&ctx);
  }

  void aes_cbc_decrypt_(const uint8_t key[16], uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_dec(&ctx, key, 128);
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, len, iv, in, out);
    mbedtls_aes_free(&ctx);
  }

  void aes_ecb_encrypt_block_(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, in, out);
    mbedtls_aes_free(&ctx);
  }

  /// CMAC subkeys (RFC 4493) for the current session key.
  void generate_cmac_subkeys_() {
    uint8_t zero[16] = {0};
    uint8_t l[16];
    this->aes_ecb_encrypt_block_(this->session_key_, zero, l);
    shift_left_(l, this->sk1_);
    if (l[0] & 0x80)
      this->sk1_[15] ^= 0x87;
    shift_left_(this->sk1_, this->sk2_);
    if (this->sk1_[0] & 0x80)
      this->sk2_[15] ^= 0x87;
  }

  /// AES-CMAC over data. Side effect: this->iv_ is updated (the session chain).
  void cmac_(const uint8_t *data, size_t len, uint8_t out[16]) {
    size_t blocks = (len + 15) / 16;
    if (blocks == 0)
      blocks = 1;
    std::vector<uint8_t> buf(blocks * 16, 0);
    if (len > 0)
      memcpy(buf.data(), data, len);

    const bool complete = (len != 0) && (len % 16 == 0);
    if (!complete)
      buf[len] = 0x80;  // the 10* padding

    const uint8_t *sk = complete ? this->sk1_ : this->sk2_;
    for (uint8_t i = 0; i < 16; i++)
      buf[buf.size() - 16 + i] ^= sk[i];

    std::vector<uint8_t> enc(buf.size());
    this->aes_cbc_encrypt_(this->session_key_, this->iv_, buf.data(), enc.data(), buf.size());
    memcpy(out, enc.data() + enc.size() - 16, 16);
    // this->iv_ already equals the last ciphertext block, which is the CMAC.
  }

  /// CRC32 in the DESFire flavour: reflected 0xEDB88320, init 0xFFFFFFFF, no final XOR.
  static uint32_t crc32_(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
      crc ^= data[i];
      for (uint8_t b = 0; b < 8; b++)
        crc = (crc >> 1) ^ (0xEDB88320u & (~(crc & 1u) + 1u));
    }
    return crc;
  }

  static void append_le32_(std::vector<uint8_t> &v, uint32_t x) {
    v.push_back(uint8_t(x & 0xFF));
    v.push_back(uint8_t((x >> 8) & 0xFF));
    v.push_back(uint8_t((x >> 16) & 0xFF));
    v.push_back(uint8_t((x >> 24) & 0xFF));
  }

  /// Rotate 16 bytes left by one byte (RndB -> RndB').
  static void rotate_left_(const uint8_t in[16], uint8_t out[16]) {
    memcpy(out, in + 1, 15);
    out[15] = in[0];
  }

  /// Shift a 128 bit number left by one bit (for the CMAC subkeys).
  static void shift_left_(const uint8_t *in, uint8_t *out) {
    uint8_t overflow = 0;
    for (int i = 15; i >= 0; i--) {
      out[i] = uint8_t(in[i] << 1) | overflow;
      overflow = (in[i] & 0x80) ? 1 : 0;
    }
  }

  // ========================================================================
  //  Cryptography of the legacy D40 mode (DES / 2K3DES)
  // ========================================================================
  ///
  /// The defining quirk of D40: the reader NEVER uses the encryption operation.
  /// The card enciphers with ek(), while the reader both enciphers and
  /// deciphers with dk(). That is why there is a single primitive here.
  ///
  /// The key is always passed as 16 bytes (K1 || K2). With equal halves 2K3DES
  /// degenerates into single DES, which is exactly how the factory key is stored.
  ///
  void des_decrypt_block_(const uint8_t key[16], const uint8_t in[8], uint8_t out[8]) {
#if DESFIRE_HAS_LEGACY_DES
    mbedtls_des3_context ctx;
    mbedtls_des3_init(&ctx);
    mbedtls_des3_set2key_dec(&ctx, key);
    mbedtls_des3_crypt_ecb(&ctx, in, out);
    mbedtls_des3_free(&ctx);
#else
    (void) key;
    (void) in;
    memset(out, 0, 8);
#endif
  }

  /// Sending data to the card:  C[i] = dk(P[i] XOR C[i-1]),  C[-1] = IV.
  void des_send_(const uint8_t key[16], uint8_t iv[8], const uint8_t *in, uint8_t *out, size_t len) {
    for (size_t off = 0; off < len; off += 8) {
      uint8_t block[8];
      for (uint8_t i = 0; i < 8; i++)
        block[i] = uint8_t(in[off + i] ^ iv[i]);
      this->des_decrypt_block_(key, block, out + off);
      memcpy(iv, out + off, 8);
    }
  }

  /// Receiving data from the card:  P[i] = dk(C[i]) XOR C[i-1],  C[-1] = IV.
  void des_receive_(const uint8_t key[16], uint8_t iv[8], const uint8_t *in, uint8_t *out, size_t len) {
    for (size_t off = 0; off < len; off += 8) {
      uint8_t decrypted[8];
      this->des_decrypt_block_(key, in + off, decrypted);
      for (uint8_t i = 0; i < 8; i++)
        out[off + i] = uint8_t(decrypted[i] ^ iv[i]);
      memcpy(iv, in + off, 8);
    }
  }

  /// Rotate 8 bytes left by one byte (RndB -> RndB').
  static void rotate_left8_(const uint8_t in[8], uint8_t out[8]) {
    memcpy(out, in + 1, 7);
    out[7] = in[0];
  }

  /// CRC16 per ISO 14443-A: polynomial 0x8408, initial value 0x6363, the result
  /// is appended least significant byte first.
  static void crc16_a_(const uint8_t *data, size_t len, uint8_t out[2]) {
    uint16_t crc = 0x6363;
    for (size_t i = 0; i < len; i++) {
      uint8_t b = uint8_t(data[i] ^ uint8_t(crc & 0x00FF));
      b = uint8_t(b ^ uint8_t(b << 4));
      crc = uint16_t((crc >> 8) ^ (uint16_t(b) << 8) ^ (uint16_t(b) << 3) ^ (uint16_t(b) >> 4));
    }
    out[0] = uint8_t(crc & 0xFF);
    out[1] = uint8_t((crc >> 8) & 0xFF);
  }

  // ========================================================================
  //  PN532: command layer
  // ========================================================================
  /// InListPassiveTarget: looks for a single 106 kbps type A card.
  bool detect_card_(std::vector<uint8_t> &uid) {
    std::vector<uint8_t> resp;
    if (!this->pn532_command_({PN532_CMD_IN_LIST_PASSIVE_TARGET, 0x01, 0x00}, resp, 100))
      return false;
    // Response: 0x4B, NbTg, Tg, SENS_RES(2), SEL_RES, NFCIDLength, NFCID...
    if (resp.size() < 8 || resp[0] != 0x4B || resp[1] < 1)
      return false;

    const uint8_t sel_res = resp[5];
    if ((sel_res & 0x20) == 0) {
      ESP_LOGD(TAG, "Card does not support ISO14443-4 (SAK 0x%02X)", sel_res);
      return false;
    }
    const uint8_t id_len = resp[6];
    if (resp.size() < size_t(7 + id_len))
      return false;
    uid.assign(resp.begin() + 7, resp.begin() + 7 + id_len);
    return true;
  }

  /// InDataExchange: the PN532 runs the ISO-DEP layer, we send native APDUs.
  bool pn532_in_data_exchange_(const std::vector<uint8_t> &tx, std::vector<uint8_t> &rx) {
    std::vector<uint8_t> cmd = {PN532_CMD_IN_DATA_EXCHANGE, 0x01};
    cmd.insert(cmd.end(), tx.begin(), tx.end());

    std::vector<uint8_t> resp;
    if (!this->pn532_command_(cmd, resp, 1000) || resp.size() < 2 || resp[0] != 0x41)
      return false;
    if ((resp[1] & 0x3F) != 0x00) {
      ESP_LOGW(TAG, "InDataExchange status 0x%02X", resp[1]);
      return false;
    }
    rx.assign(resp.begin() + 2, resp.end());
    return true;
  }

  /// InRelease: drop the target so the next cycle starts from a clean activation.
  void release_card_() {
    std::vector<uint8_t> resp;
    this->pn532_command_({PN532_CMD_IN_RELEASE, 0x00}, resp, 100);
    this->authenticated_ = false;
    this->legacy_session_ = false;
  }

  // ========================================================================
  //  PN532: I2C transport (normal information frame)
  // ========================================================================
  /// Sends a command and reads the response. data[0] is the PN532 command code.
  bool pn532_command_(const std::vector<uint8_t> &data, std::vector<uint8_t> &resp, uint32_t timeout_ms) {
    if (!this->pn532_write_frame_(data))
      return false;
    if (!this->pn532_read_ack_())
      return false;
    return this->pn532_read_frame_(resp, timeout_ms);
  }

  bool pn532_write_frame_(const std::vector<uint8_t> &data) {
    std::vector<uint8_t> frame;
    frame.push_back(0x00);  // preamble
    frame.push_back(0x00);  // start code 1
    frame.push_back(0xFF);  // start code 2

    const uint8_t len = uint8_t(data.size() + 1);  // TFI + PD
    frame.push_back(len);
    frame.push_back(uint8_t(~len + 1));  // LCS
    frame.push_back(PN532_HOSTTOPN532);

    uint8_t sum = PN532_HOSTTOPN532;
    for (uint8_t b : data) {
      frame.push_back(b);
      sum += b;
    }
    frame.push_back(uint8_t(~sum + 1));  // DCS
    frame.push_back(0x00);               // postamble

    return this->write(frame.data(), uint8_t(frame.size())) == i2c::ERROR_OK;
  }

  /// Over I2C the PN532 returns a ready byte (bit0 = 1) ahead of every frame.
  bool pn532_wait_ready_(uint32_t timeout_ms) {
    const uint32_t start = millis();
    uint8_t status = 0;
    while (millis() - start < timeout_ms) {
      if (this->read(&status, 1) == i2c::ERROR_OK && (status & 0x01))
        return true;
      delay(1);
    }
    return false;
  }

  bool pn532_read_ack_() {
    if (!this->pn532_wait_ready_(50)) {
      ESP_LOGW(TAG, "No ACK from the PN532");
      return false;
    }
    static const uint8_t ACK[6] = {0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00};
    uint8_t buf[7] = {0};
    if (this->read(buf, sizeof(buf)) != i2c::ERROR_OK)
      return false;
    return memcmp(buf + 1, ACK, sizeof(ACK)) == 0;
  }

  /// Reads a response frame. Returns the PD without the TFI, so it starts with
  /// the response code.
  bool pn532_read_frame_(std::vector<uint8_t> &out, uint32_t timeout_ms) {
    if (!this->pn532_wait_ready_(timeout_ms)) {
      ESP_LOGW(TAG, "Timed out waiting for the PN532 response");
      return false;
    }

    // A single read transaction: ready byte + header + data + DCS and postamble.
    // 73 bytes cover every frame this component uses, with room to spare.
    uint8_t buf[73] = {0};
    if (this->read(buf, sizeof(buf)) != i2c::ERROR_OK)
      return false;

    if (buf[1] != 0x00 || buf[2] != 0x00 || buf[3] != 0xFF) {
      ESP_LOGW(TAG, "Bad PN532 frame preamble");
      return false;
    }
    const uint8_t len = buf[4];
    const uint8_t lcs = buf[5];
    if (uint8_t(len + lcs) != 0x00 || len < 2) {
      ESP_LOGW(TAG, "Bad PN532 frame length");
      return false;
    }
    if (buf[6] != PN532_PN532TOHOST) {
      ESP_LOGW(TAG, "Bad TFI 0x%02X", buf[6]);
      return false;
    }
    if (size_t(6 + len + 1) > sizeof(buf)) {
      ESP_LOGW(TAG, "PN532 frame too long (%u bytes)", len);
      return false;
    }

    // Checksum: TFI + PD together with the DCS add up to 0 modulo 256.
    uint8_t sum = 0;
    for (uint8_t i = 0; i < len; i++)
      sum += buf[6 + i];
    if (uint8_t(sum + buf[6 + len]) != 0x00) {
      ESP_LOGW(TAG, "PN532 frame DCS error");
      return false;
    }

    out.assign(buf + 7, buf + 7 + (len - 1));
    return true;
  }

  // ========================================================================
  //  Helpers
  // ========================================================================
  void enter_mode_(DesfireMode mode) {
    this->mode_ = mode;
    this->mode_started_ = millis();
    this->last_uid_.clear();
    this->card_present_ = false;
  }

  void publish_status_(const std::string &text) {
    ESP_LOGD(TAG, "Status: %s", text.c_str());
    this->status_callback_.call(text);
  }

  bool fail_(const char *step) {
    ESP_LOGE(TAG, "Step failed: %s", step);
    return false;
  }

  static std::string trim_string_(const std::string &in) {
    size_t b = in.find_first_not_of(" \t\r\n");
    if (b == std::string::npos)
      return "";
    size_t e = in.find_last_not_of(" \t\r\n");
    return in.substr(b, e - b + 1);
  }

  // ------------------------------------------------------------- members -----
  uint8_t master_key_[16] = {0};   ///< AES-128 from secrets.yaml
  uint8_t app_id_[3] = {0xA1, 0xB2, 0xC3};
  uint8_t key_number_ = 0x01;
  uint8_t file_id_ = 0x01;
  uint8_t file_size_ = 16;
  uint32_t mode_timeout_ = 30000;
  bool harden_picc_master_key_ = true;

  text_sensor::TextSensor *target_id_sensor_{nullptr};
  std::string pending_id_;

  DesfireMode mode_{MODE_READ};
  uint32_t mode_started_{0};
  std::vector<uint8_t> last_uid_;
  uint32_t last_seen_{0};
  bool card_present_{false};

  // State of the cryptographic session.
  bool authenticated_{false};      ///< an AES session is active (with CMAC)
  bool legacy_session_{false};     ///< a D40 session is active (DES, no CMAC)
  uint8_t auth_key_no_{0};
  uint8_t session_des_key_[16] = {0};
  uint8_t session_key_[16] = {0};
  uint8_t iv_[16] = {0};
  uint8_t sk1_[16] = {0};
  uint8_t sk2_[16] = {0};

  CallbackManager<void(std::string)> tag_callback_;
  CallbackManager<void(std::string)> status_callback_;
};

// ------------------------------------------------------------- triggers -----
class TagTrigger : public Trigger<std::string> {
 public:
  explicit TagTrigger(DesfireReader *parent) {
    parent->add_on_tag_callback([this](const std::string &x) { this->trigger(x); });
  }
};

class StatusTrigger : public Trigger<std::string> {
 public:
  explicit StatusTrigger(DesfireReader *parent) {
    parent->add_on_status_callback([this](const std::string &x) { this->trigger(x); });
  }
};

}  // namespace desfire_reader
}  // namespace esphome
