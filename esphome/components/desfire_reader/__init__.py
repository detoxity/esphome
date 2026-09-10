"""ESPHome external component: secure MIFARE DESFire reader (ESP32 + PN532)."""

import esphome.codegen as cg
import esphome.config_validation as cv
from esphome import automation
from esphome.components import i2c, text_sensor
from esphome.const import CONF_ID, CONF_TRIGGER_ID

CODEOWNERS = ["@detoxity"]
DEPENDENCIES = ["i2c"]
AUTO_LOAD = ["text_sensor"]
MULTI_CONF = True

CONF_MASTER_KEY = "master_key"
CONF_APP_ID = "app_id"
CONF_KEY_NUMBER = "key_number"
CONF_FILE_ID = "file_id"
CONF_FILE_SIZE = "file_size"
CONF_TARGET_ID = "target_id"
CONF_MODE_TIMEOUT = "mode_timeout"
CONF_HARDEN_PICC_MASTER_KEY = "harden_picc_master_key"
CONF_ON_TAG = "on_tag"
CONF_ON_STATUS = "on_status"

desfire_ns = cg.esphome_ns.namespace("desfire_reader")
DesfireReader = desfire_ns.class_("DesfireReader", cg.PollingComponent, i2c.I2CDevice)
TagTrigger = desfire_ns.class_("TagTrigger", automation.Trigger.template(cg.std_string))
StatusTrigger = desfire_ns.class_("StatusTrigger", automation.Trigger.template(cg.std_string))


def _hex_bytes(length):
    """Validator for a fixed length hex string, returning a list of bytes."""

    def validator(value):
        value = cv.string_strict(value).strip().replace(":", "").replace(" ", "")
        if len(value) != length * 2:
            raise cv.Invalid(
                f"Expected {length * 2} hex characters ({length} bytes), got {len(value)}"
            )
        try:
            data = bytes.fromhex(value)
        except ValueError as err:
            raise cv.Invalid(f"Invalid hex string: {err}") from err
        return list(data)

    return validator


CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(DesfireReader),
            # AES-128 master key, 32 hex characters. Keep it in secrets.yaml.
            cv.Required(CONF_MASTER_KEY): _hex_bytes(16),
            cv.Optional(CONF_APP_ID, default="A1B2C3"): _hex_bytes(3),
            cv.Optional(CONF_KEY_NUMBER, default=1): cv.int_range(min=1, max=13),
            cv.Optional(CONF_FILE_ID, default=1): cv.int_range(min=0, max=31),
            cv.Optional(CONF_FILE_SIZE, default=16): cv.int_range(min=4, max=48),
            cv.Optional(CONF_TARGET_ID): cv.use_id(text_sensor.TextSensor),
            cv.Optional(
                CONF_MODE_TIMEOUT, default="30s"
            ): cv.positive_time_period_milliseconds,
            cv.Optional(CONF_HARDEN_PICC_MASTER_KEY, default=True): cv.boolean,
            cv.Optional(CONF_ON_TAG): automation.validate_automation(
                {cv.GenerateID(CONF_TRIGGER_ID): cv.declare_id(TagTrigger)}
            ),
            cv.Optional(CONF_ON_STATUS): automation.validate_automation(
                {cv.GenerateID(CONF_TRIGGER_ID): cv.declare_id(StatusTrigger)}
            ),
        }
    )
    .extend(cv.polling_component_schema("500ms"))
    .extend(i2c.i2c_device_schema(0x24)),
    # The component relies on mbedtls, which is only available on the ESP32.
    cv.only_on_esp32,
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    await i2c.register_i2c_device(var, config)

    cg.add(var.set_master_key(config[CONF_MASTER_KEY]))
    cg.add(var.set_app_id(config[CONF_APP_ID]))
    cg.add(var.set_key_number(config[CONF_KEY_NUMBER]))
    cg.add(var.set_file_id(config[CONF_FILE_ID]))
    cg.add(var.set_file_size(config[CONF_FILE_SIZE]))
    cg.add(var.set_mode_timeout(config[CONF_MODE_TIMEOUT]))
    cg.add(var.set_harden_picc_master_key(config[CONF_HARDEN_PICC_MASTER_KEY]))

    if CONF_TARGET_ID in config:
        sens = await cg.get_variable(config[CONF_TARGET_ID])
        cg.add(var.set_target_id_sensor(sens))

    for conf in config.get(CONF_ON_TAG, []):
        trigger = cg.new_Pvariable(conf[CONF_TRIGGER_ID], var)
        await automation.build_automation(trigger, [(cg.std_string, "x")], conf)

    for conf in config.get(CONF_ON_STATUS, []):
        trigger = cg.new_Pvariable(conf[CONF_TRIGGER_ID], var)
        await automation.build_automation(trigger, [(cg.std_string, "x")], conf)
