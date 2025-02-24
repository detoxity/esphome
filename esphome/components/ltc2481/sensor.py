import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import i2c, sensor
from esphome.const import UNIT_VOLT, DEVICE_CLASS_VOLTAGE, STATE_CLASS_MEASUREMENT

DEPENDENCIES = ["i2c"]

ltc2481_ns = cg.esphome_ns.namespace("ltc2481")
LTC2481Sensor = ltc2481_ns.class_("LTC2481Sensor", cg.PollingComponent, i2c.I2CDevice, sensor.Sensor)

CONFIG_SCHEMA = sensor.sensor_schema(
    unit_of_measurement=UNIT_VOLT,
    accuracy_decimals=4,
    device_class=DEVICE_CLASS_VOLTAGE,
    state_class=STATE_CLASS_MEASUREMENT
).extend(
    {
        cv.GenerateID(): cv.declare_id(LTC2481Sensor),
        cv.Required("address"): cv.i2c_address,
        cv.Optional("update_interval", default="60s"): cv.update_interval,
    }
).extend(i2c.i2c_device_schema(0x24))

async def to_code(config):
    var = cg.new_Pvariable(config[cv.GenerateID()])
    await cg.register_component(var, config)
    await i2c.register_i2c_device(var, config)
