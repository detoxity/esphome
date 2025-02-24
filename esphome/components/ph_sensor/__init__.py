import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import i2c, sensor

DEPENDENCIES = ["i2c"]
ph_ns = cg.esphome_ns.namespace("ph_sensor")  # Ensure consistency
PhSensor = ph_ns.class_("PhSensor", cg.PollingComponent)  # Ensure consistency

CONFIG_SCHEMA = cv.Schema({
    cv.GenerateID(): cv.declare_id(PhSensor),  # Ensure consistency
    cv.Optional("i2c_address", default=0x48): cv.i2c_address,
    cv.Optional("reference_voltage", default=3.3): cv.positive_float,
}).extend(cv.polling_component_schema("60s")).extend(i2c.i2c_device_schema(0x48))

def to_code(config):
    var = cg.new_Pvariable(config[cv.GenerateID()], config["i2c_address"], config["reference_voltage"], config["update_interval"])
    yield cg.register_component(var, config)
    yield i2c.register_i2c_device(var, config)
