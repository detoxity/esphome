#include "ph_sensor.h"
#include "Wire.h"
#include "ADC.h"

PhSensor::PhSensor(uint8_t address, float reference_voltage, uint32_t update_interval) 
    : PollingComponent(update_interval), i2c_address(address), vref(reference_voltage) {}

void PhSensor::setup() {
    Wire.begin();
}

void PhSensor::update() {
    int32_t adc_code;
    if (adc_read(i2c_address, &adc_code, 100) == 0) {
        float voltage = adc_code_to_voltage(adc_code, vref);
        adc_sensor->publish_state(voltage);
    } else {
        ESP_LOGW("ph_sensor", "Failed to read ADC");
    }
}
