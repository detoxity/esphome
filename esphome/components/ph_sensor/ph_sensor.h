#ifndef PH_SENSOR_H
#define PH_SENSOR_H

#include "esphome.h"

class PhSensor : public PollingComponent {
public:
    Sensor *adc_sensor = new Sensor();
    uint8_t i2c_address;
    float vref;

    PhSensor(uint8_t address, float reference_voltage, uint32_t update_interval);
    void setup() override;
    void update() override;
};

#endif // PH_SENSOR_H
