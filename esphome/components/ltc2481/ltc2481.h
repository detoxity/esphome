#pragma once

#include "esphome.h"
#include "esphome/components/i2c/i2c.h"

namespace esphome {
namespace ltc2481 {

class LTC2481Sensor : public PollingComponent, public i2c::I2CDevice, public sensor::Sensor {
 public:
  void setup() override;
  void update() override;
  void dump_config() override;
  float read_voltage();
};

}  // namespace ltc2481
}  // namespace esphome
