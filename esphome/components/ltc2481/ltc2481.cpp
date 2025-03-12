#include "ltc2481.h"
#include "esphome/core/log.h"

namespace esphome {
namespace ltc2481 {

static const char *const TAG = "ltc2481.sensor";

void LTC2481Sensor::setup() {
  ESP_LOGD(TAG, "Setting up LTC2481 sensor");
}

void LTC2481Sensor::dump_config() { LOG_I2C_DEVICE(this); }

void LTC2481Sensor::update() {
  float voltage = read_voltage();
  if (!std::isnan(voltage)) {
    ESP_LOGD(TAG, "LTC2481 Voltage: %.6f mV", voltage);
    this->publish_state(voltage);
  } else {
    ESP_LOGE(TAG, "Failed to read voltage from LTC2481");
  }
}

float LTC2481Sensor::read_voltage() {
  union LT_UNION_INT32_4BYTES
{
  int32_t  LT_INT32;       //!< 32-bit signed integer to be converted to four bytes
  uint32_t LT_UINT32;     //!< 32-bit unsigned integer to be converted to four bytes
  uint8_t  LT_BYTE[4];     //!< 4 bytes (unsigned 8-bit integers) to be converted to a 32-bit signed or unsigned integer
};

  LT_UNION_INT32_4BYTES data;


  uint8_t ret;
  ret = this->read(data.LT_BYTE, 3);
  ESP_LOGI("LTC2483", "i2c read res: %d", ret);
  if(ret){
    ESP_LOGI("LTC2483", "ERROR read from i2c");
    return NAN;
  } 


  data.LT_BYTE[3] = data.LT_BYTE[0]; // Shift bytes up by one. We read out 24 bits,
  data.LT_BYTE[2] = data.LT_BYTE[1]; // which are loaded into bytes 2,1,0. Need to left-
  data.LT_BYTE[1] = data.LT_BYTE[2]; // justify.
  data.LT_BYTE[0] = 0x00;
  data.LT_UINT32 >>= 2;  // Shifts data 2 bits to the right; operating on unsigned member shifts in zeros.
  data.LT_BYTE[3] = data.LT_BYTE[3] & 0x3F; // Clear upper 2 bits JUST IN CASE. Now the data format matches the SPI parts.

  int32_t raw_value = data.LT_INT32;

  float voltage;
  raw_value -= 0x20000000;             //! 1) Converts offset binary to binary
  voltage=(float) raw_value;
  voltage = voltage / 536870912.0;    //! 2) This calculates the input as a fraction of the reference voltage (dimensionless)
  voltage = voltage * 2.5 * 1000;           //! 3) Multiply fraction by Vref to get the actual voltage at the input (in volts)



   ESP_LOGI("LTC2483", "Voltage: %.5f mV", voltage);
   return voltage;
}

}  // namespace ltc2481
}  // namespace esphome
