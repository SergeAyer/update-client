// Copyright 2022 Haute école d'ingénierie et d'architecture de Fribourg
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/****************************************************************************
 * @file usb_serial_uc.hpp
 * @author Serge Ayer <serge.ayer@hefr.ch>
 *
 * @brief Header file for defining the update client over usb serial class.
 *
 * @date 2022-07-05
 * @version 0.1.0
 ***************************************************************************/
#pragma once

#include "USBSerial.h"
#include "mbed.h"
#include "uc_error_code.hpp"

namespace update_client {

#if (USE_USB_SERIAL_UC == 1) && defined(HEADER_ADDR)

class USBSerialUC {
   public:
    // constructor with a reference to a block device
    explicit USBSerialUC(BlockDevice& blockDevice);

    // method called for creating the CandidateApplications instance

    // methods for starting and stopping the updater
    UCErrorCode start();
    void stop();

   private:
    // private method
    void downloadFirmware();

    // data members
    BlockDevice& _blockDevice;
    Thread _downloaderThread;
    enum { STOP_EVENT_FLAG = 1 };
    EventFlags _stopEvent;
    static constexpr std::chrono::milliseconds kWaitTimeBetweenCheck = 5000ms;
};

#endif  // USE_USB_SERIAL_UC

}  // namespace update_client
