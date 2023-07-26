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
 * @file usb_serial_uc.cpp
 * @author Serge Ayer <serge.ayer@hefr.ch>
 *
 * @brief Implementation of the update client over usb serial class.
 *
 * @date 2022-07-05
 * @version 0.1.0
 ***************************************************************************/
#include "usb_serial_uc.hpp"

// for unique_ptr
#include <memory>

#include "mbed_trace.h"
#if MBED_CONF_MBED_TRACE_ENABLE
#define TRACE_GROUP "USBSerialUC"
#endif  // MBED_CONF_MBED_TRACE_ENABLE

#include "candidate_applications.hpp"
#include "uc_error_code.hpp"

namespace update_client {

#if (USE_USB_SERIAL_UC == 1) && defined(HEADER_ADDR)

USBSerialUC::USBSerialUC(BlockDevice& blockDevice)
    : _blockDevice(blockDevice),
      _downloaderThread(osPriorityNormal, OS_STACK_SIZE, nullptr, "DownloaderThread") {}

UCErrorCode USBSerialUC::start() {
    // initialize the block device
    int result = _blockDevice.init();
    if (0 != result) {
        tr_error("Failed to initialized block device: %d", result);
        return UCErrorCode::UC_ERR_CANNOT_INIT;
    }
    tr_debug("Block device initialized");
    osStatus status =
        _downloaderThread.start(callback(this, &USBSerialUC::downloadFirmware));
    if (osOK != status) {
        tr_error("Failed to start downloader thread: %d", status);
        return UCErrorCode::UC_ERR_CANNOT_START_THREAD;
    }

    return UCErrorCode::UC_ERR_NONE;
}

void USBSerialUC::stop() {
    _stopEvent.set(STOP_EVENT_FLAG);
    _downloaderThread.join();
    _blockDevice.deinit();
}

void USBSerialUC::downloadFirmware() {
    tr_debug("Downloader thread started");
    while (true) {
        tr_debug("Updater waiting for connection");
        USBSerial usbSerial(true);
        tr_debug("Updater connected");
        // flush the serial connection
        usbSerial.sync();

        const mbed::bd_size_t programSize = _blockDevice.get_program_size();

        // recompute the header size (accounting for alignment)
        const uint32_t headerSize = APPLICATION_ADDR - HEADER_ADDR;
        tr_debug(" Application header size is %" PRIu32 "", headerSize);

        // create the CandidateApplications instance for receiving the update
        std::unique_ptr<CandidateApplications> candidateApplications =
            std::unique_ptr<CandidateApplications>(
                createCandidateApplications(_blockDevice,
                                            MBED_CONF_UPDATE_CLIENT_STORAGE_ADDRESS,
                                            MBED_CONF_UPDATE_CLIENT_STORAGE_SIZE,
                                            headerSize,
                                            MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS));

        // get the slot index to be used for storing the candidate application
        tr_debug("Getting slot index...");
        uint32_t slotIndex = candidateApplications->getSlotForCandidate();

        tr_debug("Reading application info for slot %" PRIu32 "", slotIndex);
        candidateApplications->getBlockDeviceApplication(slotIndex).logApplicationInfo();

        mbed::bd_addr_t candidateApplicationAddress = 0;
        mbed::bd_size_t slotSize                    = 0;
        candidateApplications->getCandidateAddress(
            slotIndex, candidateApplicationAddress, slotSize);
        mbed::bd_addr_t addr = candidateApplicationAddress;

        // on the DISCO_H747I, if we erase the flash while receiving data from USBSerial,
        // the data received is somehow corrupted (??!!)
        // erase all blocks before entering the loop for receiving data
        mbed::bd_addr_t eraseAddr       = addr;
        const mbed::bd_size_t eraseSize = _blockDevice.get_erase_size(eraseAddr);
        const uint32_t nbrOfErases      = slotSize / eraseSize;
        for (uint32_t i = 0; i < nbrOfErases; i++) {
            tr_debug("Trying to erase block device at address 0x%08" PRIx64
                     " (size %" PRIu64 ")",
                     eraseAddr,
                     eraseSize);
            if (!_blockDevice.is_valid_erase(eraseAddr, eraseSize)) {
                tr_error("Invalid erase address or size");
                return;
            }
            int result = _blockDevice.erase(eraseAddr, eraseSize);
            if (0 != result) {
                tr_error("Cannot erase block device at slot %" PRIu32
                         " (address 0x%08" PRIx64 "): %d",
                         slotIndex,
                         addr,
                         result);
                return;
            }
            eraseAddr += eraseSize;
        }

        tr_debug("Using slot %" PRIu32 " and starting to write at address 0x%08" PRIx64
                 " with program size %" PRIu64 " and erase size %" PRIu64 "",
                 slotIndex,
                 addr,
                 programSize,
                 eraseSize);

        tr_debug("Please send the update file...");

        uint32_t nbrOfBytes = 0;
        uint32_t counter    = 0;

        std::unique_ptr<char> writeBuffer = std::unique_ptr<char>(new char[programSize]);
        std::unique_ptr<char> readBuffer  = std::unique_ptr<char>(new char[programSize]);

        while (usbSerial.connected()) {
            // receive data from USB serial
            memset(writeBuffer.get(), 0, sizeof(char) * programSize);
            for (uint32_t i = 0; i < programSize; i++) {
                writeBuffer.get()[i] = usbSerial.getc();
            }

            // program the block device
            // tr_debug("Writing %" PRIu64 " bytes at address 0x%08" PRIx64 "",
            // programSize, addr);
            int result = _blockDevice.program(writeBuffer.get(), addr, programSize);
            if (0 != result) {
                tr_error("Failed to program device: %d", result);
                return;
            }

            // check that write was correct
            result = _blockDevice.read(readBuffer.get(), addr, programSize);
            if (0 != result) {
                tr_error("Failed to read device: %d", result);
                return;
            }
            if (memcmp(writeBuffer.get(), readBuffer.get(), programSize) != 0) {
                tr_error("write failed");
                return;
            }

            // update progress and address
            nbrOfBytes += programSize;
            addr += programSize;
            printf("Received %05" PRIu32 " bytes\r", nbrOfBytes);
        }

        // compare the active application with the downloaded one
        // addresses are specified relatively to the base address of the block device
        mbed::bd_addr_t activeApplicationHeaderAddress = MBED_CONF_TARGET_HEADER_OFFSET;
        mbed::bd_addr_t activeApplicationAddress =
            activeApplicationHeaderAddress + headerSize;
        update_client::BlockDeviceApplication activeApplication(
            _blockDevice, activeApplicationHeaderAddress, activeApplicationAddress);

        update_client::BlockDeviceApplication candidateApplication(
            _blockDevice,
            candidateApplicationAddress,
            candidateApplicationAddress + headerSize);
        activeApplication.compareTo(candidateApplication);

        writeBuffer = NULL;
        readBuffer  = NULL;

        tr_debug("Nbr of bytes received %" PRIu32 "", nbrOfBytes);

        // check whether the thread has been stopped
        if (_stopEvent.wait_all_for(STOP_EVENT_FLAG, std::chrono::milliseconds::zero()) ==
            STOP_EVENT_FLAG) {
            // exit the loop and the thread
            tr_debug("Exiting downloadFirmware");
            break;
        }
    }
}

#endif  // USE_USB_SERIAL_UC

}  // namespace update_client
