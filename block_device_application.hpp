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
 * @file block_device_applications.hpp
 * @author Serge Ayer <serge.ayer@hefr.ch>
 *
 * @brief Header file for defining the class representing an application
 *        stored in a block device.
 *
 * @date 2022-07-05
 * @version 0.1.0
 ***************************************************************************/
#pragma once

#include "mbed.h"
#include "uc_error_code.hpp"

namespace update_client {

class BlockDeviceApplication {
   public:
    // constructor
    BlockDeviceApplication(BlockDevice& blockDevice,
                           mbed::bd_addr_t applicationHeaderAddress,
                           mbed::bd_addr_t applicationAddress);

    // public methods
    bool isValid();
    uint64_t getFirmwareVersion();
    uint64_t getFirmwareSize();
    bool isNewerThan(BlockDeviceApplication& otherApplication);
    UCErrorCode checkApplication();
    void logApplicationInfo() const;
    void compareTo(BlockDeviceApplication& otherApplication);

   private:
    // private methods
    UCErrorCode readApplicationHeader();
    UCErrorCode parseInternalHeaderV2(const uint8_t* pBuffer);

    static uint32_t parseUint32(const uint8_t* pBuffer);
    static uint64_t parseUint64(const uint8_t* pBuffer);
    static uint32_t crc32(const uint8_t* pBuffer, uint32_t length);

    // data members
    BlockDevice& _blockDevice;
    const mbed::bd_addr_t _applicationHeaderAddress;
    const mbed::bd_addr_t _applicationAddress;

    // application header
    // GUID type
    static constexpr uint8_t GUID_SIZE = (128 / 8);
    typedef uint8_t guid_t[GUID_SIZE];

    // SHA256 hash
    static constexpr uint8_t SHA256_SIZE = (256 / 8);
    typedef uint8_t hash_t[SHA256_SIZE];

    enum ApplicationState { NOT_CHECKED, VALID, NOT_VALID };
    struct ApplicationHeader {
        bool initialized;
        uint32_t magic;
        uint32_t headerVersion;
        uint64_t firmwareVersion;
        uint64_t firmwareSize;
        hash_t hash;
        guid_t campaign;
        uint32_t signatureSize;
        uint8_t signature[0];
        ApplicationState state;
    };
    ApplicationHeader _applicationHeader;

    // the size and offsets defined below do not correspond to the
    // application header defined above but rather to the definition in
    // the mbed_lib.json file
    // constants defining the header
    static constexpr uint32_t kHeaderVersionV2         = 2;
    static constexpr uint32_t kHeaderMagicV2           = 0x5a51b3d4UL;
    static constexpr uint32_t kHeaderSizeV2            = 112;
    static constexpr uint32_t kFirmwareVersionOffsetV2 = 8;
    static constexpr uint32_t kFirmwareSizeOffsetV2    = 16;
    static constexpr uint32_t kHashOffsetV2            = 24;
    static constexpr uint32_t kCampaingOffetV2         = 88;
    static constexpr uint32_t kSignatureSizeOffsetV2   = 104;
    static constexpr uint32_t kHeaderCrcOffsetV2       = 108;

    // other constants
    static constexpr uint32_t kSizeOfSHA256 = (256 / 8);
    static constexpr uint32_t kBufferSize   = 256;
    // buffer used in storage operations
    uint8_t _buffer[kBufferSize];
};

}  // namespace update_client
