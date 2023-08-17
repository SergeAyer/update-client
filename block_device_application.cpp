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
 * @file block_device_applications.cpp
 * @author Serge Ayer <serge.ayer@hefr.ch>
 *
 * @brief Implementation of the class representing an application
 *        stored in a block device.
 *
 * @date 2022-07-05
 * @version 0.1.0
 ***************************************************************************/
#include "block_device_application.hpp"

// for unique_ptr
#include <memory>

#include "mbed_trace.h"
#if MBED_CONF_MBED_TRACE_ENABLE
#define TRACE_GROUP "BlockDeviceApplication"
#endif  // MBED_CONF_MBED_TRACE_ENABLE

#include "mbedtls/sha256.h"
#include "uc_error_code.hpp"

namespace update_client {

BlockDeviceApplication::BlockDeviceApplication(BlockDevice& blockDevice,
                                               mbed::bd_addr_t applicationHeaderAddress,
                                               mbed::bd_addr_t applicationAddress)
    : _blockDevice(blockDevice),
      _applicationHeaderAddress(applicationHeaderAddress),
      _applicationAddress(applicationAddress) {
    memset(_buffer, 0, sizeof(_buffer));
    memset(&_applicationHeader, 0, sizeof(_applicationHeader));
    _applicationHeader.initialized = false;
    _applicationHeader.state       = NOT_CHECKED;
}

bool BlockDeviceApplication::isValid() {
    if (!_applicationHeader.initialized) {
        UCErrorCode rc = readApplicationHeader();
        if (UCErrorCode::UC_ERR_NONE != rc) {
            _applicationHeader.state = NOT_VALID;
        }
    }
    if (_applicationHeader.state == NOT_CHECKED) {
        UCErrorCode rc = checkApplication();
        if (UCErrorCode::UC_ERR_NONE != rc) {
            _applicationHeader.state = NOT_VALID;
        }
    }

    return _applicationHeader.state != NOT_VALID;
}

uint64_t BlockDeviceApplication::getFirmwareVersion() {
    if (!_applicationHeader.initialized) {
        UCErrorCode rc = readApplicationHeader();
        if (UCErrorCode::UC_ERR_NONE != rc) {
            tr_error(" Invalid application header: %" PRIi32 "", (int32_t)rc);
            _applicationHeader.state = NOT_VALID;
            return 0;
        }
    }

    return _applicationHeader.firmwareVersion;
}

uint64_t BlockDeviceApplication::getFirmwareSize() {
    if (!_applicationHeader.initialized) {
        UCErrorCode rc = readApplicationHeader();
        if (UCErrorCode::UC_ERR_NONE != rc) {
            tr_error(" Invalid application header: %" PRIi32 "", (int32_t)rc);
            _applicationHeader.state = NOT_VALID;
            return 0;
        }
    }

    return _applicationHeader.firmwareSize;
}

bool BlockDeviceApplication::isNewerThan(BlockDeviceApplication& otherApplication) {
    // read application header if required
    if (!_applicationHeader.initialized) {
        readApplicationHeader();
    }
    if (!otherApplication._applicationHeader.initialized) {
        otherApplication.readApplicationHeader();
    }

    // if this application is not valid or empty, it cannot be newer
    if (_applicationHeader.headerVersion < kHeaderVersionV2 ||
        _applicationHeader.firmwareSize == 0 || _applicationHeader.state == NOT_VALID) {
        return false;
    }
    // if the other application is not valid or empty, this one is newer
    if (otherApplication._applicationHeader.headerVersion < kHeaderVersionV2 ||
        otherApplication._applicationHeader.firmwareSize == 0 ||
        otherApplication._applicationHeader.state == NOT_VALID) {
        return true;
    }

    // both applications are valid and not empty
    return otherApplication._applicationHeader.firmwareVersion <
           _applicationHeader.firmwareVersion;
}

UCErrorCode BlockDeviceApplication::checkApplication() {
    // read the header
    UCErrorCode rc = readApplicationHeader();
    if (UCErrorCode::UC_ERR_NONE != rc) {
        tr_error(" Invalid application header: %" PRIi32 "", (int32_t)rc);
        _applicationHeader.state = NOT_VALID;
        return rc;
    }
    tr_debug(" Application size is %lld", _applicationHeader.firmwareSize);

    // at this stage, the header is valid
    // calculate hash if slot is not empty
    if (_applicationHeader.firmwareSize > 0) {
        // initialize hashing facility
        mbedtls_sha256_context mbedtls_ctx;
        mbedtls_sha256_init(&mbedtls_ctx);
        mbedtls_sha256_starts(&mbedtls_ctx, 0);

        uint8_t SHA[kSizeOfSHA256] = {0};
        uint32_t remaining         = _applicationHeader.firmwareSize;

        // read full image
        tr_debug(" Calculating hash (start address 0x%08" PRIx64 ", size %" PRIu64 ")",
                 _applicationAddress,
                 _applicationHeader.firmwareSize);
        while (remaining > 0) {
            // read full buffer or what is remaining
            uint32_t readSize = (remaining > kBufferSize) ? kBufferSize : remaining;

            // read buffer using FlashIAP API for portability */
            int err = _blockDevice.read(
                _buffer,
                _applicationAddress + (_applicationHeader.firmwareSize - remaining),
                readSize);
            if (err != 0) {
                tr_error(" Error while reading flash %d", err);
                rc = UCErrorCode::UC_ERR_READ_FAILED;
                break;
            }

            // update hash
            mbedtls_sha256_update(&mbedtls_ctx, _buffer, readSize);

            // update remaining bytes
            remaining -= readSize;
        }

        // finalize hash
        mbedtls_sha256_finish(&mbedtls_ctx, SHA);
        mbedtls_sha256_free(&mbedtls_ctx);

        // compare calculated hash with hash from header
        int diff = memcmp(_applicationHeader.hash, SHA, kSizeOfSHA256);

        if (diff == 0) {
            rc = UCErrorCode::UC_ERR_NONE;
        } else {
            rc = UCErrorCode::UC_ERR_HASH_INVALID;
        }
    } else {
        // header is valid but application size is 0
        rc = UCErrorCode::UC_ERR_FIRMWARE_EMPTY;
    }
    if (rc == UCErrorCode::UC_ERR_NONE) {
        _applicationHeader.state = VALID;
    } else {
        _applicationHeader.state = NOT_VALID;
    }
    return rc;
}

void BlockDeviceApplication::logApplicationInfo() const {
    if (!_applicationHeader.initialized) {
        tr_debug("Application not initialized");
    } else {
        tr_debug(" Magic %" PRIu32 ", Version %" PRIu32 "",
                 _applicationHeader.magic,
                 _applicationHeader.headerVersion);
    }
}

void BlockDeviceApplication::compareTo(BlockDeviceApplication& otherApplication) {
    tr_debug(" Comparing applications at address 0x%08" PRIx64 " and 0x%08" PRIx64 "",
             _applicationAddress,
             otherApplication._applicationAddress);

    tr_debug(" Checking application at address 0x%08" PRIx64 "", _applicationAddress);
    UCErrorCode rc = checkApplication();
    if (UCErrorCode::UC_ERR_NONE != rc) {
        tr_error(" Application is not valid");
        return;
    }
    tr_debug(" Checking application at address 0x%08" PRIx64 "",
             otherApplication._applicationAddress);
    rc = otherApplication.checkApplication();
    if (UCErrorCode::UC_ERR_NONE != rc) {
        tr_error(" Application is not valid");
        return;
    }
    tr_debug(" Both applications are valid");

    if (_applicationHeader.magic != otherApplication._applicationHeader.magic) {
        tr_debug(" Magic numbers differ");
    }
    if (_applicationHeader.headerVersion !=
        otherApplication._applicationHeader.headerVersion) {
        tr_debug(" Header versions differ");
    }
    if (_applicationHeader.firmwareSize !=
        otherApplication._applicationHeader.firmwareSize) {
        tr_debug(" Firmware sizes differ");
    }
    if (_applicationHeader.firmwareVersion !=
        otherApplication._applicationHeader.firmwareVersion) {
        tr_debug(" Firmware versions differ");
    }
    if (memcmp(_applicationHeader.hash,
               otherApplication._applicationHeader.hash,
               sizeof(_applicationHeader.hash)) != 0) {
        tr_debug(" Hash differ");
    }

    if (_applicationHeader.firmwareSize ==
        otherApplication._applicationHeader.firmwareSize) {
        tr_debug(" Comparing application binaries");
        const bd_size_t readSize = _blockDevice.get_read_size();

        std::unique_ptr<char> readBuffer1 = std::unique_ptr<char>(new char[readSize]);
        std::unique_ptr<char> readBuffer2 = std::unique_ptr<char>(new char[readSize]);
        mbed::bd_addr_t address1          = _applicationAddress;
        mbed::bd_addr_t address2          = otherApplication._applicationAddress;
        mbed::bd_size_t nbrOfBytes        = 0;
        bool binariesMatch                = true;
        while (nbrOfBytes < _applicationHeader.firmwareSize) {
            int result = _blockDevice.read(readBuffer1.get(), address1, readSize);
            if (0 != result) {
                tr_error("Cannot read application 1 (address 0x%08" PRIx64 ")", address1);
                binariesMatch = false;
                break;
            }
            result = _blockDevice.read(readBuffer2.get(), address2, readSize);
            if (0 != result) {
                tr_error("Cannot read application 2 (address 0x%08" PRIx64 ")", address2);
                binariesMatch = false;
                break;
            }

            if (memcmp(readBuffer1.get(), readBuffer2.get(), readSize) != 0) {
                tr_error("Applications differ at byte %" PRIu64 " (address1 0x%08" PRIx64
                         " - address2 0x%08" PRIx64 ")",
                         nbrOfBytes,
                         address1,
                         address2);
                binariesMatch = false;
                break;
            }
            // update addresses and progress
            address1 += readSize;
            address2 += readSize;
            nbrOfBytes += readSize;
        }

        if (binariesMatch) {
            tr_debug(" Application binaries are identical");
        }
    } else {
        tr_debug(" Applications differ in size");
    }
}

UCErrorCode BlockDeviceApplication::readApplicationHeader() {
    // default return code
    UCErrorCode rc = UCErrorCode::UC_ERR_INVALID_HEADER;

    // read magic number and version
    uint8_t version_buffer[8] = {0};
    int err                   = _blockDevice.read(
        version_buffer, _applicationHeaderAddress, sizeof(version_buffer));
    if (0 == err) {
        // read out header magic
        _applicationHeader.magic = parseUint32(&version_buffer[0]);
        // read out header magic
        _applicationHeader.headerVersion = parseUint32(&version_buffer[4]);

        // choose version to decode
        switch (_applicationHeader.headerVersion) {
            case kHeaderVersionV2: {
                rc = UCErrorCode::UC_ERR_NONE;
                // Check the header magic
                if (_applicationHeader.magic == kHeaderMagicV2) {
                    uint8_t read_buffer[kHeaderSizeV2] = {0};
                    // read the rest of header (V2)
                    err = _blockDevice.read(
                        read_buffer, _applicationHeaderAddress, kHeaderSizeV2);
                    if (err == 0) {
                        // parse the header
                        tr_debug("Parsing header read at address 0x%08" PRIx64
                                 " starting with 0x%x",
                                 _applicationHeaderAddress,
                                 read_buffer[0]);
                        rc = parseInternalHeaderV2(read_buffer);
                        if (UCErrorCode::UC_ERR_NONE != rc) {
                            tr_error(" Failed to parse header: %" PRIi32 "", (int32_t)rc);
                        }
                    } else {
                        tr_error("Flash read failed at address 0x%08" PRIx64 ": %d",
                                 _applicationHeaderAddress,
                                 err);
                        rc = UCErrorCode::UC_ERR_READ_FAILED;
                    }
                } else {
                    tr_error(" Invalid magic number");
                    rc = UCErrorCode::UC_ERR_INVALID_HEADER;
                }
            } break;

            // Other firmware header versions can be supported here
            default: {
            } break;
        }
    } else {
        tr_error("Flash read failed at address 0x%08" PRIx64 ": %d",
                 _applicationHeaderAddress,
                 err);
        rc = UCErrorCode::UC_ERR_READ_FAILED;
    }

    _applicationHeader.initialized = true;
    if (rc == UCErrorCode::UC_ERR_NONE) {
        _applicationHeader.state = VALID;
    } else {
        _applicationHeader.state = NOT_VALID;
    }

    return rc;
}

UCErrorCode BlockDeviceApplication::parseInternalHeaderV2(const uint8_t* pBuffer) {
    // we expect pBuffer to contain the entire header (version 2)
    UCErrorCode rc = UCErrorCode::UC_ERR_INVALID_HEADER;

    if (pBuffer != NULL) {
        // calculate CRC
        uint32_t calculatedChecksum = crc32(pBuffer, kHeaderCrcOffsetV2);

        // read out CRC
        uint32_t temp32 = parseUint32(&pBuffer[kHeaderCrcOffsetV2]);

        if (temp32 == calculatedChecksum) {
            // parse content
            _applicationHeader.firmwareVersion =
                parseUint64(&pBuffer[kFirmwareVersionOffsetV2]);
            _applicationHeader.firmwareSize =
                parseUint64(&pBuffer[kFirmwareSizeOffsetV2]);

            tr_debug(" headerVersion %" PRIi32 ", calculatedChecksum  0x%08" PRIx32
                     ", firmwareVersion %" PRIu64 ", firmwareSize %" PRIu64 "",
                     _applicationHeader.headerVersion,
                     calculatedChecksum,
                     _applicationHeader.firmwareVersion,
                     _applicationHeader.firmwareSize);

            memcpy(_applicationHeader.hash, &pBuffer[kHashOffsetV2], SHA256_SIZE);
            memcpy(_applicationHeader.campaign, &pBuffer[kCampaingOffetV2], GUID_SIZE);

            // set result
            rc = UCErrorCode::UC_ERR_NONE;
        } else {
            tr_debug("0x%d", pBuffer[0]);
            tr_error("Calculated CRC (address 0x%08" PRIx64 ", size  %" PRIu32
                     ") %" PRIu32 " while read out CRC is  0x%08" PRIx32 "",
                     (mbed::bd_addr_t)pBuffer,
                     kHeaderCrcOffsetV2,
                     calculatedChecksum,
                     temp32);
            rc = UCErrorCode::UC_ERR_INVALID_CHECKSUM;
        }
    }

    return rc;
}

uint32_t BlockDeviceApplication::parseUint32(const uint8_t* pBuffer) {
    uint32_t result = 0;
    if (pBuffer) {
        result = pBuffer[0];
        result = (result << 8) | pBuffer[1];
        result = (result << 8) | pBuffer[2];
        result = (result << 8) | pBuffer[3];
    }

    return result;
}

uint64_t BlockDeviceApplication::parseUint64(const uint8_t* pBuffer) {
    uint64_t result = 0;
    if (pBuffer) {
        result = pBuffer[0];
        result = (result << 8) | pBuffer[1];
        result = (result << 8) | pBuffer[2];
        result = (result << 8) | pBuffer[3];
        result = (result << 8) | pBuffer[4];
        result = (result << 8) | pBuffer[5];
        result = (result << 8) | pBuffer[6];
        result = (result << 8) | pBuffer[7];
    }

    return result;
}

uint32_t BlockDeviceApplication::crc32(const uint8_t* pBuffer, uint32_t length) {
    const uint8_t* pCurrent = pBuffer;
    uint32_t crc            = 0xFFFFFFFF;

    while (length--) {
        crc ^= *pCurrent;
        pCurrent++;

        for (uint32_t counter = 0; counter < 8; counter++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc = crc >> 1;
            }
        }
    }

    return (crc ^ 0xFFFFFFFF);
}

}  // namespace update_client
