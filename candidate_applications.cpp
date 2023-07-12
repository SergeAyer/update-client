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
 * @file candidate_applications.hpp
 * @author Serge Ayer <serge.ayer@hefr.ch>
 *
 * @brief Implementation of the class representing application candidates
 *
 * @date 2022-07-05
 * @version 0.1.0
 ***************************************************************************/
#include "candidate_applications.hpp"

// for unique_ptr
#include <memory>

#include "mbed_trace.h"
#if MBED_CONF_MBED_TRACE_ENABLE
#define TRACE_GROUP "CandidateApplications"
#endif  // MBED_CONF_MBED_TRACE_ENABLE

#include "uc_error_code.hpp"

MBED_WEAK update_client::CandidateApplications* createCandidateApplications(
    BlockDevice& blockDevice,
    mbed::bd_addr_t storageAddress,
    mbed::bd_size_t storageSize,
    uint32_t headerSize,
    uint32_t nbrOfSlots) {
    return new update_client::CandidateApplications(
        blockDevice, storageAddress, storageSize, headerSize, nbrOfSlots);
}

namespace update_client {

CandidateApplications::CandidateApplications(BlockDevice& blockDevice,
                                             mbed::bd_addr_t storageAddress,
                                             mbed::bd_size_t storageSize,
                                             uint32_t headerSize,
                                             uint32_t nbrOfSlots)
    : _blockDevice(blockDevice),
      _storageAddress(storageAddress),
      _storageSize(storageSize),
      _nbrOfSlots(nbrOfSlots) {
    // the number of slots must be equal or smaller than
    // MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS
    if (nbrOfSlots <= MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS) {
        for (uint32_t slotIndex = 0; slotIndex < nbrOfSlots; slotIndex++) {
            mbed::bd_addr_t candidateAddress = 0;
            mbed::bd_size_t slotSize         = 0;
            getCandidateAddress(slotIndex, candidateAddress, slotSize);
            tr_debug(" Slot %" PRIu32 ": application header address: 0x%08" PRIx64
                     " application address 0x%08" PRIx64 " (slot size %" PRIu64 ")",
                     slotIndex,
                     candidateAddress,
                     candidateAddress + headerSize,
                     slotSize);
            _candidateApplicationArray[slotIndex] =
                new update_client::BlockDeviceApplication(
                    _blockDevice, candidateAddress, candidateAddress + headerSize);
        }
    }
}

CandidateApplications::~CandidateApplications() {
    for (uint32_t slotIndex = 0; slotIndex < _nbrOfSlots; slotIndex++) {
        delete _candidateApplicationArray[slotIndex];
        _candidateApplicationArray[slotIndex] = nullptr;
    }
}

uint32_t CandidateApplications::getSlotForCandidate() {
    // default implementation, always returns 0
    return 0;
}

uint32_t CandidateApplications::getSlotSize() const { return _storageSize / _nbrOfSlots; }

uint32_t CandidateApplications::getNbrOfSlots() const { return _nbrOfSlots; }

BlockDeviceApplication& CandidateApplications::getBlockDeviceApplication(
    uint32_t slotIndex) {
    return *_candidateApplicationArray[slotIndex];
}

void CandidateApplications::getCandidateAddress(uint32_t slotIndex,
                                                mbed::bd_addr_t& candidateAddress,
                                                mbed::bd_size_t& slotSize) const {
    // Addresses are specified relatively to the start address of the block device
    // The block device start address must thus not be accounted for
    slotSize         = _storageSize / _nbrOfSlots;
    candidateAddress = _storageAddress + (slotIndex * slotSize);

    // sanity check
    if (!_blockDevice.is_valid_erase(candidateAddress,
                                     _blockDevice.get_erase_size(candidateAddress))) {
        tr_error("Candidate address 0x%08" PRIx64 " for slot %" PRIu32 "",
                 candidateAddress,
                 slotIndex);
        MBED_ERROR(MBED_MAKE_ERROR(MBED_MODULE_APPLICATION, -1),
                   "Unexpected candidate address (erase)");
    }
    if (!_blockDevice.is_valid_program(candidateAddress,
                                       _blockDevice.get_program_size())) {
        tr_error("Candidate address 0x%08" PRIx64 " for slot %" PRIu32 "",
                 candidateAddress,
                 slotIndex);
        MBED_ERROR(MBED_MAKE_ERROR(MBED_MODULE_APPLICATION, -1),
                   "Unexpected candidate address (program)");
    }
    if (!_blockDevice.is_valid_read(candidateAddress, _blockDevice.get_read_size())) {
        tr_error("Candidate address 0x%08" PRIx64 " for slot %" PRIu32 "",
                 candidateAddress,
                 slotIndex);
        MBED_ERROR(MBED_MAKE_ERROR(MBED_MODULE_APPLICATION, -1),
                   "Unexpected candidate address (read)");
    }
}

void CandidateApplications::logCandidateAddress(uint32_t slotIndex) const {
    tr_debug(" Slot %" PRIu32 ": Storage address: 0x%08" PRIx64 " Storage size: %" PRIu64
             "",
             slotIndex,
             _storageAddress,
             _storageSize);

    // addresses are specified relatively to the start address of the block device
    mbed::bd_size_t slotSize         = _storageSize / _nbrOfSlots;
    mbed::bd_addr_t candidateAddress = _storageAddress + (slotIndex * slotSize);

    tr_debug(" Slot start address (slot %" PRIu32 "): 0x%08" PRIx64 "",
             slotIndex,
             candidateAddress);
}

bool CandidateApplications::hasValidNewerApplication(
    BlockDeviceApplication& activeApplication, uint32_t& newestSlotIndex) const {
    tr_debug(" Checking for newer applications on %" PRIu32 " slots", _nbrOfSlots);
    newestSlotIndex = _nbrOfSlots;
    for (uint32_t slotIndex = 0; slotIndex < _nbrOfSlots; slotIndex++) {
        // Only hash check firmwares with higher version number than the
        // active image and with a different hash. This prevents rollbacks
        // and hash checks of old images. If the active image is not valid,
        // bestStoredFirmwareImageDetails.version equals 0
        tr_debug(" Checking application at slot %" PRIu32 "", slotIndex);
        BlockDeviceApplication& newestApplication =
            newestSlotIndex == _nbrOfSlots ? activeApplication
                                           : *_candidateApplicationArray[newestSlotIndex];

        if (_candidateApplicationArray[slotIndex]->isNewerThan(newestApplication)) {
#if MBED_CONF_MBED_TRACE_ENABLE
            if (newestSlotIndex == _nbrOfSlots) {
                tr_debug(" Candidate application at slot %" PRIu32
                         " is newer than the active one",
                         slotIndex);
            } else {
                tr_debug(" Candidate application at slot %" PRIu32
                         " is newer than application at slot %" PRIu32 "",
                         slotIndex,
                         newestSlotIndex);
            }
#endif
            UCErrorCode rc = _candidateApplicationArray[slotIndex]->checkApplication();
            if (UCErrorCode::UC_ERR_NONE != rc) {
                tr_error(" Candidate application at slot %" PRIu32
                         " is not valid: %" PRIi32 "",
                         slotIndex,
                         rc);
                continue;
            }
            tr_debug(" Candidate application at slot %" PRIu32 " is valid", slotIndex);

            // update the newest slot index
            newestSlotIndex = slotIndex;
        }
    }
    return newestSlotIndex != _nbrOfSlots;
}

#if defined(POST_APPLICATION_ADDR)
UCErrorCode CandidateApplications::installApplication(uint32_t slotIndex,
                                                      mbed::bd_addr_t destHeaderAddress) {
    tr_debug(" Installing candidate application at slot %d as active application",
             slotIndex);
    const mbed::bd_size_t programSize = _blockDevice.get_program_size();
    const mbed::bd_size_t eraseSize   = _blockDevice.get_erase_size();

    // sanity check
    tr_debug("Blockdevice: program size is %" PRIu64 ", erase size is %" PRIu64 "",
             programSize,
             eraseSize);
    if ((destHeaderAddress % programSize) != 0) {
        tr_error("Destination address 0x%08" PRIx64 " must be a multiple of program size",
                 destHeaderAddress);
        return UCErrorCode::UC_ERR_PROGRAM_FAILED;
    }
    if ((destHeaderAddress % eraseSize) != 0) {
        tr_error("Destination address 0x%08" PRIx64 " must be a multiple of erase size",
                 destHeaderAddress);
        return UCErrorCode::UC_ERR_ERASE_FAILED;
    }

    std::unique_ptr<char> buffer = std::unique_ptr<char>(new char[programSize]);

    mbed::bd_addr_t destAddr   = destHeaderAddress;
    mbed::bd_addr_t sourceAddr = 0;
    mbed::bd_size_t slotSize   = 0;
    getCandidateAddress(slotIndex, sourceAddr, slotSize);

    // add the header size to the firmware size
    const uint32_t headerSize = POST_APPLICATION_ADDR - HEADER_ADDR;
    tr_debug(" Header size is %d", headerSize);
    const uint64_t copySize =
        _candidateApplicationArray[slotIndex]->getFirmwareSize() + headerSize;

    uint32_t nbrOfBytes = 0;
    tr_debug(" Starting to copy application from address 0x%08" PRIx64
             " to address 0x%08" PRIx64 "",
             sourceAddr,
             destAddr);

    while (nbrOfBytes < copySize) {
        // read the buffer (candidate application)
        int result = _blockDevice.read(buffer.get(), sourceAddr, programSize);
        if (0 != result) {
            tr_error("Cannot read candidate application at slot %" PRIu32
                     " (address 0x%08" PRIx64 "): %d",
                     slotIndex,
                     sourceAddr,
                     result);
            return UCErrorCode::UC_ERR_READ_FAILED;
        }

        // program the new application (need to erase when necessary)
        if ((destAddr % eraseSize) == 0) {
            result = _blockDevice.erase(destAddr, eraseSize);
            if (0 != result) {
                tr_error("Cannot erase block device at slot %" PRIu32
                         " (address 0x%08" PRIx64 "): %d",
                         slotIndex,
                         destAddr,
                         result);
                return UCErrorCode::UC_ERR_ERASE_FAILED;
            }
        }

        result = _blockDevice.program(buffer.get(), destAddr, programSize);
        if (0 != result) {
            tr_error("Cannot program candidate application at slot %" PRIu32
                     " (address 0x%08" PRIx64 "): %d",
                     slotIndex,
                     destAddr,
                     result);
            return UCErrorCode::UC_ERR_PROGRAM_FAILED;
        }

        // update addresses and progress
        sourceAddr += programSize;
        destAddr += programSize;
        nbrOfBytes += programSize;
    }
    tr_debug(" Copied %" PRIu32 " bytes", nbrOfBytes);
    buffer = nullptr;

    return UCErrorCode::UC_ERR_NONE;
}
#endif

}  // namespace update_client
