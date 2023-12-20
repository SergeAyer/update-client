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
 * @brief Header file for defining the class representing application
 *        candidates.
 *
 * @date 2022-07-05
 * @version 0.1.0
 ***************************************************************************/

#pragma once

#include "block_device_application.hpp"
#include "mbed.h"

namespace update_client {

class CandidateApplications {
   public:
    // storage address is specified relatively to the start of the block device
    CandidateApplications(BlockDevice& blockDevice,
                          mbed::bd_addr_t storageAddress,
                          mbed::bd_size_t storageSize,
                          uint32_t headerSize,
                          uint32_t nbrOfSlots);
    virtual ~CandidateApplications();

    // methods that can be overriden
    virtual uint32_t getSlotForCandidate();

    // public methods
    uint32_t getSlotSize() const;
    uint32_t getNbrOfSlots() const;
    BlockDeviceApplication& getBlockDeviceApplication(uint32_t slotIndex);
    void getCandidateAddress(uint32_t slotIndex,
                             mbed::bd_addr_t& applicationAddress,
                             mbed::bd_size_t& slotSize) const;
    void logCandidateAddress(uint32_t slotIndex) const;
    bool hasValidNewerApplication(BlockDeviceApplication& activeApplication,
                                  uint32_t& newestSlotIndex) const;
    // the installApplication method is used by the bootloader application
    // (for which the POST_APPLICATION_ADDR symbol is defined)
#if defined(POST_APPLICATION_ADDR)
    UCErrorCode installApplication(uint32_t slotIndex, mbed::bd_addr_t destHeaderAddress);
#endif

   private:
    // data members
    BlockDevice& _blockDevice;
    mbed::bd_addr_t _storageAddress;
    mbed::bd_size_t _storageSize;
    uint32_t _nbrOfSlots;
    BlockDeviceApplication*
        _candidateApplicationArray[MBED_CONF_UPDATE_CLIENT_STORAGE_LOCATIONS];
};

}  // namespace update_client

update_client::CandidateApplications* createCandidateApplications(
    BlockDevice& blockDevice,
    mbed::bd_addr_t storageAddress,
    mbed::bd_size_t storageSize,
    uint32_t headerSize,
    uint32_t nbrOfSlots);
