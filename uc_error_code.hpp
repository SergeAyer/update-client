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
 * @file error_codes.hpp
 * @author Serge Ayer <serge.ayer@hefr.ch>
 *
 * @brief Header file for defining the error codes of the update client library.
 *
 * @date 2022-07-05
 * @version 0.1.0
 ***************************************************************************/
#pragma once

namespace update_client {

// return codes
enum class UCErrorCode {
    UC_ERR_NONE                = 0,
    UC_ERR_INVALID_HEADER      = -1,
    UC_ERR_INVALID_CHECKSUM    = -2,
    UC_ERR_READ_FAILED         = -3,
    UC_ERR_HASH_INVALID        = -4,
    UC_ERR_FIRMWARE_EMPTY      = -5,
    UC_ERR_PROGRAM_FAILED      = -6,
    UC_ERR_ERASE_FAILED        = -7,
    UC_ERR_CANNOT_INIT         = -8,
    UC_ERR_CANNOT_START_THREAD = -9
};

}  // namespace update_client
