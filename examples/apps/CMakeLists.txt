# Copyright 2018 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CMAKE_MINIMUM_REQUIRED(VERSION 3.2 FATAL_ERROR)

INCLUDE(CMakeVariables.txt)
SET(GENERIC_PRIVATE_INCLUDE_DIRS "." "${TCF_TOP_DIR}/tc/sgx/common"
	"${TCF_TOP_DIR}/tc/sgx/common/work_order_interface"
	"${TCF_TOP_DIR}/common/sgx_workload")

################################################################################
ADD_SUBDIRECTORY(echo/workload)
ADD_SUBDIRECTORY(heart_disease_eval/workload)

# To add a new workload, uncomment the following line and change
# $WORKLOAD_STATIC_NAME$ to the appropriate name (such as hello_world):
#ADD_SUBDIRECTORY($WORKLOAD_STATIC_NAME$/workload)

