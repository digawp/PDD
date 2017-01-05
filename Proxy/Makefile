#
# Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
		SGX_COMMON_CFLAGS += -O0 -g
else
		SGX_COMMON_CFLAGS += -O2
endif

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

# Cpp_Files
Common_Cpp_Files := sgx_utils/sgx_utils.cpp
Cupload_Cpp_Files := $(wildcard Cupload/*.cpp)
Pdedup_Cpp_Files := $(wildcard Pdedup/*.cpp)

# Include_Paths
Common_Include_Paths := -Isgx_utils -I$(SGX_SDK)/include
Cupload_Include_Paths := -ICupload $(Common_Include_Paths)
Pdedup_Include_Paths := -IPdedup $(Common_Include_Paths)

# C Flags
Common_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(Common_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
		Common_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
		Common_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
		Common_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

Cupload_C_Flags := $(Common_C_Flags) $(Cupload_Include_Paths)
Pdedup_C_Flags := $(Common_C_Flags) $(Pdedup_Include_Paths)

# Cpp Flags
Common_Cpp_Flags := $(Common_C_Flags) -std=c++11
Cupload_Cpp_Flags := $(Cupload_C_Flags) -std=c++11
Pdedup_Cpp_Flags := $(Pdedup_C_Flags) -std=c++11
Common_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread -lcryptopp

ifneq ($(SGX_MODE), HW)
	Common_Link_Flags += -lsgx_uae_service_sim
else
	Common_Link_Flags += -lsgx_uae_service
endif

# Cpp Objects
Common_Cpp_Objects := $(Common_Cpp_Files:.cpp=.o)
Cupload_Cpp_Objects := $(Cupload_Cpp_Files:.cpp=.o)
Pdedup_Cpp_Objects := $(Pdedup_Cpp_Files:.cpp=.o)

# Exe Names
Cupload_Name := cupload
Pdedup_Name := pdedup

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := Enclave/Enclave.cpp Enclave/Sealing/Sealing.cpp
Enclave_Include_Paths := -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I../topenssl/include

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++03 -nostdinc++
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0
	# -Wl,--version-script=Enclave/Enclave.lds

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all run allc runc alls runs

all: | c s

run: runc

ifeq ($(Build_Mode), HW_RELEASE)
c: $(Cupload_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(Cupload_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool. See User's Guide for more details."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."

s: $(Pdedup_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(Pdedup_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool. See User's Guide for more details."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."

else
c: $(Cupload_Name) $(Signed_Enclave_Name)

s: $(Pdedup_Name) $(Signed_Enclave_Name)
endif

runc: c
ifneq ($(Build_Mode), HW_RELEASE)
	@mkdir -p samples
	@mkdir -p chunks
	@$(CURDIR)/$(Cupload_Name)
	@echo "RUN  =>  $(Cupload_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

runs: s
ifneq ($(Build_Mode), HW_RELEASE)
	@mkdir -p samples
	@mkdir -p chunks
	@$(CURDIR)/$(Pdedup_Name)
	@echo "RUN  =>  $(Pdedup_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## App Objects ########

Enclave/Enclave_u.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --untrusted ./Enclave.edl --search-path . --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Enclave/Enclave_u.o: Enclave/Enclave_u.c
	@$(CC) $(Common_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

sgx_utils/%.o: sgx_utils/%.cpp
	@$(CXX) $(Common_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"


######## Enclave Objects ########

Enclave/Enclave_t.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/%.o: Enclave/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): Enclave/Enclave_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"


######## Cupload Objects ########

Cupload/%.o: Cupload/%.cpp
	@$(CXX) $(Cupload_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Cupload_Name): Enclave/Enclave_u.o $(Common_Cpp_Objects) $(Cupload_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Common_Link_Flags)
	@echo "LINK =>  $@"


######## Pdedup Objects ########

Pdedup/%.o: Pdedup/%.cpp
	@$(CXX) $(Pdedup_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Pdedup_Name): Enclave/Enclave_u.o $(Common_Cpp_Objects) $(Pdedup_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Common_Link_Flags)
	@echo "LINK =>  $@"


.PHONY: clean

clean:
	@rm -f $(Cupload_Name) $(Pdedup_Name) $(Enclave_Name) $(Signed_Enclave_Name) \
		$(Common_Cpp_Objects) $(Cupload_Cpp_Objects) $(Pdedup_Cpp_Objects) \
		Enclave/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.* \
		samples/* chunks/*
