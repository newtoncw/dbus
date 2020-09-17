######### SGX TOOLS ######################
SGX_SDK ?= /opt/Intel/sgxsdk
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

######## Enclave Settings ########
Enclave_C_Flags := -nostdinc -fvisibility=hidden -fpie -fstack-protector -IInclude -IEnclave \
	-I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport

Enclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tservice -Wl,--end-group \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0
	
Enclave_Name := dbus_enclave.so
Signed_Enclave_Name := dbus_enclave.signed.so
Enclave_Config_File := enclave.config.xml

.PHONY: all run

all: $(Signed_Enclave_Name) enclave_u.c

run: all

####### Enclave Objects ########
enclave_u.c: $(SGX_EDGER8R) enclave.edl
	$(SGX_EDGER8R) --untrusted enclave.edl --search-path $(SGX_SDK)/include

enclave_t.c: $(SGX_EDGER8R) enclave.edl
	$(SGX_EDGER8R) --trusted enclave.edl --search-path $(SGX_SDK)/include

enclave_t.o: enclave_t.c 
	gcc $(Enclave_C_Flags) -c $< -o $@ -g

enclave.o: enclave.c
	gcc $(Enclave_C_Flags) -c $< -o $@ -g

$(Enclave_Name): enclave_t.o enclave.o
	gcc $^ -o $@ $(Enclave_Link_Flags) -g

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)


.PHONY: clean

clean:
	@rm -f *.o $(Enclave_Name) $(Signed_Enclave_Name) enclave_t.c enclave_t.h enclave_u.c enclave_u.h

