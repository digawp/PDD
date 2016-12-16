#include <fstream>
#include <iostream>
#include <stdio.h>
#include <string>
#include <vector>
#include "../Enclave/Enclave_u.h"
#include "sgx_urts.h"

// Unix-specific way to enumerate files in a dir
#include <dirent.h>

#include "../sgx_utils/sgx_utils.h"
#include "Network.h"

#define CHUNK_SIZE 4096

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

// OCall implementations
void ocall_print(const char* str) {
    printf("%s\n", str);
}

// taken from http://stackoverflow.com/questions/612097/how-can-i-get-the-list-of-files-in-a-directory-using-c-or-c
void get_all_files_in_dir(
        const std::string& dir_name, std::vector<std::string>& file_vector) {
    DIR *dir;
    struct dirent *ent;
    if ((dir = opendir (dir_name.c_str())) != NULL) {
        /* print all the files and directories within directory */
        while ((ent = readdir (dir)) != NULL) {
            if (ent->d_type == DT_REG) {
                file_vector.push_back(ent->d_name);
            }
        }
        closedir (dir);
    } else {
        /* could not open directory */
        perror ("opendir");
    }
}

int main(int argc, char const *argv[]) {
    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
        std::cout << "Failed to initialize enclave" << std::endl;
        return 1;
    }

    std::vector<std::string> file_names;
    get_all_files_in_dir("samples", file_names);

    sgx_status_t status = set_counters(global_eid, NULL, file_names.size());
    if (!is_ecall_successful(status, "Set counters failed.")) {
        return 1;
    }
    // int socket_fd = connect_to_s();

    for (auto fnp = file_names.begin(); fnp != file_names.end(); ++fnp) {
        size_t sealed_size = sizeof(sgx_sealed_data_t) + CHUNK_SIZE;
        char sealed_chunk[sealed_size];

        std::ifstream chunk_file(*fnp);
        chunk_file.read(sealed_chunk, sealed_size);
        chunk_file.close();

        sgx_status_t ecall_success;
        status = label_chunk(global_eid, &ecall_success, (sgx_sealed_data_t*)sealed_chunk, sealed_size);

        if (!is_ecall_successful(status, "Label chunk failed", ecall_success)) {
            return 1;
        }
    }
    return 0;
}
