#include <cstdio>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>

#include "Enclave_u.h"
#include <sgx_urts.h>
#include "error_print.h"

#define MRENCLAVE 0
#define MRSIGNER 1


sgx_enclave_id_t global_eid = 0;



/* OCALL implementations */
void ocall_print(const char* str)
{
	std::cout << "Output from OCALL: " << std::endl;
	std::cout << str << std::endl;
	
	return;
}

void ocall_error_print(sgx_status_t st)
{
	sgx_error_print(st);
}



/* Enclave initialization function */
int initialize_enclave()
{
	std::string launch_token_path = "enclave.token";
	std::string enclave_name = "enclave.signed.so";
	const char* token_path = launch_token_path.c_str();

	sgx_launch_token_t token = {0};
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	int updated = 0;


	/*==============================================================*
	 * Step 1: Obtain enclave launch token                          *
	 *==============================================================*/
	
	/* If exist, load the enclave launch token */
	FILE *fp = fopen(token_path, "rb");

	/* If token doesn't exist, create the token */
	if(fp == NULL && (fp = fopen(token_path, "wb")) == NULL)
	{		
		/* Storing token is not necessary, so file I/O errors here
		 * is not fatal
		 */
		std::cerr << "Warning: Failed to create/open the launch token file ";
		std::cerr << "\"" << launch_token_path << "\"." << std::endl;
	}


	if(fp != NULL)
	{
		/* read the token from saved file */
		size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);

		/* if token is invalid, clear the buffer */
		if(read_num != 0 && read_num != sizeof(sgx_launch_token_t))
		{
			memset(&token, 0x0, sizeof(sgx_launch_token_t));

			/* As aforementioned, if token doesn't exist or is corrupted,
			 * zero-flushed new token will be used for launch.
			 * So token error is not fatal.
			 */
			std::cerr << "Warning: Invalid launch token read from ";
			std::cerr << "\"" << launch_token_path << "\"." << std::endl;
		}
	}


	/*==============================================================*
	 * Step 2: Initialize enclave by calling sgx_create_enclave     *
	 *==============================================================*/

	status = sgx_create_enclave(enclave_name.c_str(), SGX_DEBUG_FLAG, &token,
		&updated, &global_eid, NULL);
	
	if(status != SGX_SUCCESS)
	{
		/* Defined at error_print.cpp */
		sgx_error_print(status);
		
		if(fp != NULL)
		{
			fclose(fp);
		}

		return -1;
	}

	/*==============================================================*
	 * Step 3: Save the launch token if it is updated               *
	 *==============================================================*/
	
	/* If there is no update with token, skip save */
	if(updated == 0 || fp == NULL)
	{
		if(fp != NULL)
		{
			fclose(fp);
		}

		return 0;
	}


	/* reopen with write mode and save token */
	fp = freopen(token_path, "wb", fp);
	if(fp == NULL) return 0;

	size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);

	if(write_num != sizeof(sgx_launch_token_t))
	{
		std::cerr << "Warning: Failed to save launch token to ";
		std::cerr << "\"" << launch_token_path << "\"." << std::endl;
	}

	fclose(fp);

	return 0;
}




int main()
{
	/* initialize enclave */
	if(initialize_enclave() < 0)
	{
		std::cerr << "App: fatal error: Failed to initialize enclave.";
		std::cerr << std::endl;
		return -1;
	}


	/* Start main operation */
	uint8_t *message;
	uint8_t *sealed;
	uint8_t *unsealed;
	
	int policy, mode;


	/* Select sealing or unsealing to operate */
	std::cout << "Select sealing or unsealing to operate.\n" << std::endl;
	std::cout << "0: sealing, 1: unsealing" << std::endl;

	while(1)
	{
		std::cin >> mode;

		if(mode == 0 || mode == 1)
		{
			break;
		}

		std::cerr << "Invalid mode number." << std::endl;
		std::cerr << "Enter 0 for sealing, 1 for unsealing:" << std::endl;
	}



	/* Select MRENCLAVE or MRSIGNER for sealing policy */
	if(mode == 0)
	{
		std::cout << "\nEnter policy for sealing." << std::endl;
		std::cout << "0: MRENCLAVE, 1: MRSIGNER" << std::endl;
	}

	while(1)
	{
		if(mode == 1) break;

		std::cin >> policy;

		if(policy == MRENCLAVE || policy == MRSIGNER)
		{
			break;
		}

		std::cerr << "Invalid policy number." << std::endl;
		std::cerr << "Enter 0 for MRENCLAVE, 1 for MRSIGNER:" << std::endl;
	}

	
	if(mode == 1)
	{
		
	}
	else if(policy == 0)
	{
		std::cout << "\n\e[44mMRENCLAVE is selected.\e[0m\n" << std::endl;
	}
	else
	{
		std::cout << "\n\e[44mMRSIGNER is selected.\e[0m\n" << std::endl;
	}

	
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	int sealed_len;
	int message_len;

	switch(mode)
	{
		/* Sealing */
		case 0:
		{
			std::string message_str;

			std::cout << "\nEnter string to seal:\n" << std::flush;
			std::cin.ignore();
			std::getline(std::cin, message_str);
			std::cout << std::endl;


			message = (uint8_t*)message_str.c_str();
			message_len = strlen((char*)message);


			/* Estimate sealed length by ECALL-API */
			status = calc_sealed_len(global_eid, &sealed_len, message_len);
			sealed = new uint8_t[sealed_len];

			/* Execute sealing */
			status = do_sealing(global_eid, message, 
				message_len, sealed, sealed_len, policy);

			
			/* Output sealed data */
			std::ofstream ofs("sealed.dat", std::ios::binary);

			if(!ofs)
			{
				std::cerr << "Failed to open file for sealed data." << std::endl;
				return -1;
			}


			std::cout << "\nSealed data in hex:" << std::endl;
	
			for(int i = 0; i < sealed_len; i++)
			{
				std::cout << std::hex << (int)sealed[i];
			}

			std::cout << "\n" << std::endl;



			ofs.write((const char*)sealed, sealed_len);

			std::cout << "\nOutput sealed data to sealed.dat successfully.\n" << std::endl;

			break;
		}



		/* Unsealing */
		case 1:
		{
			/* Load sealed data from sealed.dat */
			std::ifstream ifs("sealed.dat", std::ios::binary);

			if(!ifs)
			{
				std::cerr << "Failed to open sealed.dat." << std::endl;
				return -1;
			}

			ifs.seekg(0, std::ios::end);
			sealed_len = ifs.tellg();
			ifs.seekg(0, std::ios::beg);

			sealed = new uint8_t[sealed_len];


			/* Convert ifstream to char array */
			ifs.read((char*)sealed, sealed_len);

					
			/* Estimate unsealed data length */
			int unsealed_len;
			status = calc_unsealed_len(global_eid, &unsealed_len,
				sealed, sealed_len);

			if(status != SGX_SUCCESS)
			{
				std::cerr << "Error occurred while unsealed length." << std::endl;
				sgx_error_print(status);

				return -1;
			}

			unsealed = new uint8_t[unsealed_len];


			/* Execute unsealing */
			int error_flag = 0;

			status = do_unsealing(global_eid, sealed, sealed_len,
				unsealed, unsealed_len, &error_flag);

			if(error_flag != 0)
			{
				std::cerr << "Failed to unseal secret." << std::endl;

				return -1;
			}

			
			/* Display unsealed secret */
			std::cout << "\n\e[44mUnsealed data is: ";
			std::cout.write((char*)unsealed, unsealed_len);
			std::cout << "\e[0m\n" << std::endl;

			break;
		}

		/* Cannot be reach here if there are no errors */
		default:
			std::cerr << "Fatal error: mode flag is corrupted." << std::endl;
			sgx_destroy_enclave(global_eid);

			return -1;
	}

	/* Destruct the enclave */
	sgx_destroy_enclave(global_eid);

	std::cout << "Operetations complete." << std::endl;

	return 0;
}
