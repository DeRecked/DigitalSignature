// Include standard libraries
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>

// Include Big Integer and sha256 libraries
#include "BigIntegerLibrary.hh"
#include "sha256.hh"

int main(int argc, char** argv) {
	try {
		char* buf;											// Char pointer for reading in data
		bool sign = false;									// Flags to control program operation
		bool verify = false;								
		std::string input_name, signature_name, line_in;	// File names
		
		// Parse CLI arguments
		if (argc >= 2) {
			if ((strcmp(argv[1], "s") == 0) && argv[2])
				sign = true;
			else if ((strcmp(argv[1], "v") == 0) && argv[2] && argv[3])
				verify = true;
			else throw "Usage: ./sign OPERATION FILE1 FILE2\nOPERATION = \"s\" to sign a file or \"v\" to verify integrity of signed file\nFILE1 = file to sign/verify\nFILE2 = signature used when verifying";
		}
		else throw "Usage: ./sign OPERATION FILE1 FILE2\nOPERATION = \"s\" to sign a file or \"v\" to verify integrity of signed file\nFILE1 = file to sign/verify\nFILE2 = signature used when verifying";

		// Read and sign a file
		if (sign) {
			std::cout << "\nSigning file" << std::endl;
			
			// Set filename of input file stream and open stream
			input_name = argv[2];
			std::ifstream input_file(input_name.c_str(), std::ios::binary);

			// Set filename of signature output file and open stream
			signature_name = argv[2];
			signature_name += ".signature";					// Append .signature to signature file name
			std::ofstream signature_file(signature_name.c_str(), std::ios::binary);
			std::ifstream private_key("d_n.txt", std::ios::binary);
			
			// Read in d from private key
			getline(private_key, line_in);
			BigUnsigned d = stringToBigUnsigned(line_in);
			line_in = "";

			// Read in n from private key
			getline(private_key, line_in);
			BigUnsigned n = stringToBigUnsigned(line_in);
			private_key.close();

			// Determine size of input file
			std::streampos begin = input_file.tellg();		// Beginning position
			input_file.seekg(0, std::ios::end);				// Go to EOF
			std::streampos end = input_file.tellg();		// End position
			std::streampos size = end - begin;				// size (bytes) = difference in positions
			input_file.seekg(0, std::ios::beg);				// Return to beginning
			
			buf = new char[size];							// Allocate memory for char array large enough to hold input file
			
			// Read in file contents and close stream
			input_file.read(buf, size);
			buf[size] = '\0';								// Append with null char
			input_file.close();

			// Assign buff to string and call sha256 to return hash of input file
			std::string str(buf);	
			std::string str_hash = sha256(str);

			// Convert string of hash to BigInteger
			BigInteger hash = stringToBigInteger_base16(str_hash);
			
			// Signature = (hash^d) % n
			BigUnsigned signature = modexp(hash, d, n);

			//Save signature to file and close stream
			signature_file << signature;
			signature_file.close();
			std::cout << "Signature generated and saved" << std::endl;
		}

		// Read and verify integrity of signed file
		else if (verify) {
			std::cout << "\nVerifying signed file" << std::endl;

			input_name = argv[2];
			std::ifstream input_file(input_name.c_str(), std::ios::binary);

			signature_name = argv[3];
			std::ifstream signature_file(signature_name.c_str(), std::ios::binary);
			std::ifstream public_key("e_n.txt", std::ios::binary);

			// Read in d from private key
			getline(public_key, line_in);
			BigUnsigned e = stringToBigUnsigned(line_in);
			line_in = "";

			// Read in n from private key
			getline(public_key, line_in);
			BigUnsigned n = stringToBigUnsigned(line_in);
			public_key.close();

			// Determine size of input file
			std::streampos begin = input_file.tellg();		// Beginning position
			input_file.seekg(0, std::ios::end);				// Go to EOF
			std::streampos end = input_file.tellg();		// End position
			std::streampos size = end - begin;				// size (bytes) = difference in positions
			input_file.seekg(0, std::ios::beg);				// Return to beginning

			buf = new char[size];							// Allocate memory for char array large enough to hold input file

			// Read in file contents and close stream
			input_file.read(buf, size);
			buf[size] = '\0';								// Append with null char
			input_file.close();

			// Assign buff to string and call sha256 to return hash of input file
			std::string str(buf);
			std::string str_hash = sha256(str);

			// Convert string of hash to BigInteger
			BigUnsigned input_hash = stringToBigUnsigned_base16(str_hash);

			// Get signature from file and close stream
			getline(signature_file, line_in);
			signature_file.close();

			// Convert signature string to BigInt
			BigInteger signature = stringToBigInteger(line_in);

			// original hash = (signature^e) % n
			BigUnsigned verify_hash = modexp(signature, e, n);

			if (input_hash == verify_hash)
				std::cout << "The hash values are equal. File has not changed" << std::endl;
			else std::cout << "The hash values are NOT equal. The file has been changed" << std::endl;
		}

		// This should never happen
		else throw "Unknown error";
	}
	catch(char const* err) {
		std::cout << "The library threw an exception:\n" << err << std::endl;
	}

	return 0;
}
