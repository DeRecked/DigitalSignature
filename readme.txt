Digital Signature

***************************************************

Usage: program OPTION FILE1 FILE2

OPTION = "s" to sign file
		 "v" to verify integrity of "signed" file

FILE1 = file to sign/verify

FILE2 = signature file (not used in sign mode)

***************************************************

Signature mode will read in the private key from the rsa435 program as well as the file to be signed. The signature is saved as the signed filename with .signed appended.

Verify mode will read in the public key from the rsa435 program, the "signed" file, and the signature. The hash value of the signature will be compared to the hash of the "signed" file in order to determine the integrity of the file. 
