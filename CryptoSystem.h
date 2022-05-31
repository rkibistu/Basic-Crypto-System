/*
	CLASA CREATA PE PARCURSUL REZOLVARII LABORATOARELOR ANTERIOARE (de aceea sunt metode suplimentare)
*/

#pragma once
#define CRYPTO_SUCCES	1
#define CRYPTO_ERROR	0
#define CRYPTO_TAG_INVALID 2
#define CRYPTO_BAD_PARAMS 3

#define TAG_LENGTH 16
#define IV_LENGTH 20
#define CHACHA_MODIFIED_BLOCK_SIZE 20
#define REDUCED_POLY_LENGTH 16


#include <string>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>


typedef struct cryptoAtm_Data {

	ASN1_OCTET_STRING* encryptedData;
	ASN1_UTF8STRING* encryptionAlgorithm;
	ASN1_OCTET_STRING* signature;

}cryptoAtm_Data;

class CryptoSystem
{
private:

	unsigned char* _reducedPolynom;

	//reducere peste polinomul dat
	int PolynomReduction(unsigned char* buffer, int length = REDUCED_POLY_LENGTH);

	//pt decodificarea din base64
	int CalcDecodeLength(const char* b64input);

	/* adaugare padding conform PCKS#5*/
	int _add_padding(unsigned char** data, int& dataLen, int blockSize);
	void _increment_counter(unsigned char* counter, int position);

	//rotations (bufferLength - bits)
	int RotateLeft(unsigned char* buffer,int bufferLength,  int rotationValue);
	int RotateRight(unsigned char* buffer, int bufferLength, int rotationValue);
public:

	CryptoSystem();
	~CryptoSystem();

	int Encrypt_RC4(const unsigned char* plainText, int length, unsigned char* key, int keyLength, unsigned char** chiperText);
	int Decrypt_RC4(unsigned char* chiperText, int length, unsigned char* key, int keyLength, unsigned char** plainText);

	int Encrypt_chacha20(const unsigned char* plainText, int length, unsigned char* key, int keyLength, unsigned char** chiperText);
	int Decrypt_chacha20(unsigned char* chiperText, int length, unsigned char* key, int keyLength, unsigned char** plainText);

	int Encrypt_chacha20_tag(const unsigned char* plainText, int plainTextLength, unsigned char* key, int keyLength, const unsigned char* password, int passwordLength, unsigned char** chiperText, unsigned char* tag);
	int Decrypt_chacha20_tag(unsigned char* chiperText, int chiperTextLength, unsigned char* key, int keyLength, const unsigned char* password, int passwordLength, unsigned char** plainText, unsigned char* tag);

	int Encrypt_xor(const unsigned char* plainText, int plainTextLength, unsigned char* key, int lengthKey, unsigned char** chiperText);
	int Decrypt_xor(const unsigned char* chiperTexh, int chiperTextLength, unsigned char* key, int lengthKey, unsigned char** plainText);

	int Encrypt_aes256_gcm(const unsigned char* plainTexxt, int plainTextLength, unsigned char* key, int lengthKey, const unsigned char* pass, int passLength, unsigned char** chiperText, unsigned char* tag);
	int Decrypt_aes256_gcm(const unsigned char* chiperText, int chiperTextLength, unsigned char* key, int lengthKey, const unsigned char* pass, int passLength, unsigned char** plainText, unsigned char* tag);

	int Encrypt_aes192_gcm(const unsigned char* plainText, int plainTextLength, unsigned char* key, int lengthKey, const unsigned char* pass, int passLength, unsigned char** chiperText, unsigned char* tag);
	int Decrypt_aes192_gcm(const unsigned char* chiperText, int chiperTextLength, unsigned char* key, int lengthKey, const unsigned char* pass, int passLength, unsigned char** plainText, unsigned char* tag);

	int Encrypt_aes128_gcm(const unsigned char* plainText, int plainTextLength, unsigned char* key, int lengthKey, const unsigned char* pass, int passLength, unsigned char** chiperText, unsigned char* tag);
	int Decrypt_aes128_gcm(const unsigned char* chiperText, int chiperTextLength, unsigned char* key, int lengthKey, const unsigned char* pass, int passLength, unsigned char** plainText, unsigned char* tag);


	int Encrypt_aes_ecb(const unsigned char* plainText, int plainTextLength, unsigned char* key, int lengthKey, unsigned char** chiperText);
	int Decrypt_aes_ecb(const unsigned char* cipherText, int cipherTextLength, unsigned char* key, int lengthKey, unsigned char** plainText);

	int Encrypt_chacha20_cbc(unsigned char** plainText, int& length, unsigned char* key, int keyLength, unsigned char* iv, unsigned char** chiperText);
	int Decrypt_chacha20_cbc(unsigned char** chiperText, int& length, unsigned char* key, int keyLength, unsigned char* iv, unsigned char** plainText);

	int Encrypt_chacha20_ctr(unsigned char** pData, int& dataLen, unsigned char* counter, unsigned char* key, int lengthKey, unsigned char** encData);
	int Decrypt_chacha20_ctr(unsigned char** encData, int& dataLen, unsigned char* counter, unsigned char* key, int lengthKey, unsigned char** pData);

	int Encrypt_chacha20_ofb(unsigned char** pData, int& dataLen, unsigned char* iv, unsigned char* key, int keyLength, unsigned char** encData);
	int Decrypt_chacha20_ofb(unsigned char** encData, int& dataLen, unsigned char* iv, unsigned char* key, int keyLength, unsigned char** pData);

	int Encrypt_chacha20_cfb(unsigned char** pData, int& dataLen, unsigned char* iv, unsigned char* key, int keyLength, unsigned char** encData);
	int Decrypt_chacha20_cfb(unsigned char** encData, int& dataLen, unsigned char* iv, unsigned char* key, int keyLength, unsigned char** pData);

	int Encrypt_chacha20_ige(unsigned char** pData, int& dataLen, unsigned char* iv, unsigned char* iv2, unsigned char* key, int keyLength, unsigned char** encData);
	int Decrypt_chacha20_ige(unsigned char** encData, int& dataLen, unsigned char* iv, unsigned char* iv2, unsigned char* key, int keyLength, unsigned char** pData);

	int ConvertToBase64(unsigned char* bits, int length, char** b64text, int& b64length);
	int ConvertFromBase64(char* b64message, unsigned char** buffer, int& length);

	//specifice pentru Tema1 de aici in jos
	int CalculateHash(unsigned char* cipherText, int cipherTextLength, unsigned char** hash, int hashLength);
	int SignHash(unsigned char* hash, int hashLength, unsigned char* tag, int tagLength, unsigned char* key, int keyLength, unsigned char** signature);
	int SaveFinalData(char* filename, unsigned char* encryptedData, int encryptedDataLength, char* algorithm, int algorithmLength, unsigned char* signature, int signatureLength);
	int LoadFinalData(char* filename, unsigned char** encryptedData, int& encryptedDatalength, char** algorithm, int& algorithmLength, unsigned char** signature, int& signatureLength);

};

