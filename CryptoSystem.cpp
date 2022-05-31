#pragma warning(disable : 4996)


#include "CryptoSystem.h"
#include "AsnStructures.h"

#include <openssl/rc4.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string>
#include <openssl/buffer.h>
#include <openssl/bio.h>


ASN1_SEQUENCE(cryptoAtm_Data) = {
	ASN1_SIMPLE(cryptoAtm_Data,encryptedData,ASN1_OCTET_STRING),
	ASN1_SIMPLE(cryptoAtm_Data,encryptionAlgorithm,ASN1_UTF8STRING),
	ASN1_SIMPLE(cryptoAtm_Data,signature,ASN1_OCTET_STRING)

}ASN1_SEQUENCE_END(cryptoAtm_Data);
DECLARE_ASN1_FUNCTIONS(cryptoAtm_Data);
IMPLEMENT_ASN1_FUNCTIONS(cryptoAtm_Data);

CryptoSystem::CryptoSystem() {

	_reducedPolynom = new unsigned char[REDUCED_POLY_LENGTH];
	memset(_reducedPolynom, 0x00, REDUCED_POLY_LENGTH);

	_reducedPolynom[15] |= 1UL << 0; //	x^127
	_reducedPolynom[0] |= 1UL << 0;  //	x^7
	_reducedPolynom[0] |= 1UL << 2;	 //	x^2
	_reducedPolynom[0] |= 1UL << 7;	 // x^0
}
CryptoSystem::~CryptoSystem() {

	delete _reducedPolynom;
	_reducedPolynom = nullptr;
}

int CryptoSystem::Encrypt_RC4(const unsigned char* plainText, int length, unsigned char* key, int keyLength, unsigned char** chiperText) {

	RC4_KEY keyRC4;

	*chiperText = new unsigned char[length];

	RC4_set_key(&keyRC4, keyLength, key);
	RC4(&keyRC4, length, plainText, *chiperText);

	return CRYPTO_SUCCES;
}
int CryptoSystem::Decrypt_RC4(unsigned char* chiperText, int length, unsigned char* key, int keyLength, unsigned char** plainText) {

	RC4_KEY keyRC4;

	*plainText = new unsigned char[length];

	RC4_set_key(&keyRC4, keyLength, (const unsigned char*)key);
	RC4(&keyRC4, length, chiperText, *plainText);

	return CRYPTO_SUCCES;
}

int CryptoSystem::Encrypt_chacha20(const unsigned char* plainText, int plainTextLength, unsigned char* key, int keyLength, unsigned char** chiperText) {

	unsigned char iv[EVP_MAX_IV_LENGTH + 1] = { 0 };
	int length = 0, finalLength = 0;
	int res;


	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx == nullptr) {

		return CRYPTO_ERROR;
	}

	res = EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, NULL);
	if (res != 1) {

		unsigned long x = ERR_get_error();
		ERR_GET_REASON(x);
		char buffer[10000];
		ERR_error_string(x, buffer);
		return CRYPTO_ERROR;
	}

	*chiperText = new unsigned char[plainTextLength];
	if (chiperText == nullptr) {

		EVP_CIPHER_CTX_free(ctx);
		return CRYPTO_ERROR;
	}

	res = EVP_EncryptUpdate(ctx, *chiperText, &length, (unsigned char*)plainText, plainTextLength);
	if (res != 1) {
		EVP_CIPHER_CTX_free(ctx);
		delete chiperText;
		return CRYPTO_ERROR;
	}

	if (length != plainTextLength) {

		printf("VEZI CA NU A CRIPTAAT TOT!!! AI NEVOIE SI DE FINAL!");
	}

	EVP_CIPHER_CTX_free(ctx);
}
int CryptoSystem::Decrypt_chacha20(unsigned char* chiperText, int chiperTextLength, unsigned char* key, int keyLength, unsigned char** plainText) {

	unsigned char iv[EVP_MAX_IV_LENGTH + 1] = { 0 };
	int length = 0, finalLength = 0;
	int res;


	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx == nullptr) {

		return CRYPTO_ERROR;
	}

	res = EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, key, NULL);
	if (res != 1) {

		unsigned long x = ERR_get_error();
		ERR_GET_REASON(x);
		char buffer[10000];
		ERR_error_string(x, buffer);
		return CRYPTO_ERROR;
	}

	*plainText = new unsigned char[chiperTextLength];
	if (plainText == nullptr) {

		EVP_CIPHER_CTX_free(ctx);
		return CRYPTO_ERROR;
	}

	res = EVP_DecryptUpdate(ctx, *plainText, &length, chiperText, chiperTextLength);
	if (res != 1) {
		EVP_CIPHER_CTX_free(ctx);
		delete chiperText;
		return CRYPTO_ERROR;
	}

	if (length != chiperTextLength) {

		printf("VEZI CA NU A DECRIPTAAT TOT!!! AI NEVOIE SI DE FINAL!");
	}

	EVP_CIPHER_CTX_free(ctx);
}

int CryptoSystem::Encrypt_chacha20_tag(const unsigned char* plainText, int plainTextLength, unsigned char* key, int keyLength, const unsigned char* password, int passwordLength, unsigned char** chiperText, unsigned char* tag) {

	unsigned char iv[EVP_MAX_IV_LENGTH + 1] = { 0 };
	int length = 0, finalLength = 0;
	int lenTag = 0;
	int res;


	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx == nullptr) {

		return CRYPTO_ERROR;
	}

	res = EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, NULL);
	if (res != 1) {

		unsigned long x = ERR_get_error();
		ERR_GET_REASON(x);
		char buffer[10000];
		ERR_error_string(x, buffer);
		return CRYPTO_ERROR;
	}

	*chiperText = new unsigned char[plainTextLength];
	if (chiperText == nullptr) {

		EVP_CIPHER_CTX_free(ctx);
		return CRYPTO_ERROR;
	}

	//auth data for tag
	res = EVP_EncryptUpdate(ctx, nullptr, &lenTag, password, passwordLength);
	if (res != 1) {
		EVP_CIPHER_CTX_free(ctx);
		delete chiperText;
		return CRYPTO_ERROR;
	}

	res = EVP_EncryptUpdate(ctx, *chiperText, &length, (unsigned char*)plainText, plainTextLength);
	if (res != 1) {
		EVP_CIPHER_CTX_free(ctx);
		delete chiperText;
		return CRYPTO_ERROR;
	}

	if (length != plainTextLength) {

		printf("VEZI CA NU A CRIPTAAT TOT!!! AI NEVOIE SI DE FINAL!");
	}

	//calculeaza tag
	res = EVP_EncryptFinal(ctx, *chiperText + length, &finalLength);
	if (res != 1) {
		printf("ERROR TAG calculate\n");
		EVP_CIPHER_CTX_free(ctx);
		delete chiperText;
		return CRYPTO_ERROR;
	}
	//get tag
	res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LENGTH, tag);
	if (res != 1) {
		printf("ERROR TAG get\n");
		EVP_CIPHER_CTX_free(ctx);
		delete chiperText;
		return CRYPTO_ERROR;
	}

	EVP_CIPHER_CTX_free(ctx);
}
int CryptoSystem::Decrypt_chacha20_tag(unsigned char* chiperText, int chiperTextLength, unsigned char* key, int keyLength, const unsigned char* password, int passwordLength, unsigned char** plainText, unsigned char* tag) {

	unsigned char iv[EVP_MAX_IV_LENGTH + 1] = { 0 };
	int length = 0, finalLength = 0;
	int lenTag = 0;
	int res;


	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx == nullptr) {

		return CRYPTO_ERROR;
	}


	res = EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, NULL);
	if (res != 1) {

		unsigned long x = ERR_get_error();
		ERR_GET_REASON(x);
		char buffer[10000];
		ERR_error_string(x, buffer);
		return CRYPTO_ERROR;
	}

	*plainText = new unsigned char[chiperTextLength];
	if (plainText == nullptr) {

		EVP_CIPHER_CTX_free(ctx);
		return CRYPTO_ERROR;
	}

	//auth data for tag
	res = EVP_DecryptUpdate(ctx, nullptr, &lenTag, password, passwordLength);
	if (res != 1) {
		EVP_CIPHER_CTX_free(ctx);
		delete chiperText;
		return CRYPTO_ERROR;
	}

	res = EVP_DecryptUpdate(ctx, *plainText, &length, chiperText, chiperTextLength);
	if (res != 1) {
		EVP_CIPHER_CTX_free(ctx);
		delete chiperText;
		return CRYPTO_ERROR;
	}

	if (length != chiperTextLength) {

		printf("VEZI CA NU A DECRIPTAAT TOT!!! AI NEVOIE SI DE FINAL!");
	}

	//se introduce authTag
	res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LENGTH, tag);
	if (res != 1) {
		//printf("ERROR TAG set\n");
		EVP_CIPHER_CTX_free(ctx);
		delete chiperText;
		return CRYPTO_TAG_INVALID;
	}

	res = EVP_DecryptFinal(ctx, *plainText + length, &finalLength);
	if (res != 1) {
		//printf("ERROR TAG verify\n");
		EVP_CIPHER_CTX_free(ctx);
		delete chiperText;
		return CRYPTO_TAG_INVALID;
	}
	else {
		printf("Tagul e bun!\n");
	}


	EVP_CIPHER_CTX_free(ctx);
	return CRYPTO_SUCCES;
}


int CryptoSystem::Encrypt_xor(const unsigned char* plainText, int length, unsigned char* key, int lengthKey, unsigned char** chiperText) {

	*chiperText = new unsigned char[length];
	for (int i = 0; i < length; i++) {

		(*chiperText)[i] = plainText[i] ^ key[i % lengthKey];
	}

	return CRYPTO_SUCCES;
}
int CryptoSystem::Decrypt_xor(const unsigned char* chiperTexh, int length, unsigned char* key, int lengthKey, unsigned char** plainText) {

	*plainText = new unsigned char[length];
	for (int i = 0; i < length; i++) {

		(*plainText)[i] = chiperTexh[i] ^ key[i % lengthKey];
	}
	return CRYPTO_SUCCES;
}

int CryptoSystem::Encrypt_aes256_gcm(const unsigned char* plainText, int plainTextLength, unsigned char* key, int lengthKey, const unsigned char* pass, int passLength, unsigned char** chiperText, unsigned char* tag) {

	unsigned char* iv = new unsigned char[16];
	int lenUpdate, lenFinal, lenTag, res;

	memset(iv, 0x00, 16);
	*chiperText = new unsigned char[plainTextLength];

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	//stabileste algoritmul folosit
	res = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
	if (res != 1) {
		printf("aes256 init1\n");
		return CRYPTO_ERROR;
	}
	//stabileste cheia si IV-ul 
	res = EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
	if (res != 1) {
		printf("aes256 init2\n");
		return CRYPTO_ERROR;
	}

	//se introduce authentication data pt calcularaea tag-ului
	res = EVP_EncryptUpdate(ctx, nullptr, &lenTag, pass, passLength);
	if (res != 1) {
		printf("aes256 update1\n");
		return CRYPTO_ERROR;
	}

	//se cripteaza datele (toate datele, fiind modul GCM)
	res = EVP_EncryptUpdate(ctx, *chiperText, &lenUpdate, plainText, plainTextLength);
	if (res != 1) {
		printf("aes256 update2\n");
		return CRYPTO_ERROR;
	}

	//se calculeaza tag-ul
	res = EVP_EncryptFinal(ctx, *chiperText + lenUpdate, &lenFinal);
	if (res != 1) {
		printf("aes256 final\n");
		return CRYPTO_ERROR;
	}

	//se extrage tag-ul
	res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LENGTH, tag);
	if (res != 1) {
		printf("aes256 get tag\n");
		return CRYPTO_ERROR;
	}

	return CRYPTO_SUCCES;
}
int CryptoSystem::Decrypt_aes256_gcm(const unsigned char* chiperText, int chiperTextLength, unsigned char* key, int lengthKey, const unsigned char* pass, int passLength, unsigned char** plainText, unsigned char* tag) {

	unsigned char* iv = new unsigned char[16];
	int lenUpdate, lenFinal, lenTag, res;

	memset(iv, 0x00, 16);
	*plainText = new unsigned char[chiperTextLength];

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	//stabileste algoritmul folosit
	res = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
	if (res != 1) {
		printf("aes256 init1\n");
		return CRYPTO_ERROR;
	}
	//stabileste cheia si IV-ul 
	res = EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);
	if (res != 1) {
		printf("aes256 init2\n");
		return CRYPTO_ERROR;
	}

	//se introduce authentication data pt calcularaea tag-ului
	res = EVP_DecryptUpdate(ctx, nullptr, &lenTag, pass, passLength);
	if (res != 1) {
		printf("aes256 update1\n");
		return CRYPTO_ERROR;
	}

	//se cripteaza datele (toate datele, fiind modul GCM)
	res = EVP_DecryptUpdate(ctx, *plainText, &lenUpdate, chiperText, chiperTextLength);
	if (res != 1) {
		printf("aes256 update2\n");
		return CRYPTO_ERROR;
	}

	//se extrage tag-ul
	res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LENGTH, tag);
	if (res != 1) {
		//printf("aes256 get tag\n");
		return CRYPTO_TAG_INVALID;
	}

	//se calculeaza tag-ul
	res = EVP_DecryptFinal(ctx, *plainText + lenUpdate, &lenFinal);
	if (res != 1) {

		//printf("aes256 final\n");
		return CRYPTO_TAG_INVALID;
	}


	return CRYPTO_SUCCES;
}

int CryptoSystem::Encrypt_aes192_gcm(const unsigned char* plainText, int plainTextLength, unsigned char* key, int lengthKey, const unsigned char* pass, int passLength, unsigned char** chiperText, unsigned char* tag) {

	unsigned char* iv = new unsigned char[16];
	int lenUpdate, lenFinal, lenTag, res;

	memset(iv, 0x00, 16);
	*chiperText = new unsigned char[plainTextLength];

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	//stabileste algoritmul folosit
	res = EVP_EncryptInit_ex(ctx, EVP_aes_192_gcm(), nullptr, nullptr, nullptr);
	if (res != 1) {
		printf("aes256 init1\n");
		return CRYPTO_ERROR;
	}
	//stabileste cheia si IV-ul 
	res = EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
	if (res != 1) {
		printf("aes256 init2\n");
		return CRYPTO_ERROR;
	}

	//se introduce authentication data pt calcularaea tag-ului
	res = EVP_EncryptUpdate(ctx, nullptr, &lenTag, pass, passLength);
	if (res != 1) {
		printf("aes256 update1\n");
		return CRYPTO_ERROR;
	}

	//se cripteaza datele (toate datele, fiind modul GCM)
	res = EVP_EncryptUpdate(ctx, *chiperText, &lenUpdate, plainText, plainTextLength);
	if (res != 1) {
		printf("aes256 update2\n");
		return CRYPTO_ERROR;
	}

	//se calculeaza tag-ul
	res = EVP_EncryptFinal(ctx, *chiperText + lenUpdate, &lenFinal);
	if (res != 1) {
		printf("aes256 final\n");
		return CRYPTO_ERROR;
	}

	//se extrage tag-ul
	res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LENGTH, tag);
	if (res != 1) {
		printf("aes256 get tag\n");
		return CRYPTO_ERROR;
	}

	return CRYPTO_SUCCES;
}
int CryptoSystem::Decrypt_aes192_gcm(const unsigned char* chiperText, int chiperTextLength, unsigned char* key, int lengthKey, const unsigned char* pass, int passLength, unsigned char** plainText, unsigned char* tag) {

	unsigned char* iv = new unsigned char[16];
	int lenUpdate, lenFinal, lenTag, res;

	memset(iv, 0x00, 16);
	*plainText = new unsigned char[chiperTextLength];

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	//stabileste algoritmul folosit
	res = EVP_DecryptInit_ex(ctx, EVP_aes_192_gcm(), nullptr, nullptr, nullptr);
	if (res != 1) {
		printf("aes256 init1\n");
		return CRYPTO_ERROR;
	}
	//stabileste cheia si IV-ul 
	res = EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);
	if (res != 1) {
		printf("aes256 init2\n");
		return CRYPTO_ERROR;
	}

	//se introduce authentication data pt calcularaea tag-ului
	res = EVP_DecryptUpdate(ctx, nullptr, &lenTag, pass, passLength);
	if (res != 1) {
		printf("aes256 update1\n");
		return CRYPTO_ERROR;
	}

	//se cripteaza datele (toate datele, fiind modul GCM)
	res = EVP_DecryptUpdate(ctx, *plainText, &lenUpdate, chiperText, chiperTextLength);
	if (res != 1) {
		printf("aes256 update2\n");
		return CRYPTO_ERROR;
	}

	//se extrage tag-ul
	res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LENGTH, tag);
	if (res != 1) {
		//printf("aes256 get tag\n");
		return CRYPTO_TAG_INVALID;
	}

	//se calculeaza tag-ul
	res = EVP_DecryptFinal(ctx, *plainText + lenUpdate, &lenFinal);
	if (res != 1) {

		//printf("aes256 final\n");
		return CRYPTO_TAG_INVALID;
	}


	return CRYPTO_SUCCES;
}

int CryptoSystem::Encrypt_aes128_gcm(const unsigned char* plainText, int plainTextLength, unsigned char* key, int lengthKey, const unsigned char* pass, int passLength, unsigned char** chiperText, unsigned char* tag) {

	unsigned char* iv = new unsigned char[16];
	int lenUpdate, lenFinal, lenTag, res;

	memset(iv, 0x00, 16);
	*chiperText = new unsigned char[plainTextLength];

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	//stabileste algoritmul folosit
	res = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
	if (res != 1) {
		printf("aes256 init1\n");
		return CRYPTO_ERROR;
	}
	//stabileste cheia si IV-ul 
	res = EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
	if (res != 1) {
		printf("aes256 init2\n");
		return CRYPTO_ERROR;
	}

	//se introduce authentication data pt calcularaea tag-ului
	res = EVP_EncryptUpdate(ctx, nullptr, &lenTag, pass, passLength);
	if (res != 1) {
		printf("aes256 update1\n");
		return CRYPTO_ERROR;
	}

	//se cripteaza datele (toate datele, fiind modul GCM)
	res = EVP_EncryptUpdate(ctx, *chiperText, &lenUpdate, plainText, plainTextLength);
	if (res != 1) {
		printf("aes256 update2\n");
		return CRYPTO_ERROR;
	}

	//se calculeaza tag-ul
	res = EVP_EncryptFinal(ctx, *chiperText + lenUpdate, &lenFinal);
	if (res != 1) {
		printf("aes256 final\n");
		return CRYPTO_ERROR;
	}

	//se extrage tag-ul
	res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LENGTH, tag);
	if (res != 1) {
		printf("aes256 get tag\n");
		return CRYPTO_ERROR;
	}

	return CRYPTO_SUCCES;
}
int CryptoSystem::Decrypt_aes128_gcm(const unsigned char* chiperText, int chiperTextLength, unsigned char* key, int lengthKey, const unsigned char* pass, int passLength, unsigned char** plainText, unsigned char* tag) {

	unsigned char* iv = new unsigned char[16];
	int lenUpdate, lenFinal, lenTag, res;

	memset(iv, 0x00, 16);
	*plainText = new unsigned char[chiperTextLength];

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	//stabileste algoritmul folosit
	res = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
	if (res != 1) {
		printf("aes256 init1\n");
		return CRYPTO_ERROR;
	}
	//stabileste cheia si IV-ul 
	res = EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);
	if (res != 1) {
		printf("aes256 init2\n");
		return CRYPTO_ERROR;
	}

	//se introduce authentication data pt calcularaea tag-ului
	res = EVP_DecryptUpdate(ctx, nullptr, &lenTag, pass, passLength);
	if (res != 1) {
		printf("aes256 update1\n");
		return CRYPTO_ERROR;
	}

	//se cripteaza datele (toate datele, fiind modul GCM)
	res = EVP_DecryptUpdate(ctx, *plainText, &lenUpdate, chiperText, chiperTextLength);
	if (res != 1) {
		printf("aes256 update2\n");
		return CRYPTO_ERROR;
	}

	//se extrage tag-ul
	res = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LENGTH, tag);
	if (res != 1) {
		//printf("aes256 get tag\n");
		return CRYPTO_TAG_INVALID;
	}

	//se calculeaza tag-ul
	res = EVP_DecryptFinal(ctx, *plainText + lenUpdate, &lenFinal);
	if (res != 1) {

		//printf("aes256 final\n");
		return CRYPTO_TAG_INVALID;
	}


	return CRYPTO_SUCCES;
}


int CryptoSystem::Encrypt_aes_ecb(const unsigned char* plainText, int plainTextLength, unsigned char* key, int lengthKey, unsigned char** chiperText) {

	int length, finalLength;
	int res;

	//creem context
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	//setam cheie si iv
	res = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr);
	if (res != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return CRYPTO_ERROR;
	}

	//criptam toate blocurile, exceptie ultimul
	*chiperText = new unsigned char[plainTextLength];
	res = EVP_EncryptUpdate(ctx, *chiperText, &length, plainText, plainTextLength);
	if (res != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return CRYPTO_ERROR;
	}

	//criptam ultimul block daca e cazul
	if (length != plainTextLength) {

		res = EVP_EncryptFinal(ctx, *chiperText + length, &finalLength);
		if (res != 1) {
			EVP_CIPHER_CTX_free(ctx);
			return CRYPTO_ERROR;
		}
	}


	return CRYPTO_SUCCES;
}
int CryptoSystem::Decrypt_aes_ecb(const unsigned char* cipherText, int cipherTextLength, unsigned char* key, int lengthKey, unsigned char** plainText) {

	int length, finalLength;
	int res;

	//creem context
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	//setam cheie si iv
	res = EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr);
	if (res != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return CRYPTO_ERROR;
	}

	//criptam toate blocurile, exceptie ultimul
	*plainText = new unsigned char[cipherTextLength];
	res = EVP_DecryptUpdate(ctx, *plainText, &length, cipherText, cipherTextLength);
	if (res != 1) {
		EVP_CIPHER_CTX_free(ctx);
		delete* plainText;
		return CRYPTO_ERROR;
	}

	//criptam ultimul block daca e cazul
	res = EVP_DecryptFinal(ctx, *plainText + length, &finalLength);
	if (res != 1) {
		EVP_CIPHER_CTX_free(ctx);
		delete* plainText;
		return CRYPTO_ERROR;
	}

	return CRYPTO_SUCCES;
}


int CryptoSystem::Encrypt_chacha20_cbc(unsigned char** plainText, int& length, unsigned char* key, int keyLength, unsigned char* iv, unsigned char** chiperText) {

	int status = CRYPTO_SUCCES;
	unsigned char inblk[CHACHA_MODIFIED_BLOCK_SIZE];
	unsigned char* outblk = nullptr;
	int offset = 0;

	int dataLen = length;

	status = _add_padding(plainText, dataLen, CHACHA_MODIFIED_BLOCK_SIZE);
	if (status != CRYPTO_SUCCES)
		return status;

	(*chiperText) = (unsigned char*)malloc(dataLen);
	if (*chiperText == NULL)
		return CRYPTO_ERROR;

	//criptez  AES CBC fiecare bloc 
	while (offset < dataLen)
	{
		memcpy(inblk, (*plainText) + offset, CHACHA_MODIFIED_BLOCK_SIZE);
		//fac XOR intre IV si blocul de intrare 
		for (int i = 0; i < CHACHA_MODIFIED_BLOCK_SIZE; i++)
			inblk[i] = inblk[i] ^ iv[i];

		//AES_encrypt(inblk, outblk, &aesKey);
		//add chahcha encrypt
		if (outblk != nullptr) {
			delete outblk;
			outblk = nullptr;
		}
		Encrypt_chacha20(inblk, CHACHA_MODIFIED_BLOCK_SIZE, key, keyLength, &outblk);

		memcpy((*chiperText) + offset, outblk, CHACHA_MODIFIED_BLOCK_SIZE);

		//copiez in bufferul iv ciphertext-ul curent pt a face XOR cu urmatorul bloc de intrare 
		memcpy(iv, outblk, CHACHA_MODIFIED_BLOCK_SIZE);
		offset += CHACHA_MODIFIED_BLOCK_SIZE;
	}

	length = dataLen;
	return CRYPTO_SUCCES;;
}
int CryptoSystem::Decrypt_chacha20_cbc(unsigned char** chiperText, int& length, unsigned char* key, int keyLength, unsigned char* iv, unsigned char** plainText) {


	unsigned char inblk[CHACHA_MODIFIED_BLOCK_SIZE];
	unsigned char* outblk = nullptr;
	int offset = 0;

	(*plainText) = (unsigned char*)malloc(length);
	if (*plainText == NULL)
		return CRYPTO_ERROR;

	//criptez  AES CBC fiecare bloc 
	while (offset < length)
	{
		memcpy(inblk, (*chiperText) + offset, CHACHA_MODIFIED_BLOCK_SIZE);

		//AES_decrypt(inblk, outblk, &aesKey);
		if (outblk != nullptr) {
			delete outblk;
			outblk = nullptr;
		}
		Decrypt_chacha20(inblk, CHACHA_MODIFIED_BLOCK_SIZE, key, keyLength, &outblk);

		//fac XOR intre IV si blocul de intrare 
		for (int i = 0; i < CHACHA_MODIFIED_BLOCK_SIZE; i++)
			outblk[i] = outblk[i] ^ iv[i];

		memcpy((*plainText) + offset, outblk, CHACHA_MODIFIED_BLOCK_SIZE);

		//copiez in bufferul iv ciphertext-ul curent pt a face XOR cu urmatorul bloc de intrare 
		memcpy(iv, (*chiperText) + offset, CHACHA_MODIFIED_BLOCK_SIZE);
		offset += CHACHA_MODIFIED_BLOCK_SIZE;
	}

	int remove = ((*plainText)[length - 1]);
	length -= remove;

	(*plainText) = (unsigned char*)realloc(*plainText, length);


	return CRYPTO_SUCCES;
}

int CryptoSystem::Encrypt_chacha20_ctr(unsigned char** pData, int& dataLen, unsigned char* counter, unsigned char* key, int lengthKey, unsigned char** encData)
{

	unsigned char inblk[CHACHA_MODIFIED_BLOCK_SIZE];
	unsigned char* outblk = nullptr;
	int offset = 0;
	int status;
	;

	status = _add_padding(pData, dataLen, CHACHA_MODIFIED_BLOCK_SIZE);
	if (status != CRYPTO_SUCCES)
		return status;

	(*encData) = (unsigned char*)malloc(dataLen);
	if (*encData == NULL)
		return CRYPTO_ERROR;

	//criptez  AES CTR fiecare bloc 
	while (offset < dataLen)
	{
		memcpy(inblk, (*pData) + offset, CHACHA_MODIFIED_BLOCK_SIZE);

		if (outblk != nullptr) {
			delete outblk;
			outblk = nullptr;
		}
		Encrypt_chacha20(counter, CHACHA_MODIFIED_BLOCK_SIZE, key, lengthKey, &outblk);

		//fac XOR intre blocul de iesire si blocul de date 
		for (int i = 0; i < CHACHA_MODIFIED_BLOCK_SIZE; i++)
			outblk[i] = outblk[i] ^ inblk[i];

		memcpy((*encData) + offset, outblk, CHACHA_MODIFIED_BLOCK_SIZE);

		//incrementez counter-ul pe 16 bytes
		_increment_counter(counter, CHACHA_MODIFIED_BLOCK_SIZE - 1);
		offset += CHACHA_MODIFIED_BLOCK_SIZE;
	}




	return CRYPTO_SUCCES;
}
int CryptoSystem::Decrypt_chacha20_ctr(unsigned char** encData, int& dataLen, unsigned char* counter, unsigned char* key, int lengthKey, unsigned char** pData) {

	int status = CRYPTO_SUCCES;;

	unsigned char inblk[CHACHA_MODIFIED_BLOCK_SIZE];
	unsigned char* outblk = nullptr;
	int offset = 0;


	(*pData) = (unsigned char*)malloc(dataLen);
	if (*pData == NULL)
		return CRYPTO_ERROR;

	//criptez  AES CTR fiecare bloc 
	while (offset < dataLen)
	{
		memcpy(inblk, (*encData) + offset, CHACHA_MODIFIED_BLOCK_SIZE);

		if (outblk != nullptr) {
			delete outblk;
			outblk = nullptr;
		}
		Encrypt_chacha20(counter, CHACHA_MODIFIED_BLOCK_SIZE, key, lengthKey, &outblk);

		//fac XOR intre blocul de iesire si blocul de date 
		for (int i = 0; i < CHACHA_MODIFIED_BLOCK_SIZE; i++)
			outblk[i] = outblk[i] ^ inblk[i];

		memcpy((*pData) + offset, outblk, CHACHA_MODIFIED_BLOCK_SIZE);

		//incrementez counter-ul pe 16 bytes
		_increment_counter(counter, CHACHA_MODIFIED_BLOCK_SIZE - 1);
		offset += CHACHA_MODIFIED_BLOCK_SIZE;
	}

	int remove = (*pData)[dataLen - 1];
	dataLen -= remove;
	(*pData) = (unsigned char*)realloc(*pData, dataLen);

	return CRYPTO_SUCCES;
}

int CryptoSystem::Encrypt_chacha20_ofb(unsigned char** pData, int& dataLen, unsigned char* iv, unsigned char* key, int keyLength, unsigned char** encData)
{
	int status = CRYPTO_SUCCES;
	unsigned char inblk[CHACHA_MODIFIED_BLOCK_SIZE];
	unsigned char* outblk = nullptr;
	int offset = 0;

	status = _add_padding(pData, dataLen, CHACHA_MODIFIED_BLOCK_SIZE);
	if (status != CRYPTO_SUCCES)
		return status;

	(*encData) = (unsigned char*)malloc(dataLen);
	if (*encData == NULL)
		return CRYPTO_ERROR;

	//criptez  AES CBC fiecare bloc 
	while (offset < dataLen)
	{
		//AES_encrypt(iv, outblk, &aesKey);
		if (outblk != nullptr) {
			delete outblk;
			outblk = nullptr;
		}
		Encrypt_chacha20(iv, CHACHA_MODIFIED_BLOCK_SIZE, key, keyLength, &outblk);


		//fac XOR intre IV criptat(outblk) si blocul de intrare 
		memcpy(inblk, (*pData) + offset, CHACHA_MODIFIED_BLOCK_SIZE);
		for (int i = 0; i < CHACHA_MODIFIED_BLOCK_SIZE; i++)
			inblk[i] = inblk[i] ^ outblk[i];

		memcpy((*encData) + offset, inblk, CHACHA_MODIFIED_BLOCK_SIZE);

		//copiez in bufferul iv ciphertext-ul curent pt a face XOR cu urmatorul bloc de intrare 
		memcpy(iv, outblk, CHACHA_MODIFIED_BLOCK_SIZE);
		offset += CHACHA_MODIFIED_BLOCK_SIZE;
	}
	return CRYPTO_SUCCES;
}
int CryptoSystem::Decrypt_chacha20_ofb(unsigned char** encData, int& dataLen, unsigned char* iv, unsigned char* key, int keyLength, unsigned char** pData) {

	int status = CRYPTO_SUCCES;
	unsigned char inblk[CHACHA_MODIFIED_BLOCK_SIZE];
	unsigned char* outblk = nullptr;
	int offset = 0;


	(*pData) = (unsigned char*)malloc(dataLen);
	if (*pData == NULL)
		return CRYPTO_ERROR;

	//criptez  AES CBC fiecare bloc 
	while (offset < dataLen)
	{

		if (outblk != nullptr) {
			delete outblk;
			outblk = nullptr;
		}
		Encrypt_chacha20(iv, CHACHA_MODIFIED_BLOCK_SIZE, key, keyLength, &outblk);

		//fac XOR intre IV criptat(outblk) si blocul de intrare 
		memcpy(inblk, (*encData) + offset, CHACHA_MODIFIED_BLOCK_SIZE);
		for (int i = 0; i < CHACHA_MODIFIED_BLOCK_SIZE; i++)
			inblk[i] = inblk[i] ^ outblk[i];

		memcpy((*pData) + offset, inblk, CHACHA_MODIFIED_BLOCK_SIZE);

		//copiez in bufferul iv ciphertext-ul curent pt a face XOR cu urmatorul bloc de intrare 
		memcpy(iv, outblk, CHACHA_MODIFIED_BLOCK_SIZE);
		offset += CHACHA_MODIFIED_BLOCK_SIZE;
	}

	int remove = ((*pData)[dataLen - 1]);
	dataLen -= remove;

	(*pData) = (unsigned char*)realloc(*pData, dataLen);
	return CRYPTO_SUCCES;
}

int CryptoSystem::Encrypt_chacha20_cfb(unsigned char** pData, int& dataLen, unsigned char* iv, unsigned char* key, int keyLength, unsigned char** encData)
{
	int status = CRYPTO_SUCCES;
	unsigned char inblk[CHACHA_MODIFIED_BLOCK_SIZE];
	unsigned char* outblk = nullptr;
	int offset = 0;


	status = _add_padding(pData, dataLen, CHACHA_MODIFIED_BLOCK_SIZE);
	if (status != CRYPTO_SUCCES)
		return status;

	(*encData) = (unsigned char*)malloc(dataLen);
	if (*encData == NULL)
		return CRYPTO_ERROR;

	//criptez  AES CBC fiecare bloc 
	while (offset < dataLen)
	{
		//AES_encrypt(iv, outblk, &aesKey);
		if (outblk != nullptr) {
			delete outblk;
			outblk = nullptr;
		}
		Encrypt_chacha20(iv, CHACHA_MODIFIED_BLOCK_SIZE, key, keyLength, &outblk);

		//fac XOR intre IV criptat(outblk) si blocul de intrare 
		memcpy(inblk, (*pData) + offset, CHACHA_MODIFIED_BLOCK_SIZE);
		for (int i = 0; i < CHACHA_MODIFIED_BLOCK_SIZE; i++)
			inblk[i] = inblk[i] ^ outblk[i];

		memcpy((*encData) + offset, inblk, CHACHA_MODIFIED_BLOCK_SIZE);

		//copiez in bufferul iv ciphertext-ul curent pt a face XOR cu urmatorul bloc de intrare 
		memcpy(iv, inblk, CHACHA_MODIFIED_BLOCK_SIZE);
		offset += CHACHA_MODIFIED_BLOCK_SIZE;
	}
	return CRYPTO_SUCCES;
}
int CryptoSystem::Decrypt_chacha20_cfb(unsigned char** encData, int& dataLen, unsigned char* iv, unsigned char* key, int keyLength, unsigned char** pData) {

	int status = CRYPTO_SUCCES;
	unsigned char inblk[CHACHA_MODIFIED_BLOCK_SIZE];
	unsigned char* outblk = nullptr;
	int offset = 0;

	(*pData) = (unsigned char*)malloc(dataLen);
	if (*pData == NULL)
		return CRYPTO_ERROR;

	//criptez  AES CBC fiecare bloc 
	while (offset < dataLen)
	{
		//AES_encrypt(iv, outblk, &aesKey);
		if (outblk != nullptr) {
			delete outblk;
			outblk = nullptr;
		}
		Encrypt_chacha20(iv, CHACHA_MODIFIED_BLOCK_SIZE, key, keyLength, &outblk);


		//fac XOR intre IV criptat si blocul de intrare 
		memcpy(inblk, (*encData) + offset, CHACHA_MODIFIED_BLOCK_SIZE);
		for (int i = 0; i < CHACHA_MODIFIED_BLOCK_SIZE; i++)
			outblk[i] = outblk[i] ^ inblk[i];

		memcpy((*pData) + offset, outblk, CHACHA_MODIFIED_BLOCK_SIZE);

		//copiez in bufferul iv ciphertext-ul curent pt a face XOR cu urmatorul bloc de intrare 
		memcpy(iv, inblk, CHACHA_MODIFIED_BLOCK_SIZE);
		offset += CHACHA_MODIFIED_BLOCK_SIZE;
	}

	int remove = ((*pData)[dataLen - 1]);
	dataLen -= remove;

	(*pData) = (unsigned char*)realloc(*pData, dataLen);


	return CRYPTO_SUCCES;
}

int CryptoSystem::Encrypt_chacha20_ige(unsigned char** pData, int& dataLen, unsigned char* iv, unsigned char* iv2, unsigned char* key, int keyLength, unsigned char** encData)
{
	int status = CRYPTO_SUCCES;
	unsigned char inblk[CHACHA_MODIFIED_BLOCK_SIZE];
	unsigned char* outblk = nullptr;
	int offset = 0;


	status = _add_padding(pData, dataLen, CHACHA_MODIFIED_BLOCK_SIZE);
	if (status != CRYPTO_SUCCES)
		return status;

	(*encData) = (unsigned char*)malloc(dataLen);
	if (*encData == NULL)
		return CRYPTO_ERROR;


	//criptez  AES IGE fiecare bloc 
	while (offset < dataLen)
	{
		//fac XOR intre IV  si blocul de intrare 
		memcpy(inblk, (*pData) + offset, CHACHA_MODIFIED_BLOCK_SIZE);
		for (int i = 0; i < CHACHA_MODIFIED_BLOCK_SIZE; i++)
			inblk[i] = inblk[i] ^ iv[i];

		//criptam rezultatul
		//AES_encrypt(inblk, outblk, &aesKey);
		if (outblk != nullptr) {
			delete outblk;
			outblk = nullptr;
		}
		Encrypt_chacha20(inblk, CHACHA_MODIFIED_BLOCK_SIZE, key, keyLength, &outblk);

		//fac XOR intre rezultat  si iv2
		for (int i = 0; i < CHACHA_MODIFIED_BLOCK_SIZE; i++)
			outblk[i] = outblk[i] ^ iv2[i];

		memcpy((*encData) + offset, outblk, CHACHA_MODIFIED_BLOCK_SIZE);

		//copiez in bufferul iv plaintextul curent pt a face XOR cu urmatorul bloc de intrare 
		memcpy(iv, outblk, CHACHA_MODIFIED_BLOCK_SIZE);
		//copiez in bufferul iv2 chipertextul curent pt a face XOR cu urmatorul bloc de intrare 
		memcpy(iv2, (*pData) + offset, CHACHA_MODIFIED_BLOCK_SIZE);

		offset += CHACHA_MODIFIED_BLOCK_SIZE;
	}
	return CRYPTO_SUCCES;;
}
int CryptoSystem::Decrypt_chacha20_ige(unsigned char** encData, int& dataLen, unsigned char* iv, unsigned char* iv2, unsigned char* key, int keyLength, unsigned char** pData) {

	int status = CRYPTO_SUCCES;
	unsigned char inblk[CHACHA_MODIFIED_BLOCK_SIZE];
	unsigned char* outblk = nullptr;
	int offset = 0;

	(*pData) = (unsigned char*)malloc(dataLen);
	if (*pData == NULL)
		return CRYPTO_ERROR;

	//criptez  AES IGE fiecare bloc 
	while (offset < dataLen)
	{
		//fac XOR intre IV  si blocul de intrare 
		memcpy(inblk, (*encData) + offset, CHACHA_MODIFIED_BLOCK_SIZE);
		for (int i = 0; i < CHACHA_MODIFIED_BLOCK_SIZE; i++)
			inblk[i] = inblk[i] ^ iv2[i];

		//criptam rezultatul
		//AES_decrypt(inblk, outblk, &aesKey);
		if (outblk != nullptr) {
			delete outblk;
			outblk = nullptr;
		}
		Decrypt_chacha20(inblk, CHACHA_MODIFIED_BLOCK_SIZE, key, keyLength, &outblk);

		//fac XOR intre rezultat  si iv2
		for (int i = 0; i < CHACHA_MODIFIED_BLOCK_SIZE; i++)
			outblk[i] = outblk[i] ^ iv[i];

		memcpy((*pData) + offset, outblk, CHACHA_MODIFIED_BLOCK_SIZE);

		//copiez in bufferul iv plaintextul curent pt a face XOR cu urmatorul bloc de intrare 
		memcpy(iv2, outblk, CHACHA_MODIFIED_BLOCK_SIZE);
		//copiez in bufferul iv2 chipertextul curent pt a face XOR cu urmatorul bloc de intrare 
		memcpy(iv, (*encData) + offset, CHACHA_MODIFIED_BLOCK_SIZE);

		offset += CHACHA_MODIFIED_BLOCK_SIZE;
	}

	int remove = ((*pData)[dataLen - 1]);
	dataLen -= remove;

	(*pData) = (unsigned char*)realloc(*pData, dataLen);

	return CRYPTO_SUCCES;
}


int CryptoSystem::ConvertToBase64(unsigned char* buffer, int length, char** b64text, int& b64length) {

	BIO* bio, * b64;
	BUF_MEM* bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);


	*b64text = (char*)malloc(sizeof(char) * (bufferPtr->length + 1));
	memcpy(*b64text, bufferPtr->data, bufferPtr->length);
	(*b64text)[bufferPtr->length] = '\0';
	b64length = bufferPtr->length + 1;

	BUF_MEM_free(bufferPtr);
	return CRYPTO_SUCCES;;
}
int CryptoSystem::CalcDecodeLength(const char* b64input) { //Calculates the length of a decoded base64 string
	int len = strlen(b64input);
	int padding = 0;

	if (b64input[len - 1] == '=' && b64input[len - 2] == '=') //last two chars are =
		padding = 2;
	else if (b64input[len - 1] == '=') //last char is =
		padding = 1;

	return (int)len * 0.75 - padding;
}
int CryptoSystem::ConvertFromBase64(char* b64message, unsigned char** buffer, int& length) { //Decodes a base64 encoded string
	BIO* bio, * b64;
	int decodeLen = CalcDecodeLength(b64message);
	int len = 0;
	*buffer = (unsigned char*)malloc(decodeLen);

	BUF_MEM* buff = new BUF_MEM();
	buff->data = b64message;
	buff->length = strlen(b64message);

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	BIO_set_mem_buf(bio, buff, BIO_NOCLOSE);
	len = BIO_read(bio, *buffer, strlen(b64message));
	//Can test here if len == decodeLen - if not, then return an error
	//(*buffer)[len] = '\0';

	BIO_free_all(bio);
	free(buff);

	length = decodeLen;
	return CRYPTO_SUCCES;
}

int CryptoSystem::CalculateHash(unsigned char* cipherText, int cipherTextLength, unsigned char** hash, int hashLength) {

	int offset = 0;
	int blockLength = 0;
	unsigned char* block = new unsigned char[hashLength];
	
	*hash = new unsigned char[hashLength];
	memset(*hash, 0x00, hashLength);

	while (offset < cipherTextLength) {

		blockLength = cipherTextLength - offset;
		blockLength = (blockLength > hashLength) ? hashLength : blockLength;
		memcpy(block, cipherText + offset, blockLength);

		for (int i = 0; i < blockLength; i++) {

			(*hash)[i] = (*hash)[i] + block[i];
		}

		offset += hashLength;
	}
	delete block;

	PolynomReduction(*hash);

	return CRYPTO_SUCCES;
}
int CryptoSystem::PolynomReduction(unsigned char* buffer, int length) {

	for (int i = 0; i < length; i++) {

		buffer[i] = buffer[i] ^ _reducedPolynom[i];
	}

	return CRYPTO_SUCCES;
}
int CryptoSystem::SignHash(unsigned char* hash, int hashLength, unsigned char* tag, int tagLength, unsigned char* key, int keyLength,unsigned char** signature) {
	
	unsigned char* tempHash = nullptr;
	int rotationValue;

	*signature = new unsigned char[hashLength];
	memcpy(*signature, hash, hashLength);

	for (int i = 0; i < tagLength / 4; i++) {

		memcpy(&rotationValue, tag + i * 4, sizeof(int));
		if (rotationValue % 2 == 0)
			RotateRight(*signature, hashLength * 8, rotationValue);
		else
			RotateLeft(*signature, hashLength * 8, rotationValue);

		if (tempHash != nullptr) {
			delete tempHash;
			tempHash = nullptr;
		}
		Encrypt_aes_ecb(*signature, hashLength, key, keyLength, &tempHash);
		memcpy(*signature, tempHash, hashLength);
	}
	

	if (tempHash != nullptr) 
		delete tempHash;
	
	return CRYPTO_SUCCES;
}

int CryptoSystem::_add_padding(unsigned char** data, int& dataLen, int blockSize)
{
	//determin numarul de octeti necesari pt padding
	int padblk_nr = blockSize - (dataLen % blockSize);

	//daca ultimul bloc este complet atunci mai aloc memorie pentru un bloc intreg cu fiecare octet 0x10
	if (padblk_nr == 0)
	{
		dataLen += blockSize;
		(*data) = (unsigned char*)realloc(*data, dataLen);
		if (*data == NULL)
			return CRYPTO_ERROR;

		for (int i = 1; i <= blockSize; i++)
			(*data)[dataLen - i] = blockSize;
	}

	else
		//altfel aloc memorie pt inca padblk_nr octeti cu valoare padblk_nr
	{
		dataLen += padblk_nr;
		(*data) = (unsigned char*)realloc(*data, dataLen);
		if (*data == NULL)
			return  CRYPTO_ERROR;

		for (int i = 1; i <= padblk_nr; i++)
			(*data)[dataLen - i] = padblk_nr;
	}
	return CRYPTO_SUCCES;
}
void CryptoSystem::_increment_counter(unsigned char* counter, int position)
{
	if (position < 0)
		return;

	/*daca octectul curent are valoare 0xFF atunci apelez recursiv functia pentru octetul urmator mai semnificativ*/
	if (counter[position] == 0xFF)
	{
		counter[position] = 0x00;
		_increment_counter(counter, position - 1);
		return;
	}
	counter[position] ++;
	return;
}
int CryptoSystem::RotateLeft(unsigned char* buffer, int bufferLength, int rotationValue) {
	
	if (rotationValue < 0 || rotationValue > bufferLength)
		return CRYPTO_BAD_PARAMS;

	*buffer =  (*buffer << rotationValue) | (*buffer >> bufferLength - rotationValue);
	return CRYPTO_SUCCES;
}
int CryptoSystem::RotateRight(unsigned char* buffer, int bufferLength, int rotationValue) {

	if (rotationValue < 0 || rotationValue > bufferLength)
		return CRYPTO_BAD_PARAMS;

	*buffer = (*buffer >> rotationValue) | (*buffer << bufferLength - rotationValue);
	return CRYPTO_SUCCES;
}

int CryptoSystem::SaveFinalData(char* filename, unsigned char* encryptedData, int encryptedDataLength, char* algorithm, int algorithmLength, unsigned char* signature, int signatureLength) {

	FILE* f;

	//creem structura ASN
	cryptoAtm_Data* data = cryptoAtm_Data_new();

	data->encryptedData = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(data->encryptedData, encryptedData, encryptedDataLength);

	data->encryptionAlgorithm = ASN1_UTF8STRING_new();
	ASN1_STRING_set(data->encryptionAlgorithm, algorithm, algorithmLength);

	data->signature = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(data->signature, signature, signatureLength);

	f = fopen(filename, "wb");
	if (f == nullptr) {
		printf("Fail to open file %s", filename);
		return CRYPTO_ERROR;
	}

	// der encoding
	unsigned char* buffer, * myber;
	int len = i2d_cryptoAtm_Data(data, NULL);
	buffer = (unsigned char*)OPENSSL_malloc(len);
	if (buffer == nullptr)
		fprintf(stderr, "Openssl malloc failed");
	myber = buffer;

	i2d_cryptoAtm_Data(data, &myber);

	//scriem in fisier
	fwrite(buffer, len, 1, f);

	fclose(f);

	return CRYPTO_SUCCES;
}
int CryptoSystem::LoadFinalData(char* filename, unsigned char** encryptedData, int& encryptedDatalength, char** algorithm, int& algorithmLength, unsigned char** signature, int& signatureLength) {


	unsigned char* buffer;
	int bufferLength;
	FILE* f = fopen(filename, "rb");
	if (f == nullptr) {

		printf("Nu am putut deschide %s\n", filename);
		return CRYPTO_ERROR;
	}

	fseek(f, 0, SEEK_END);
	bufferLength = ftell(f);
	rewind(f);

	buffer = new unsigned char[bufferLength];
	fread(buffer, 1, bufferLength, f);

	cryptoAtm_Data* data = cryptoAtm_Data_new();;
	const unsigned char* my_ber;
	my_ber = buffer;
	d2i_cryptoAtm_Data(&data, &my_ber, bufferLength);

	encryptedDatalength = data->encryptedData->length;
	*encryptedData = new unsigned char[encryptedDatalength];
	memcpy(*encryptedData, data->encryptedData->data, encryptedDatalength);

	algorithmLength = data->encryptionAlgorithm->length;
	*algorithm = new char[algorithmLength];
	memcpy(*algorithm, data->encryptionAlgorithm->data, algorithmLength);

	signatureLength = data->signature->length;
	*signature = new unsigned char[signatureLength];
	memcpy(*signature, data->signature->data, signatureLength);

	return CRYPTO_SUCCES;
}