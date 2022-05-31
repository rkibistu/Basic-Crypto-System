#pragma once
#pragma warning(disable : 4996)
#include <openssl/des.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>


#define PEM_HEADER "-----BEGIN KEY STREAM-----"
#define PEM_FOOTER "-----END KEY STREAM-----"
#define PEM_HEADER_LENGTH 26
#define PEM_FOOTER_LENGTH 24

typedef struct ASN_EncKey {

	ASN1_OCTET_STRING* salt;
	ASN1_OCTET_STRING* nonce;
	ASN1_OCTET_STRING* AesEncryptedKey;
}ASN_EncKey;
typedef struct ASN_AES_KEY {

	ASN1_INTEGER* keySize;
	ASN_EncKey* encKey;
	ASN1_UTCTIME* from;
	ASN1_UTCTIME* to;
}ASN_AES_KEY;

#define SALT_LENGTH 4


class KeyGenerator
{
private:
	void _3des_ecb_encrypt(unsigned char* inData, unsigned char* outData, int length, DES_key_schedule* pKs1, DES_key_schedule* pKs2, DES_key_schedule* pKs3, int operation);
	void myPBKDF(unsigned char* password, int passLen, unsigned char* salt, int saltLen, unsigned char* key, int lengthKey,int operation);
public:
	void GenerateSeed(int length, unsigned char* seed);
	void GenerateKey(int length, unsigned char* key, int lengthSeed, unsigned char* seed);
	ASN_AES_KEY* GenerateAesKeyStructure(int lengthKey, unsigned char* key, unsigned char* password, int passLen, int lifeTime);
	void DecryptAesEncKey(ASN_AES_KEY* aesStruct, unsigned char* password, int passwordLength, unsigned char** key, int& length);

	int SaveKeyToFileAsOctetString(const char* filename, unsigned char* key, int length);
	void LoadKeyFromFileOctetString(const char* filename, unsigned char** key, int& length);

	int SaveAesKeyStructure(const char* filename, ASN_AES_KEY* aesKey);
	ASN_AES_KEY* LoadAesKeyStructure(const char* filename);


	//void SaveKeyToFile

	void GenerateSalt(int length, unsigned char* salt);
};

