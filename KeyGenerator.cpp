#define _CRT_SECURE_NO_WARNINGS

#include "KeyGenerator.h"
#include "CryptoSystem.h"

#include <time.h>
#include <openssl/rand.h>
#include <string.h>


ASN1_SEQUENCE(ASN_EncKey) = {
	ASN1_SIMPLE(ASN_EncKey,salt,ASN1_OCTET_STRING),
	ASN1_SIMPLE(ASN_EncKey,nonce,ASN1_OCTET_STRING),
	ASN1_SIMPLE(ASN_EncKey,AesEncryptedKey,ASN1_OCTET_STRING)
}ASN1_SEQUENCE_END(ASN_EncKey);
DECLARE_ASN1_FUNCTIONS(ASN_EncKey);
IMPLEMENT_ASN1_FUNCTIONS(ASN_EncKey);

ASN1_SEQUENCE(ASN_AES_KEY) = {
	ASN1_SIMPLE(ASN_AES_KEY,keySize,ASN1_INTEGER),
	ASN1_SIMPLE(ASN_AES_KEY,encKey,ASN_EncKey),
	ASN1_SIMPLE(ASN_AES_KEY,from,ASN1_UTCTIME),
	ASN1_SIMPLE(ASN_AES_KEY,to,ASN1_UTCTIME)
}ASN1_SEQUENCE_END(ASN_AES_KEY);
DECLARE_ASN1_FUNCTIONS(ASN_AES_KEY);
IMPLEMENT_ASN1_FUNCTIONS(ASN_AES_KEY);


void KeyGenerator::GenerateSeed(int length, unsigned char* seed) {

	RAND_bytes(seed, length);
	srand(time(NULL));
	for (int i = 0; i < length; i++) {

		seed[i] = (rand() % 255) ^ seed[i];
	}
}
void KeyGenerator::GenerateKey(int length, unsigned char* key, int lengthSeed, unsigned char* seed) {

	
	long long currentTime = time(NULL);

	RAND_bytes(key, length);
	memcpy(key, &currentTime, 1);
	memcpy(key + length - 1, &currentTime + sizeof(long long) - 1, 1);

	for (int i = 0; i < length; i++) {

		key[i] = key[i] ^ seed[i % lengthSeed];
	}
	
	int x = 3;
}
ASN_AES_KEY* KeyGenerator::GenerateAesKeyStructure(int lengthKey, unsigned char* key, unsigned char* password, int passLen, int lifeTime) {
	
	unsigned char salt[SALT_LENGTH];
	GenerateSalt(SALT_LENGTH, salt);

	RAND_bytes(key, lengthKey);
	myPBKDF(password, passLen, salt, SALT_LENGTH, key, lengthKey, DES_ENCRYPT);

	ASN_AES_KEY* aesKey = ASN_AES_KEY_new();

	aesKey->keySize = ASN1_INTEGER_new();
	ASN1_INTEGER_set(aesKey->keySize, lengthKey);
	
	ASN_EncKey* encKey = ASN_EncKey_new();
	encKey->salt =  ASN1_OCTET_STRING_new();
	encKey->nonce =  ASN1_OCTET_STRING_new();
	encKey->AesEncryptedKey =  ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(encKey->salt, salt, SALT_LENGTH);
	ASN1_OCTET_STRING_set(encKey->AesEncryptedKey, key, lengthKey);
	aesKey->encKey = encKey;


	aesKey->from = ASN1_UTCTIME_new();
	ASN1_UTCTIME_set(aesKey->from, time(NULL));
	aesKey->to = ASN1_UTCTIME_new();
	ASN1_UTCTIME_set(aesKey->to, time(NULL) + 2628000 * lifeTime);

	return aesKey;
}
void KeyGenerator::DecryptAesEncKey(ASN_AES_KEY* aesStruct, unsigned char* password, int passwordLength, unsigned char** key, int& length) {

	//preluam cheia criptata din structura
	int encKeyLength = aesStruct->encKey->AesEncryptedKey->length;
	unsigned char* encKey = new unsigned char[encKeyLength];
	memcpy(encKey, aesStruct->encKey->AesEncryptedKey->data,encKeyLength);

	//preluam salt
	int saltLength = aesStruct->encKey->salt->length;
	unsigned char* salt = new unsigned char[saltLength];
	memcpy(salt, aesStruct->encKey->salt->data, saltLength);

	//o decriptam
	myPBKDF(password, passwordLength, salt, saltLength, encKey, encKeyLength,DES_ENCRYPT);

	//populam parametrii de reutrn
	length = encKeyLength;;
	*key = new unsigned char[length];
	memcpy(*key, encKey, length);
}
void KeyGenerator::GenerateSalt(int length, unsigned char* salt)
{
	RAND_bytes(salt, length);
}

void KeyGenerator::_3des_ecb_encrypt(unsigned char* inData, unsigned char* outData, int length, DES_key_schedule* pKs1, DES_key_schedule* pKs2, DES_key_schedule* pKs3, int operation)
{
	int offset = 0;
	DES_cblock cblockIN;
	DES_cblock cblockOut;
	int cblock_size = sizeof(DES_cblock);

	//criptez 3DES_ECB fiecare bloc de 8 bytes ( cblock_size)
	while (offset < length)
	{
		memcpy(cblockIN, inData + offset, cblock_size);
		DES_ecb3_encrypt((const_DES_cblock*)&cblockIN, &cblockOut, pKs1, pKs2, pKs3, operation);

		memcpy(outData + offset, cblockOut, cblock_size);
		offset += cblock_size;
	}
}
void KeyGenerator::myPBKDF(unsigned char* password, int passLen, unsigned char* salt, int saltLen,unsigned char* key, int lengthKey, int operation)
{
	/* pentru criptarea 3DES_ECB folosesc cheia K = 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0A 0x0B 0x0C 0x0D 0x0E 0x0F */
	DES_cblock cb1 = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	DES_cblock cb2 = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
	DES_cblock cb3 = { 0x010, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	DES_key_schedule ks1, ks2, ks3;

	int bufferLen = passLen + saltLen;

	unsigned char* cipherData = NULL;;
	unsigned char* buffer = (unsigned char*)malloc(passLen + saltLen);

	if (buffer == NULL)
		return;

	//concatenare parola si salt in buffer
	memcpy(buffer, password, passLen);
	memcpy(buffer + passLen, salt, saltLen);

	//setez cheile pentru 3DES_ECB, fara a valida paritatea sau "siguranta" acestora
	//pentru aceste validari, ar trebui utilizata metoda DES_set_key_checked(...)
	DES_set_key_unchecked(&cb1, &ks1);
	DES_set_key_unchecked(&cb2, &ks2);
	DES_set_key_unchecked(&cb3, &ks3);

	//aloc memorie pentru buffer-ul unde voi stoca datele criptate
	cipherData = (unsigned char*)malloc(bufferLen);
	if (cipherData == NULL)
		return;

	//criptez 3DES_ECB parola concatenata cu saltul
	_3des_ecb_encrypt(buffer, cipherData, bufferLen, &ks1, &ks2, &ks3, operation);

	for (int i = 0; i < lengthKey; i++)
		key[i] = key[i] ^ cipherData[i & bufferLen];
}


int KeyGenerator::SaveKeyToFileAsOctetString(const char* filename, unsigned char* key, int length) {

	CryptoSystem crypto; //folosim la conversia base64
	char* b64text = nullptr;
	int b64length;

	char newLine[] = "\n";
	FILE* f = fopen(filename, "wb");
	if (f == nullptr) {

		printf("Error open file %s", filename);
		return -1;
	}

	//scrie header PEM
	fwrite(PEM_HEADER, 1, PEM_HEADER_LENGTH, f);
	fwrite(newLine, 1, strlen(newLine), f);

	//converteste la OCTET_STRING cheia
	ASN1_OCTET_STRING* octetString = ASN1_OCTET_STRING_new();;
	ASN1_OCTET_STRING_set(octetString, key, length);

	unsigned char* buffer, * myber;
	int len = i2d_ASN1_OCTET_STRING(octetString, NULL);
	buffer = (unsigned char*)OPENSSL_malloc(len);
	if (buffer == nullptr)
		fprintf(stderr, "Openssl malloc failed");
	myber = buffer;

	i2d_ASN1_OCTET_STRING(octetString, &myber);

	//converteste in base64 cheia
	crypto.ConvertToBase64(buffer, len, &b64text, b64length);

	//scrie in fisier cheia codificata base64
	fwrite(b64text, b64length, 1, f);

	//scrie footer PEM
	fwrite(newLine, 1, strlen(newLine), f);
	fwrite(PEM_FOOTER, 1, PEM_FOOTER_LENGTH, f);

	//inchide fiiser
	fclose(f);
	return 0;
}
void KeyGenerator::LoadKeyFromFileOctetString(const char* filename, unsigned char** key, int& length) {

	CryptoSystem crypto;
	char* asnStructure;
	unsigned char* buffer, *from64text;
	int bufferLength,from64length;
	int res;
	int newLineLength = 1;
	FILE* f = fopen(filename, "rb");
	if (f == nullptr) {

		printf("Error open file %s", filename);
		exit(1);
		return;
	}

	//calc lungime fisier
	fseek(f, 0, SEEK_END);
	bufferLength = ftell(f);
	rewind(f);

	//alocam memorie si citim fisierul
	buffer = new unsigned char[bufferLength];
	fread(buffer, 1, bufferLength, f);

	//verificam header si footer PEM
	res = memcmp(buffer, PEM_HEADER, PEM_HEADER_LENGTH);
	if (res != 0) {
		printf("Bad header to PEM file %s", filename);
		return;
	}
	res = memcmp(buffer + bufferLength - PEM_FOOTER_LENGTH, PEM_FOOTER, PEM_FOOTER_LENGTH);
	if (res != 0) {
		printf("Bad footer to PEM file %s", filename);
		return;
	}

	//preluam doar informatia utila din fisier (fara header si footer)
	length = bufferLength - PEM_FOOTER_LENGTH - PEM_HEADER_LENGTH - newLineLength;
	asnStructure = new char[length];
	memcpy(asnStructure, buffer + PEM_HEADER_LENGTH + newLineLength, length);

	//decodificam din base64
	crypto.ConvertFromBase64(asnStructure, &from64text, from64length);


	//preluam info din structura OCTET_STRING
	ASN1_OCTET_STRING* octetString = ASN1_OCTET_STRING_new();;
	unsigned char* ber_info;
	const unsigned char* my_ber;

	my_ber = from64text;
	d2i_ASN1_OCTET_STRING(&octetString, &my_ber, from64length);

	length = octetString->length;
	*key = new unsigned char[length];
	memcpy(*key, octetString->data, length);

	delete asnStructure;
	delete buffer;
}
int KeyGenerator::SaveAesKeyStructure(const char* filename, ASN_AES_KEY* aesKey) {

	FILE* f = fopen(filename, "wb");
	if (f == nullptr) {

		printf("File not open %s", filename);
		return -1;
	}

	unsigned char* buffer, * myber;
	int len = i2d_ASN_AES_KEY(aesKey, NULL);
	buffer = (unsigned char*)OPENSSL_malloc(len);
	if (buffer == nullptr)
		fprintf(stderr, "Openssl malloc failed");
	myber = buffer;

	i2d_ASN_AES_KEY(aesKey, &myber);

	fwrite(buffer, 1, len, f);
	fclose(f);
	return 0;
}
ASN_AES_KEY* KeyGenerator::LoadAesKeyStructure(const char* filename) {

	unsigned char* buffer;
	int bufferLength;
	FILE* f = fopen(filename, "rb");
	if (f == nullptr) {

		printf("Error open file %s", filename);
		return nullptr;
	}

	fseek(f, 0, SEEK_END);
	bufferLength = ftell(f);
	rewind(f);

	buffer = new unsigned char[bufferLength];
	fread(buffer, 1, bufferLength, f);

	ASN_AES_KEY* aesKey = ASN_AES_KEY_new();;

	const unsigned char* my_ber;

	my_ber = buffer;
	d2i_ASN_AES_KEY(&aesKey, &my_ber, bufferLength);

	return aesKey;
}
