#include "KeyGenerator.h"
#include "CryptoSystem.h"
#include "CryptoFileSystem.h"

#include <string>
#include <stdio.h>
#include <conio.h>
#include <iostream>

void ClearScreen()
{
	int n;
	for (n = 0; n < 10; n++)
		printf("\n\n\n\n\n\n\n\n\n\n");
}
void ReadText(char** text, int& length) {

	char c = getc(stdin);
	length = 0;
	*text = nullptr;
	do {

		c = getc(stdin);
		*text = (char*)realloc(*text, length + 1);
		(*text)[length] = c;
		length++;

	} while (c != '\n');
	(*text)[length] = '\0';
}

void GenerateKeyChaCha20() {

	KeyGenerator generator;
	int seedLength;
	unsigned char* seed = nullptr;
	char filename[100];
	int keyLength = 256;
	unsigned char* key = new unsigned char[keyLength];
	int res;

	ClearScreen();
	printf("Introdu lungime dorita seed: ");
	scanf("%d", &seedLength);
	printf("Introdu fisier pentru salvare cheie: ");
	scanf("%s", filename);

	seed = new unsigned char[seedLength];

	generator.GenerateSeed(seedLength, seed);
	generator.GenerateKey(keyLength, key, seedLength, seed);

	res = generator.SaveKeyToFileAsOctetString(filename, key, keyLength);

	delete[] seed;
	delete key;

	if (res == 0)
		printf("\nCheie salvata cu succes in fisierul %s\n", filename);
	else
		printf("\n Generare cheie esuate\n");
}
void GenerateKeyAes() {

	KeyGenerator generator;
	int keyLength;
	unsigned char* key = nullptr;
	char password[100];
	char filename[100];
	int res;

	ClearScreen();
	printf("Introduceti lungime cheie aes (16,24,32): ");
	scanf("%d", &keyLength);
	key = new unsigned char[keyLength];

	printf("Introduceti parola pentru criptare cheie: ");
	scanf("%s", password);

	printf("Introduceti fisier pentru salvare cheie: ");
	scanf("%s", filename);

	ASN_AES_KEY* aesKey = generator.GenerateAesKeyStructure(keyLength, key, (unsigned char*)password, strlen(password), 6); //6 luni validitate cheie
	res = generator.SaveAesKeyStructure(filename, aesKey);
	if (res == 0)
		printf("Cheie salvata cu succes in fisierul %s\n", filename);
	else
		printf("\nGenerare cheie esuata!\n");
}
void EncryptChaCha() {

	KeyGenerator generator;
	CryptoSystem crypto;
	int keyLength;
	unsigned char* key = nullptr;
	int aesKeyLength;
	unsigned char* aesKey = nullptr;
	ASN_AES_KEY* aesKeyStructure = nullptr;
	int plainTextLength;
	char* plainText;
	char password[100];
	unsigned char* cipherText = nullptr;
	unsigned char tag[TAG_LENGTH];
	char filenameKeyChacha[100];
	char filenameKeyAes[100];
	char filenameFinal[100];
	int hashLength = 16;
	unsigned char* hash = new unsigned char[hashLength];
	unsigned char* signature = nullptr;
	char algorithm[] = "chacha20_poly1305";
	int res;

	ClearScreen();
	printf("Introduceti fisier cheie chacha20 (unde ati generat anterior): ");
	scanf("%s", filenameKeyChacha);
	generator.LoadKeyFromFileOctetString(filenameKeyChacha, &key, keyLength);

	printf("Introduceti fisier cheie AES: ");
	scanf("%s", filenameKeyAes);

	printf("Introduceti text pentru criptat: ");
	ReadText(&plainText, plainTextLength);

	printf("Introduceti parola: ");
	scanf("%s", password);

	printf("Introduceti fisier output: ");
	scanf("%s", filenameFinal);

	crypto.Encrypt_chacha20_tag((const unsigned char*)plainText, strlen(plainText), key, keyLength, (const unsigned char*)password, strlen(password), &cipherText, tag);

	//SALVARE IN FISIER

	crypto.CalculateHash(cipherText, strlen(plainText), &hash, hashLength);

	aesKeyStructure = generator.LoadAesKeyStructure(filenameKeyAes);
	if (aesKeyStructure == nullptr)
		exit(1);
	generator.DecryptAesEncKey(aesKeyStructure, (unsigned char*)password, strlen(password), &aesKey, aesKeyLength);
	crypto.SignHash(hash, hashLength, tag, TAG_LENGTH, aesKey, aesKeyLength, &signature);

	res = crypto.SaveFinalData(filenameFinal, cipherText, strlen(plainText), algorithm, strlen(algorithm), signature, hashLength);
	if (res == CRYPTO_SUCCES) {

		printf("Datele au fost criptate cu succes si salvate in: %s\n", filenameFinal);
	}
	else {
		printf("Datele nu au putut fi criptate\n");
	}
}
void EncryptAes() {

	KeyGenerator generator;
	CryptoSystem crypto;
	ASN_AES_KEY* aesKeyStructure = nullptr;
	int aesKeyLength;
	unsigned char* aesKey = nullptr;
	int plainTextLength;
	char* plainText;
	char password[100];
	unsigned char* cipherText = nullptr;
	unsigned char tag[TAG_LENGTH];
	char filenameKeyAes[100];
	char filenameFinal[100];
	int hashLength = 16;
	unsigned char* hash = new unsigned char[hashLength];
	unsigned char* signature = nullptr;
	char algorithm[] = "aes_gcm";
	int res;

	ClearScreen();

	printf("Introduceti fisier cheie AES: ");
	scanf("%s", filenameKeyAes);

	printf("Introduceti text pentru criptat: ");
	ReadText(&plainText, plainTextLength);

	printf("Introduceti parola: ");
	scanf("%s", password);

	printf("Introduceti fisier salvare output: ");
	scanf("%s", filenameFinal);

	aesKeyStructure = generator.LoadAesKeyStructure(filenameKeyAes);
	if (aesKeyStructure == nullptr)
		exit(1);
	generator.DecryptAesEncKey(aesKeyStructure, (unsigned char*)password, strlen(password), &aesKey, aesKeyLength);

	if (aesKeyLength == 16) {

		crypto.Encrypt_aes128_gcm((const unsigned char*)plainText, strlen(plainText), aesKey, aesKeyLength, (const unsigned char*)password, strlen(password), &cipherText, tag);
	}
	else if (aesKeyLength = 24) {

		crypto.Encrypt_aes192_gcm((const unsigned char*)plainText, strlen(plainText), aesKey, aesKeyLength, (const unsigned char*)password, strlen(password), &cipherText, tag);
	}
	else if (aesKeyLength = 32) {

		crypto.Encrypt_aes256_gcm((const unsigned char*)plainText, strlen(plainText), aesKey, aesKeyLength, (const unsigned char*)password, strlen(password), &cipherText, tag);
	}
	else {

		printf("Lungime cheie gresita in fisierul %s", filenameKeyAes);
	}

	crypto.CalculateHash(cipherText, strlen(plainText), &hash, hashLength);
	crypto.SignHash(hash, hashLength, tag, TAG_LENGTH, aesKey, aesKeyLength, &signature);

	res = crypto.SaveFinalData(filenameFinal, cipherText, strlen(plainText), algorithm, strlen(algorithm), signature, hashLength);
	if (res == CRYPTO_SUCCES) {

		printf("Datele au fost criptate cu succes si salvate in: %s\n", filenameFinal);
	}
	else {
		printf("Datele nu au putut fi criptate\n");
	}
}
void Decrypt() {

	CryptoSystem crypto;
	KeyGenerator generator;
	char filenameAesKey[100];
	char filanemChachaKey[100];
	char filenameData[100];
	char password[100];
	int res;

	ASN_AES_KEY* aesKeyStructure;
	int aesKeyLength;
	unsigned char* aesKey;

	int chachaKeyLength;
	unsigned char* chachaKey;

	int cipherTectLength;
	unsigned char* cipherText = nullptr;
	int signatureLength;
	unsigned char* signature = nullptr;
	int algorithmLength;
	char* algorithm = nullptr;

	unsigned char* plainText = nullptr;

	ClearScreen();


	printf("Introduceti fisier cheie AES: ");
	scanf("%s", filenameAesKey);

	printf("Introduceti parola: ");
	scanf("%s", password);

	printf("Introduceti fisier de decriptat: ");
	scanf("%s", filenameData);


	//load and decrypt aes key
	aesKeyStructure = generator.LoadAesKeyStructure(filenameAesKey);
	if (aesKeyStructure == nullptr)
		exit(1);
	generator.DecryptAesEncKey(aesKeyStructure, (unsigned char*)password, strlen(password), &aesKey, aesKeyLength);

	res = crypto.LoadFinalData(filenameData, &cipherText, cipherTectLength, &algorithm, algorithmLength, &signature, signatureLength);
	if (res == CRYPTO_ERROR)
		exit(1);

	if (algorithm[0] == 'a') {

		if (aesKeyLength == 16) {

			crypto.Decrypt_aes128_gcm(cipherText, cipherTectLength, aesKey, aesKeyLength, (const unsigned char*)password, strlen(password), &plainText, nullptr);
		}
		else if (aesKeyLength = 24) {

			crypto.Decrypt_aes192_gcm(cipherText, cipherTectLength, aesKey, aesKeyLength, (const unsigned char*)password, strlen(password), &plainText, nullptr);
		}
		else if (aesKeyLength = 32) {

			crypto.Decrypt_aes256_gcm(cipherText, cipherTectLength, aesKey, aesKeyLength, (const unsigned char*)password, strlen(password), &plainText, nullptr);
		}
		else {

			printf("Lungime cheie gresita in fisierul %s", filenameAesKey);
		}
	}
	else if (algorithm[0] == 'c') {

		printf("Introduceti fisier cheie chacha20: ");
		scanf("%s", filanemChachaKey);

		//load chacha key
		generator.LoadKeyFromFileOctetString(filanemChachaKey, &chachaKey, chachaKeyLength);

		crypto.Decrypt_chacha20_tag(cipherText, cipherTectLength, chachaKey, chachaKeyLength, (const unsigned char*)password, strlen(password), &plainText, nullptr);
	}

	printf("\nTextul decriptat: \n");
	if (plainText != nullptr) {
		fwrite(plainText, 1, cipherTectLength, stdout);
		printf("\n\n");
	}
	else
		printf("N am putut decripta. Scuze\n");
}

void PrintMenu() {

	ClearScreen();
	printf("\t\t MENU\n\n");
	printf("Apasa (+ENTER):\n");
	printf("\t1. Generare cheie ChaCha20\n");
	printf("\t2. Generare cheie Aes\n");
	printf("\t3. Cripteaza ChaCha20_poly1305\n");
	printf("\t4. Cripteaza Aes_gcm\n");
	printf("\t5. Decripteaza\n");
	printf("\t6. Exit\n");
}
int ChooseOption() {

	int option;
	scanf("%d", &option);
	switch (option)
	{
	case 1:
		GenerateKeyChaCha20();
		break;
	case 2:
		GenerateKeyAes();
		break;
	case 3:
		EncryptChaCha();
		break;
	case 4:
		EncryptAes();
		break;
	case 5:
		Decrypt();
		break;
	case 6:
		exit(1);
		break;
	default:
		return -1;
		break;
	}
	return 0;
}

void Run() {

	int loop = 1;
	int res;
	while (loop == 1) {

		PrintMenu();

		res = ChooseOption();

		if (res == 0) {
			printf("Apasa orice pentru a reveni la MENU\n");
			_getch();
		}
	}
}

int main(int argc, char** argv) {

	Run();
}