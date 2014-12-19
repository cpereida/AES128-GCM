/*****************************************************************************/
/* Implementation of AES 128 bit                                             
  
	Author: Cesar Pereida                                         
	Student Number: 466408

	The following is a basic implementation of AES 128 bit key only.

	NOTE: We assume that both plaintext and key are 16 bytes long.

																			 */
/*****************************************************************************/

  // ************************************************************************//
 // Includes		                                                        //
// ************************************************************************//
#include <stdio.h>		// Used for printing and debugging
#include <stdint.h>
#include "aes128e.h"

  // ************************************************************************//
 // Definitions		                                                        //
// ************************************************************************//

/* Key Length */
#define Nk 4
/* Block Size */
#define Nb 4
/* Number of Rounds */
#define Nr 10

  // ************************************************************************ //
 // Private variables                                                        //
// ************************************************************************ //

/* State array */
static unsigned char stateMatrix[4][4];
/* All the Round Keys */
static unsigned char roundKeys[Nb * Nk * (Nr + 1)];
/* Round counter */
static unsigned char roundNumber;

/* Multiplication by two in GF(2^8). Multiplication by three is xtime(a) ^ a */
#define xtime(a) ( ((a) & 0x80) ? (((a) << 1) ^ 0x1b) : ((a) << 1) )

/* The S-box table */
static const unsigned char sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; // F

/* The round constant table (needed in KeyExpansion) */
static const unsigned char rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 
    0x20, 0x40, 0x80, 0x1b, 0x36 };

  // ************************************************************************ //
 // Private functions                                                        //
// ************************************************************************ //

/* Method used for printing arrays with 4 by 4 values in Hex format 
static void Print(unsigned char myarray[4][4]) {		
	
	unsigned char i, j;

	for(i = 0; i < Nb; i++) 
	{
		for(j = 0; j < Nb; j++) 
		{
			printf("%#x ", myarray[i][j]);		// Print state array 
		}
		printf("%s\n", "");
	}
	printf("%s\n", "");
}*/

/* Method used for printing values in one dimension arrays 
static void PrintVector(unsigned char *myArray, unsigned char arraySize) {		
	
	unsigned char i, j;

	for(i = 0; i < arraySize; i++) 
	{
		printf("%#X ", myArray[i]);
	}
}*/

/* Return the Sbox translated value of a word, submethod of KeyExpansion function  */
static void SubWord(unsigned char word[4]) {
	word[0] = sbox[word[0]];
	word[1] = sbox[word[1]];
	word[2] = sbox[word[2]];
	word[3] = sbox[word[3]];
}

/* Key values (word) are rotated to the left, submethod of KeyExpansion function */
static void RotWord(unsigned char word[4]) {
	
	unsigned char tempRot;	// use of tempRot to hold the value of the first byte

	tempRot = word[0];									
	word[0] = word[1];
	word[1] = word[2];
	word[2] = word[3];
	word[3] = tempRot;
}

/* Method to expand the key, only for AES128 */
static void KeyExpansion128(const unsigned char *key) {	

	unsigned char temp[4], i, j;

	/* Initial round key values of the key expansion */
	for (i = 0; i < Nb * Nk; i++) 
	{
		roundKeys[i] = key[i];							// We get the first 4 bytes directly from the original key
	}

	for (; i < Nb * Nk * (Nr + 1); i++)			// Iterate through the 176 - 4 bytes array
	{
		if (i % (Nk * Nb) == 0)							// If i % 16 == 0, we use the temp variable to store 4 bytes at a time
		{
			temp[0] = roundKeys[(i - Nk) + 0];			// We get the last 4 bytes from the roundKeys and store at temp
			temp[1] = roundKeys[(i - Nk) + 1];
			temp[2] = roundKeys[(i - Nk) + 2];
			temp[3] = roundKeys[(i - Nk) + 3];

			RotWord(temp);								// Last 4 bytes are rotated
			SubWord(temp);								// Last 4 bytes are replaced with Sbox values

			temp[0] = temp[0] ^ rcon[i / (Nk * Nb) - 1];// The leftmost byte of temp is multiplied with rcon[round] in GF(2)

			roundKeys[i + 0] = roundKeys[i - (Nb * Nk) + 0] ^ temp[0];	// First byte of temp is XORed with byte 16 positions before
			roundKeys[i + 1] = roundKeys[i - (Nb * Nk) + 1] ^ temp[1];	// Second byte of temp is XORed with byte 16 positions before
			roundKeys[i + 2] = roundKeys[i - (Nb * Nk) + 2] ^ temp[2];	// Third byte of temp is XORed with byte 16 positions before
			roundKeys[i + 3] = roundKeys[i - (Nb * Nk) + 3] ^ temp[3];	// Fourth byte of temp is XORed with byte 16 positions before

			i += 3;	// If we use the temp variable, then index needs to be added by 3 (plus the addition of the iteration)
		} 
		else 
		{
			roundKeys[i] = roundKeys[i - Nk] ^ roundKeys[i - (Nb * Nk)]; // Current byte == roundKeys 4 positions before XORed with roundKeys of 16 positions before
		}
	}
	//PrintVector(roundKeys, sizeof(roundKeys) / sizeof(roundKeys[0]));
}

/* Method used to add the roundKeys to the state array */
static void AddRoundKey() {

	unsigned char tempRoundKeys[4][4], i, j, tempArray[4];

	// Round keys are grabbed byte-by-byte on each round and stored in a temporal 4x4 matrix
	for(i = 0; i < Nb; i++) 
	{
		tempArray[0] = roundKeys[Nk * (i + roundNumber * Nb) + 0];	// First  byte of roundKeys[roundNumber] is grabbed and stored in tempArray 
		tempArray[1] = roundKeys[Nk * (i + roundNumber * Nb) + 1];	// Second byte of roundKeys[roundNumber] is grabbed and stored in tempArray
		tempArray[2] = roundKeys[Nk * (i + roundNumber * Nb) + 2];	// Third  byte of roundKeys[roundNumber] is grabbed and stored in tempArray
		tempArray[3] = roundKeys[Nk * (i + roundNumber * Nb) + 3];	// Fourth byte of roundKeys[roundNumber] is grabbed and stored in tempArray

		// iterate from 0 to 3 to fill the 4 columns
		for(j = 0; j < Nb; j++) 
		{
			tempRoundKeys[j][i] = tempArray[j];	// Four bytes are stored in the j column of tempRoundKeys
		}
	}

	//printf("%s\n", "");
	//Print(tempRoundKeys);

	for(i = 0; i < Nb; i++) 
	{
		for(j = 0; j < Nb; j++) 
		{
			stateMatrix[i][j] = stateMatrix[i][j] ^ tempRoundKeys[i][j];	// Round keys of the current round (tempRoundKeys) are XORed with state matrix
		}
	}
	//printf("%s\n", "");
	//Print(stateMatrix);
}

/* State values are mapped to the Sbox values */
static void SubBytes() {

	unsigned char i, j;

	for(i = 0; i < Nb; i++)
	{
		for(j = 0; j < Nb; j++)
		{
			stateMatrix[i][j] = sbox[stateMatrix[i][j]];
		}
	}
	//Print(stateMatrix);
}

/* Row bytes are shifted. Row N[i][] is shifted to the left by i bytes */
static void ShiftRows() {

	unsigned char tempRow;

	// Row N[1][] (second row) is shifted to the left by 1 byte
	tempRow = stateMatrix[1][0];
	stateMatrix[1][0] = stateMatrix[1][1];
	stateMatrix[1][1] = stateMatrix[1][2];
	stateMatrix[1][2] = stateMatrix[1][3];
	stateMatrix[1][3] = tempRow;

	// Row N[2][] (third row) is shifted to the left by 2 bytes
	tempRow = stateMatrix[2][0];
	stateMatrix[2][0] = stateMatrix[2][2];
	stateMatrix[2][2] = tempRow;

	tempRow = stateMatrix[2][1];
	stateMatrix[2][1] = stateMatrix[2][3];
	stateMatrix[2][3] = tempRow;

	// Row N[3][] (fourth row) is shifted to the left by 3 bytes
	tempRow = stateMatrix[3][3];
	stateMatrix[3][3] = stateMatrix[3][2];
	stateMatrix[3][2] = stateMatrix[3][1];
	stateMatrix[3][1] = stateMatrix[3][0];
	stateMatrix[3][0] = tempRow;
}

static void MixColumns() {

	unsigned char i, j, tempCell[4];

	for(i = 0; i < Nb; i++)
	{
		tempCell[0] = (xtime(stateMatrix[0][i])
					^ (xtime(stateMatrix[1][i]) ^ stateMatrix[1][i]) 
				   	^ (stateMatrix[2][i])
				   	^ (stateMatrix[3][i]));			// ({02} • s0c ) ({03} • s1c ) (s2c) (s3c)

		tempCell[1] = (stateMatrix[0][i]
					^ (xtime(stateMatrix[1][i]))
					^ (xtime(stateMatrix[2][i]) ^ stateMatrix[2][i]) 
				   	^ (stateMatrix[3][i]));			// (s0c) ({02} • s1c ) ({03} • s2c) (s3c)

		tempCell[2] = (stateMatrix[0][i] 
					^  stateMatrix[1][i]
					^ (xtime(stateMatrix[2][i]))
					^ (xtime(stateMatrix[3][i]) ^ stateMatrix[3][i]));	// (s0c) (s1c) ({02} • s2c) ({03} • s3c)

		tempCell[3] = ((xtime(stateMatrix[0][i]) ^ stateMatrix[0][i])	// ({03} • s0c) (s1c) (s2c) ({02} • s3c)
					^  stateMatrix[1][i] 
					^  stateMatrix[2][i]
					^ (xtime(stateMatrix[3][i])));

		for(j = 0; j < Nb; j++)
		{
			stateMatrix[j][i] = tempCell[j];	// Push each value from tempCell to stateMatrix
		}
	}
}

/* Under the 16-byte key at k, encrypt the 16-byte plaintext at p and store it at c. */
void aes128e(unsigned char *c, const unsigned char *p, const unsigned char *k) {

	KeyExpansion128(k);

	for(unsigned char i = 0; i < Nb; i++) 
	{
		for(unsigned char j = 0; j < Nb; j++) 
		{
			stateMatrix[j][i] = p[(i * Nb) + j];	// Fill state array with values from plaintext p filling column by column
		}
	}
	
	roundNumber = 0;								// Initialize roundNumber to 0
	AddRoundKey();									// First key added

	// Iterate the process by Nr - 1 times which is 9 (10 - 1) times for 128 AES 
	for (roundNumber = 1; roundNumber < Nr; ++roundNumber) 
	{
		SubBytes();									// Bytes are substituted by Sbox values
		ShiftRows();								// Bytes rows are shifted to the left by N bytes 
		MixColumns();								// Byte columns are multiplied by a constant to mix the columns
		AddRoundKey();								// Round key added to the stateMatrix
		//Print(stateMatrix);
		//printf("%s%d\n", "Round: ", roundNumber);		
	}

	// The last round does not include MixColumns but adds a final round key
	SubBytes();
	ShiftRows();
	AddRoundKey();

	//Print(stateMatrix);

	for(unsigned char i = 0; i < Nb; i++)
	{
		for(unsigned char j = 0; j < Nb; j++)
		{
			c[(i * Nb) + j] = stateMatrix[j][i];	// stateMatrix values are stored in c
		}
	}
	//PrintVector(c, sizeof(c) / sizeof(c[0]));	
}