/* Implement the following API.
 * You can add your own functions, but don't modify below this line.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "aes128e.h"

/* Under the 16-byte (128-bit) key "k", 
and the 12-byte (96-bit) initial value "IV", 
encrypt the plaintext "plaintext" and store it at "ciphertext". 
The length of the plaintext is a multiple of 16-byte (128-bit) given by len_p (e.g., len_p = 2 for a 32-byte plaintext). 
The length of the ciphertext "ciphertext" is len_p*16 bytes. 
The authentication tag is obtained by the 16-byte tag "tag". 
For the authentication an additional data "add_data" can be added. 
The number of blocks for this additional data is "len_ad" (e.g., len_ad = 1 for a 16-byte additional data). 
*/

void aes128gcm(unsigned char *ciphertext, unsigned char *tag, const unsigned char *k, const unsigned char *IV, const unsigned char *plaintext, const unsigned long len_p, const unsigned char* add_data, const unsigned long len_ad);
