#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <time.h> 
#include <omp.h>


#define Nb 4
#define Nk(keysize) ((int)(keysize / 32))
#define Nr(keysize) ((int)(Nk(keysize) + 6))

/* State and key types */
typedef uint8_t** State;
typedef uint8_t* Key;

/* My additional methods */
void encrypt(char* plain, char* key);
void decrypt(char* cipher, char* key);
State* toState(uint8_t* input);
uint8_t** fromState(State* state);
void freeState(State* state);
void stringToBytes(char* str, uint8_t* bytes);

/* AES main methods */
uint8_t** Cipher(uint8_t* input, uint8_t* keySchedule, size_t keySize);
uint8_t** InvCipher(uint8_t* input, uint8_t* w, size_t keySize);

/* AES sub-methods */
void _SubBytes(State* state, const uint8_t* box);
void SubBytes(State* state);
void InvSubBytes(State* state);
void _ShiftRows(State* state, int multiplier);
void ShiftRows(State* state);
void InvShiftRows(State* state);
void MixColumns(State* state);
void InvMixColumns(State* state);
void AddRoundKey(State* state, uint8_t* roundKey);
void KeyExpansion(uint8_t* key, uint8_t* keySchedule, size_t keySize);

/* AES sub-sub-methods and round constant array */
uint8_t* SubWord(uint8_t* a);
uint8_t* RotWord(uint8_t* a);
uint8_t* Rcon(int a);

/* AES helper methods */
uint8_t* xorWords(uint8_t* a, uint8_t* b);
uint8_t* copyWord(uint8_t* start);
uint8_t* getWord(uint8_t* w, int i);
uint8_t galoisMultiply(uint8_t a, uint8_t b);


const uint8_t sbox[] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
const uint8_t isbox[] = {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};
int main(){

    /* Examples of encryption */
    printf("ENCRYPTION:\n");
     clock_t start, end; // Added clock_t variables
    double cpu_time_used; // Added double to store execution time
    start = clock();
    #pragma omp parallel for
    for (int i = 0; i < 4; i++) {
        switch(i){
            case 0: 
                encrypt("3243f6a8885a308d313198a2e0370734", "2b7e151628aed2a6abf7158809cf4f3c"); /* Appendix B example */
                break;
            case 1: 
                encrypt("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f"); /* Appendix C 128-bit example */
                break;
            case 2: 
                encrypt("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f1011121314151617"); /* Appendix C 192-bit example */
                break;
            case 3: 
                encrypt("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"); /* Appendix C 256-bit example */
                break;
        }
    }
    end = clock(); // Get end time
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC; // Calculate execution time
    printf("Time taken: %f seconds\n", cpu_time_used); 
  
}

void AES_main(char* text, char* keyStr, int encrypting){
    /* 
       Takes a 128-bit hexadecimal string plaintext and
       128-, 192- or 256- bit hexadecimal string key and
       applies AES encryption or decryption. 
    */
    uint8_t *keySchedule, **output;
    int i;
    /* Convert input string to state */
    uint8_t* input = malloc(sizeof(uint8_t) * 16);
    stringToBytes(text, input);
    /* Convert key string to bytes */
    size_t keyBytes = (sizeof(uint8_t)*strlen(keyStr))/2;
    Key key = malloc(keyBytes);
    stringToBytes(keyStr, key);
    /* Convert number of bytes to bits */
    size_t keySize = keyBytes * 8;
    /* Create array for key schedule */
    keySchedule = calloc(4 * Nb * (Nr(keySize) + 1), sizeof(uint8_t));
    /* Expand key */
    KeyExpansion(key, keySchedule, keySize);
    /* Run cipher */
    if(encrypting){
        output = Cipher(input, keySchedule, keySize);
    } /*else{
        output = InvCipher(input, keySchedule, keySize);
    }*/
    /* Display result */
    for(i = 0; i < 16; i++){
        printf("%02x", (*output)[i]);
    }
    printf("\n");
    /* Free memory */
    free(input);
    free(key);
    free(keySchedule);
    free(*output);
    free(output);
}

void encrypt(char* plaintext, char* keyStr){
    AES_main(plaintext, keyStr, 1);
}

/*void decrypt(char* ciphertext, char* keyStr){
    AES_main(ciphertext, keyStr, 0);
}*/

/* 
    AES main methods
*/
void KeyExpansion(uint8_t* key, uint8_t* w, size_t keySize){
    /*
        Takes a 128-, 192- or 256-bit key and applies the
        key expansion algorithm to produce a key schedule.
    */
    int i, j;
    uint8_t *wi, *wk, *temp, *rconval;
    /* Copy the key into the first Nk words of the schedule */
    for(i = 0; i < Nk(keySize); i++){
        for(j = 0; j < Nb; j++){
            w[4*i+j] = key[4*i+j];
        }
    }
    i = Nk(keySize);
    /* Generate Nb * (Nr + 1) additional words for the schedule */
    while(i < Nb * (Nr(keySize) + 1)){
        /* Copy the previous word */
        temp = copyWord(getWord(w, i-1));
        if(i % Nk(keySize) == 0){
            /* If i is divisble by Nk, rotate and substitute the word
               and then xor with Rcon[i/Nk] */
            rconval = Rcon(i/Nk(keySize));
            xorWords(SubWord(RotWord(temp)), rconval);
            free(rconval);
        } else if(Nk(keySize) > 6 && i % Nk(keySize) == 4){
            /* If Nk > 6 and i mod Nk is 4 then just substitute */
            memcpy(temp, SubWord(temp), 4);
        }
        /* Get pointers for the current word and the (i-Nk)th word */
        wi = getWord(w, i);
        wk = getWord(w, i - Nk(keySize));
        /* wi = temp xor wk */
        memcpy(wi, xorWords(temp, wk), 4);
        free(temp);
        i++;
    }
}

uint8_t** Cipher(uint8_t* input, uint8_t* w, size_t keySize){
    /*
        AES Cipher method - Takes a 128 bit array of bytes and
        the key schedule and applies the cipher algorithm,
        returning a pointer to an array of output.
    */
    int i;
    uint8_t** output;
    State* state = toState(input);

    /* Cipher method */
    AddRoundKey(state, getWord(w, 0));
    for(i = 1; i < Nr(keySize); i++){
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, getWord(w, i*Nb));
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, getWord(w, Nr(keySize)*Nb));
    
    output = fromState(state);
    freeState(state);
    return output;
}

/* uint8_t** InvCipher(uint8_t* input, uint8_t* w, size_t keySize){
   
    int i;
    uint8_t** output;
    State* state = toState(input);


    AddRoundKey(state, getWord(w, Nr(keySize) * Nb));
    for(i = Nr(keySize) - 1; i >= 1; i--){
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, getWord(w, i*Nb));
        InvMixColumns(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, getWord(w, 0));

    output = fromState(state);
    freeState(state);
    return output;
} */

/*
    State to/from and helper methods
*/
State* toState(uint8_t* input){
    /*
        Takes an array of bytes and returns
        a pointer to a State.
    */
    int i, j;
    /* Malloc state pointer and state.
       The state pointer is returned because
       it is more useful than the state itself */
    State* stateptr = malloc(sizeof(State));
    *stateptr = malloc(4 * sizeof(uint8_t*));
    State state = *stateptr;
    for(i = 0; i < 4; i++){
        state[i] = malloc(Nb * sizeof(uint8_t));
    }
    /* Fill state */
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
            /* Set value in state array to current byte
               j and i are swapped because the input is
               transposed */
            state[j][i] = *input;
            /* Increment pointer */
            input++;
        }
    }
    return stateptr;
}

uint8_t** fromState(State* state){
    /*
        Takes a State and returns a pointer
        to an array of bytes.
    */
    int i, j;
    /* Malloc outputptr and output */
    uint8_t** outputptr = malloc(sizeof(uint8_t*));
    *outputptr = malloc(sizeof(uint8_t) * 16);
    uint8_t* output = *outputptr;
    /* Fill output */
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
            /* Set the output to it's array item,
               transposing the state */
            *output = (*state)[j][i];
            /* Increment the pointer */
            output++;
        }
    }
    return outputptr;
}

void freeState(State* state){
    /*
        Free the memory used by each row, the
        state itself and the pointer to the state.
    */
    int i;
    for(i = 0; i < 4; i++){
        free((*state)[i]);
    }
    free(*state);
    free(state);
}

void stringToBytes(char* str, uint8_t* bytes){
    /*
        Converts a hexadecimal string of bytes into an
        array of uint8_t.
    */
    int i;
    for(i = 0; i < strlen(str) - 1; i += 2){
        /* Allocate space for pair of nibbles */
        char* pair = malloc(2 * sizeof(char));
        /* Copy current and next character to pair */
        memcpy(pair, &str[i], 2);
        /* Use strtol to convert string to long, which is
           implicitly converted to a uint8_t. This is stored
           in index i/2 as there are half as many bytes as
           hex characters */
        bytes[i/2] = strtol(pair, NULL, 16);
        free(pair);
    }
}

/*
    AES sub-methods
*/
void _SubBytes(State* state, const uint8_t* box){
    /*
        Generalised SubBytes method which takes the
        S-box to use as an argument.
    */
    int i, j;
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
            /* Get the new value from the S-box */
            uint8_t new = box[(*state)[i][j]];
            (*state)[i][j] = new;
        }
    }
}

void SubBytes(State* state){
    _SubBytes(state, sbox);
}

/*void InvSubBytes(State* state){
    _SubBytes(state, isbox);
} */

void _ShiftRows(State* state, int multiplier){
    /*
        Generalised ShiftRows method which takes a multiplier
        which affects the shift direction.
    */
    int i, j;
    for(i = 0; i < 4; i++){
        /* The row number is the number of shifts to do */
        uint8_t temp[4];
        for(j = 0; j < Nb; j++){
            /* The multiplier determines whether to do a left or right shift */
            temp[((j + Nb) + (multiplier * i)) % Nb] = (*state)[i][j];
        }
        /* Copy temp array to state array */
        memcpy((*state)[i], temp, 4);
    }
}

void ShiftRows(State* state){
    _ShiftRows(state, -1);
}

/*void InvShiftRows(State* state){
    _ShiftRows(state, 1);
}*/

uint8_t galoisMultiply(uint8_t a, uint8_t b){
    /*
        Multiplies two bytes in the 2^8 Galois field.
        Implementation based on description from https://e...content-available-to-author-only...a.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
    */
    uint8_t p = 0;
    int i;
    int carry;
    for(i = 0; i < 8; i++){
        if((b & 1) == 1){
            p ^= a;
        }
        b >>= 1;
        carry = a & 0x80;
        a <<= 1;
        if(carry == 0x80){
            a ^= 0x1b;
        }
    }
    return p;
}

void MixColumns(State* state){
    /*
        Applies the MixColumns method to the state.
        See Section 5.1.3 of the standard for explanation.
    */
    int c, r;
    for(c = 0; c < Nb; c++){
        uint8_t temp[4];
        temp[0] = galoisMultiply((*state)[0][c], 2) ^ galoisMultiply((*state)[1][c], 3) ^ (*state)[2][c] ^ (*state)[3][c];
        temp[1] = (*state)[0][c] ^ galoisMultiply((*state)[1][c], 2) ^ galoisMultiply((*state)[2][c], 3) ^ (*state)[3][c];
        temp[2] = (*state)[0][c] ^ (*state)[1][c] ^ galoisMultiply((*state)[2][c], 2) ^ galoisMultiply((*state)[3][c], 3);
        temp[3] = galoisMultiply((*state)[0][c], 3) ^ (*state)[1][c] ^ (*state)[2][c] ^ galoisMultiply((*state)[3][c], 2);
        /* Copy temp array to state */
        for(r = 0; r < 4; r++){
            (*state)[r][c] = temp[r];
        }
    }
}

/*void InvMixColumns(State* state){
   
    int c, r;
    for(c = 0; c < Nb; c++){
        uint8_t temp[4];
        temp[0] = galoisMultiply((*state)[0][c], 14) ^ galoisMultiply((*state)[1][c], 11) ^ galoisMultiply((*state)[2][c], 13) ^ galoisMultiply((*state)[3][c], 9);
        temp[1] = galoisMultiply((*state)[0][c], 9)  ^ galoisMultiply((*state)[1][c], 14) ^ galoisMultiply((*state)[2][c], 11) ^ galoisMultiply((*state)[3][c], 13);
        temp[2] = galoisMultiply((*state)[0][c], 13) ^ galoisMultiply((*state)[1][c], 9)  ^ galoisMultiply((*state)[2][c], 14) ^ galoisMultiply((*state)[3][c], 11);
        temp[3] = galoisMultiply((*state)[0][c], 11) ^ galoisMultiply((*state)[1][c], 13) ^ galoisMultiply((*state)[2][c], 9)  ^ galoisMultiply((*state)[3][c], 14);
       
        for(r = 0; r < 4; r++){
            (*state)[r][c] = temp[r];
        }
    }
} */

void AddRoundKey(State* state, uint8_t* roundKey){
    /*
        Takes a pointer to the start of a round key
        and XORs it with the columns of the state.
    */
    int c, r;
    for(c = 0; c < Nb; c++){
        for(r = 0; r < 4; r++){
            /* XOR each column with the round key */
            (*state)[r][c] ^= *roundKey;
            roundKey++;
        }
    }
}

/*
    AES sub-sub-methods
*/
uint8_t* SubWord(uint8_t* a){
    /*
        Substitute bytes in a word using the sbox.
    */
    int i;
    uint8_t* init = a;
    for(i = 0; i < 4; i++){
        *a = sbox[*a];
        a++;
    }
    return init;
}

uint8_t* RotWord(uint8_t* a){
    /*
        Rotate word then copy to pointer.
    */
    uint8_t rot[] = {a[1], a[2], a[3], a[0]};
    memcpy(a, rot, 4);
    return a;
}

uint8_t* Rcon(int a){
    /* Calculates the round constant and returns it in an array.
       This implementation is adapted from
       https://g...content-available-to-author-only...b.com/secworks/aes/blob/6fb0aef25df082d68da9f75e2a682441b5f9ff8e/src/model/python/rcon.py#L180
    */
    uint8_t rcon = 0x8d;
    int i;
    for(i = 0; i < a; i++){
        rcon = ((rcon << 1) ^ (0x11b & - (rcon >> 7)));
    }
    /* The round constant array is always of the form [rcon, 0, 0, 0] */
    uint8_t* word = calloc(4, sizeof(uint8_t));
    word[0] = rcon;
    return word;
}

/*
    Word helper methods
*/
uint8_t* xorWords(uint8_t* a, uint8_t* b){
    /* Takes the two pointers to the start of 4 byte words and
       XORs the words, overwriting the first. Returns a pointer to
       the first byte of the first word. */
    int i;
    uint8_t* init = a;
    for(i = 0; i < 4; i++, a++, b++){
        *a ^= *b;
    }
    return init;
}

uint8_t* copyWord(uint8_t* start){
    /*
        Returns a pointer to a copy of a word.
    */
    int i;
    uint8_t* word = malloc(sizeof(uint8_t) * 4);
    for(i = 0; i < 4; i++, start++){
        word[i] = *start;
    }
    return word;
}

uint8_t* getWord(uint8_t* w, int i){
    /*
        Takes a word number (w[i] in spec) and
        returns a pointer to the first of it's 4 bytes.
    */
    return &w[4*i];
}
