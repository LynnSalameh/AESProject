#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <time.h> 
#include "mpi.h"

#define Nb 4
#define Nk(keysize) ((int)(keysize / 32))
#define Nr(keysize) ((int)(Nk(keysize) + 6))

typedef uint8_t** State;
typedef uint8_t* Key;

void AES_main(char* text, char* keyStr, int encrypting);

void encrypt(char* plain, char* key);
void decrypt(char* cipher, char* key);
State* toState(uint8_t* input);
uint8_t** fromState(State* state);
void freeState(State* state);
void stringToBytes(char* str, uint8_t* bytes);

uint8_t** Cipher(uint8_t* input, uint8_t* keySchedule, size_t keySize);
uint8_t** InvCipher(uint8_t* input, uint8_t* w, size_t keySize);
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

uint8_t* SubWord(uint8_t* a);
uint8_t* RotWord(uint8_t* a);
uint8_t* Rcon(int a);

uint8_t* xorWords(uint8_t* a, uint8_t* b);
uint8_t* copyWord(uint8_t* start);
uint8_t* getWord(uint8_t* w, int i);
uint8_t galoisMultiply(uint8_t a, uint8_t b);


const uint8_t sbox[] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
const uint8_t isbox[] = {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

int main(int argc, char **argv) {
    int rank, size;

    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    printf("ENCRYPTION:\n");
    double start, end; // Added double variables for timing
    double cpu_time_used; // Added double to store execution time
    start = MPI_Wtime();
    
    int n = 4;
    int chunksize = 4 /size; 
    int remainder = 4 % size;
    int start_idx = rank * chunksize + (rank < remainder ? rank : remainder);
    int end_idx = start_idx + chunksize + (rank < remainder ? 1 : 0);

    char *plaintext[4] = {"3243f6a8885a308d313198a2e0370734",
                          "00112233445566778899aabbccddeeff",
                          "00112233445566778899aabbccddeeff",
                          "00112233445566778899aabbccddeeff"};
    char *key[4] = {"2b7e151628aed2a6abf7158809cf4f3c",
                    "000102030405060708090a0b0c0d0e0f",
                    "000102030405060708090a0b0c0d0e0f1011121314151617",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"};
    char *part_plain[n];
    char *part_key[n];
    for (int i = 0; i < n; i++) {
        part_plain[i] = plaintext[start_idx + i];
        part_key[i] = key[start_idx + i];
    }

    for (int i = 0; i < n; i++) {
        AES_main(part_plain[i], part_key[i], 1);
    }

    MPI_Barrier(MPI_COMM_WORLD); 
    end = MPI_Wtime(); 
    cpu_time_used = end - start; 
    printf("Time taken: %f seconds\n", cpu_time_used);

    MPI_Finalize();
    return 0;
}

void AES_main(char* text, char* keyStr, int encrypting){
  
    uint8_t *keySchedule, **output;
    int i;
  
    uint8_t* input = malloc(sizeof(uint8_t) * 16);
    stringToBytes(text, input);

    size_t keyBytes = (sizeof(uint8_t)*strlen(keyStr))/2;
    Key key = malloc(keyBytes);
    stringToBytes(keyStr, key);

    size_t keySize = keyBytes * 8;
 
    keySchedule = calloc(4 * Nb * (Nr(keySize) + 1), sizeof(uint8_t));
    
    KeyExpansion(key, keySchedule, keySize);
  
    if(encrypting){
        output = Cipher(input, keySchedule, keySize);
    }
   
    for(i = 0; i < 16; i++){
        printf("%02x", (*output)[i]);
    }
    printf("\n");
    free(input);
    free(key);
    free(keySchedule);
    free(*output);
    free(output);
}

void encrypt(char* plaintext, char* keyStr){
    AES_main(plaintext, keyStr, 1);
}

void KeyExpansion(uint8_t* key, uint8_t* w, size_t keySize){
    int i, j;
    uint8_t *wi, *wk, *temp, *rconval;
    for(i = 0; i < Nk(keySize); i++){
        for(j = 0; j < Nb; j++){
            w[4*i+j] = key[4*i+j];
        }
    }
    i = Nk(keySize);
    while(i < Nb * (Nr(keySize) + 1)){
        
        temp = copyWord(getWord(w, i-1));
        if(i % Nk(keySize) == 0){
          
            rconval = Rcon(i/Nk(keySize));
            xorWords(SubWord(RotWord(temp)), rconval);
            free(rconval);
        } else if(Nk(keySize) > 6 && i % Nk(keySize) == 4){
            
            memcpy(temp, SubWord(temp), 4);
        }

        wi = getWord(w, i);
        wk = getWord(w, i - Nk(keySize));
     
        memcpy(wi, xorWords(temp, wk), 4);
        free(temp);
        i++;
    }
}

uint8_t** Cipher(uint8_t* input, uint8_t* w, size_t keySize){
  
    int i;
    uint8_t** output;
    State* state = toState(input);

   
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


State* toState(uint8_t* input){
   
    int i, j;

    State* stateptr = malloc(sizeof(State));
    *stateptr = malloc(4 * sizeof(uint8_t*));
    State state = *stateptr;
    for(i = 0; i < 4; i++){
        state[i] = malloc(Nb * sizeof(uint8_t));
    }
   
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
           
            state[j][i] = *input;
           
            input++;
        }
    }
    return stateptr;
}

uint8_t** fromState(State* state){
    
    int i, j;
    
    uint8_t** outputptr = malloc(sizeof(uint8_t*));
    *outputptr = malloc(sizeof(uint8_t) * 16);
    uint8_t* output = *outputptr;
 
    for(i = 0; i < 4; i++){
        for(j = 0; j < Nb; j++){
          
            *output = (*state)[j][i];
           
            output++;
        }
    }
    return outputptr;
}

void freeState(State* state){
   
    int i;
    for(i = 0; i < 4; i++){
        free((*state)[i]);
    }
    free(*state);
    free(state);
}

void stringToBytes(char* str, uint8_t* bytes){
   
    int i;
    for(i = 0; i < strlen(str) - 1; i += 2){

        char* pair = malloc(2 * sizeof(char));
      
        memcpy(pair, &str[i], 2);
        
        bytes[i/2] = strtol(pair, NULL, 16);
        free(pair);
    }
}


void _SubBytes(State* state, const uint8_t* box){
    
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



void _ShiftRows(State* state, int multiplier){
  
    int i, j;
    for(i = 0; i < 4; i++){
        /* The row number is the number of shifts to do */
        uint8_t temp[4];
        for(j = 0; j < Nb; j++){
           
            temp[((j + Nb) + (multiplier * i)) % Nb] = (*state)[i][j];
        }
      
        memcpy((*state)[i], temp, 4);
    }
}

void ShiftRows(State* state){
    _ShiftRows(state, -1);
}



uint8_t galoisMultiply(uint8_t a, uint8_t b){
   
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
   
    int c, r;
    for(c = 0; c < Nb; c++){
        uint8_t temp[4];
        temp[0] = galoisMultiply((*state)[0][c], 2) ^ galoisMultiply((*state)[1][c], 3) ^ (*state)[2][c] ^ (*state)[3][c];
        temp[1] = (*state)[0][c] ^ galoisMultiply((*state)[1][c], 2) ^ galoisMultiply((*state)[2][c], 3) ^ (*state)[3][c];
        temp[2] = (*state)[0][c] ^ (*state)[1][c] ^ galoisMultiply((*state)[2][c], 2) ^ galoisMultiply((*state)[3][c], 3);
        temp[3] = galoisMultiply((*state)[0][c], 3) ^ (*state)[1][c] ^ (*state)[2][c] ^ galoisMultiply((*state)[3][c], 2);
       
        for(r = 0; r < 4; r++){
            (*state)[r][c] = temp[r];
        }
    }
}



void AddRoundKey(State* state, uint8_t* roundKey){
   
    int c, r;
    for(c = 0; c < Nb; c++){
        for(r = 0; r < 4; r++){
            
            (*state)[r][c] ^= *roundKey;
            roundKey++;
        }
    }
}


uint8_t* SubWord(uint8_t* a){
  
    int i;
    uint8_t* init = a;
    for(i = 0; i < 4; i++){
        *a = sbox[*a];
        a++;
    }
    return init;
}

uint8_t* RotWord(uint8_t* a){
  
    uint8_t rot[] = {a[1], a[2], a[3], a[0]};
    memcpy(a, rot, 4);
    return a;
}

uint8_t* Rcon(int a){
   
    uint8_t rcon = 0x8d;
    int i;
    for(i = 0; i < a; i++){
        rcon = ((rcon << 1) ^ (0x11b & - (rcon >> 7)));
    }
   
    uint8_t* word = calloc(4, sizeof(uint8_t));
    word[0] = rcon;
    return word;
}


uint8_t* xorWords(uint8_t* a, uint8_t* b){
  
    int i;
    uint8_t* init = a;
    for(i = 0; i < 4; i++, a++, b++){
        *a ^= *b;
    }
    return init;
}

uint8_t* copyWord(uint8_t* start){
   
    int i;
    uint8_t* word = malloc(sizeof(uint8_t) * 4);
    for(i = 0; i < 4; i++, start++){
        word[i] = *start;
    }
    return word;
}

uint8_t* getWord(uint8_t* w, int i){

    return &w[4*i];
}



