//
//  aesAlgorithm.h
//  Security-TermProject
//
//  Created by Barış Yamansavaşçılar on 30.04.2017.
//  Copyright © 2017 Barış Yamansavaşçılar. All rights reserved.
//

#ifndef aesAlgorithm_h
#define aesAlgorithm_h

#include <stdio.h>

#include <stdlib.h>
#include <stdint.h>

/*
 * Advanced Encryption Standard
 * @author Dani Huertas
 * @email huertas.dani@gmail.com
 *
 * Based on the document FIPS PUB 197
 */


/*
 * Number of columns (32-bit words) comprising the State. For this
 * standard, Nb = 4.
 */
extern int Nb;

/*
 * Number of 32-bit words comprising the Cipher Key. For this
 * standard, Nk = 4, 6, or 8.
 */
extern int Nk;

/*
 * Number of rounds, which is a function of  Nk  and  Nb (which is
 * fixed). For this standard, Nr = 10, 12, or 14.
 */
extern int Nr;

/*
 * S-box transformation table


/*
 * Transformation in the Inverse Cipher that is the inverse of
 * ShiftRows().
 */
void inv_shift_rows(uint8_t *state);

/*
 * Transformation in the Cipher that processes the State using a non­
 * linear byte substitution table (S-box) that operates on each of the
 * State bytes independently.
 */
void sub_bytes(uint8_t *state);

/*
 * Transformation in the Inverse Cipher that is the inverse of
 * SubBytes().
 */
void inv_sub_bytes(uint8_t *state);

/*
 * Function used in the Key Expansion routine that takes a four-byte
 * input word and applies an S-box to each of the four bytes to
 * produce an output word.
 */
void sub_word(uint8_t *w);

/*
 * Function used in the Key Expansion routine that takes a four-byte
 * word and performs a cyclic permutation.
 */
void rot_word(uint8_t *w);

/*
 * Key Expansion
 */
void key_expansion(uint8_t *key, uint8_t *w);

void cipher(uint8_t *in, uint8_t *out, uint8_t *w);

void inv_cipher(uint8_t *in, uint8_t *out, uint8_t *w);

void run(uint8_t *input);

#endif /* aesAlgorithm_h */
