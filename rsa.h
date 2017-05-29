//
//  rsa.h
//  Security-TermProject
//
//  Created by Barış Yamansavaşçılar on 5.05.2017.
//  Copyright © 2017 Barış Yamansavaşçılar. All rights reserved.
//

#ifndef rsa_h
#define rsa_h

#include <stdio.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define ACCURACY 5
#define SINGLE_MAX 10000
#define EXPONENT_MAX 1000
#define BUF_SIZE 1024


/**
 * Computes a^b mod c
 */
int modpow(long long a, long long b, int c);

/**
 * Computes the Jacobi symbol, (a, n)
 */
int jacobi(int a, int n);

/**
 * Check whether a is a Euler witness for n
 */
int solovayPrime(int a, int n);

/**
 * Test if n is probably prime, using accuracy of k (k solovay tests)
 */
int probablePrime(int n, int k);

/**
 * Find a random (probable) prime between 3 and n - 1, this distribution is
 * nowhere near uniform, see prime gaps
 */
int randPrime(int n);


/**
 * Compute gcd(a, b)
 */
int gcd(int a, int b);


/**
 * Find a random exponent x between 3 and n - 1 such that gcd(x, phi) = 1,
 * this distribution is similarly nowhere near uniform
 */
int randExponent(int phi, int n);

/**
 * Compute n^-1 mod m by extended euclidian method
 */
int inverse(int n, int modulus);

/**
 * Read the file fd into an array of bytes ready for encryption.
 * The array will be padded with zeros until it divides the number of
 * bytes encrypted per block. Returns the number of bytes read.
 */
int readFile(FILE* fd, char** buffer, int bytes);


/**
 * Encode the message m using public exponent and modulus, c = m^e mod n
 */
int encode(int m, int e, int n);

/**
 * Decode cryptogram c using private exponent and public modulus, m = c^d mod n
 */
int decode(int c, int d, int n);

/**
 * Encode the message of given length, using the public key (exponent, modulus)
 * The resulting array will be of size len/bytes, each index being the encryption
 * of "bytes" consecutive characters, given by m = (m1 + m2*128 + m3*128^2 + ..),
 * encoded = m^exponent mod modulus
 */
int* encodeMessage(int len, int bytes, char* message, int exponent, int modulus);

/**
 * Decode the cryptogram of given length, using the private key (exponent, modulus)
 * Each encrypted packet should represent "bytes" characters as per encodeMessage.
 * The returned message will be of size len * bytes.
 */
int* decodeMessage(int len, int bytes, int* cryptogram, int exponent, int modulus);







#endif /* rsa_h */
