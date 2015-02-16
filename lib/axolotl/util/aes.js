/** @fileOverview Low-level AES implementation.
 *
 * This file contains a low-level implementation of AES, optimized for
 * size and for efficiency on several browsers.  It is based on
 * OpenSSL's aes_core.c, a public-domain implementation by Vincent
 * Rijmen, Antoon Bosselaers and Paulo Barreto.
 *
 * An older version of this implementation is available in the public
 * domain, but this one is (c) Emily Stark, Mike Hamburg, Dan Boneh,
 * Stanford University 2008-2010 and BSD-licensed for liability
 * reasons.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * Schedule out an AES key for both encryption and decryption.  This
 * is a low-level class.  Use a cipher mode to do bulk encryption.
 *
 * @constructor
 * @param {Array} key The key as an array of 4, 6 or 8 words.
 *
 * @class Advanced Encryption Standard (low-level interface)
 */

var util = exports

util.AES = function (key) {
  if (!this._tables[0][0][0]) {
    this._precompute();
  }

  var i, j, tmp,
    encKey, decKey,
    sbox = this._tables[0][4], decTable = this._tables[1],
    keyLen = key.length, rcon = 1;

  if (keyLen !== 4 && keyLen !== 6 && keyLen !== 8) {
    throw "invalid aes key size";
  }
  
  this._key = [encKey = key.slice(0), decKey = []];
  
  // schedule encryption keys
  for (i = keyLen; i < 4 * keyLen + 28; i++) {
    tmp = encKey[i-1];
    
    // apply sbox
    if (i%keyLen === 0 || (keyLen === 8 && i%keyLen === 4)) {
      tmp = sbox[tmp>>>24]<<24 ^ sbox[tmp>>16&255]<<16 ^ sbox[tmp>>8&255]<<8 ^ sbox[tmp&255];
      
      // shift rows and add rcon
      if (i%keyLen === 0) {
        tmp = tmp<<8 ^ tmp>>>24 ^ rcon<<24;
        rcon = rcon<<1 ^ (rcon>>7)*283;
      }
    }
    
    encKey[i] = encKey[i-keyLen] ^ tmp;
  }
  
  // schedule decryption keys
  for (j = 0; i; j++, i--) {
    tmp = encKey[j&3 ? i : i - 4];
    if (i<=4 || j<4) {
      decKey[j] = tmp;
    } else {
      decKey[j] = decTable[0][sbox[tmp>>>24      ]] ^
                  decTable[1][sbox[tmp>>16  & 255]] ^
                  decTable[2][sbox[tmp>>8   & 255]] ^
                  decTable[3][sbox[tmp      & 255]];
    }
  }
};

util.AES.prototype = {
  // public
  /* Something like this might appear here eventually
  name: "AES",
  blockSize: 4,
  keySizes: [4,6,8],
  */
  
  /**
   * Encrypt an array of 4 big-endian words.
   * @param {Array} data The plaintext.
   * @return {Array} The ciphertext.
   */
  encrypt:function (data) { return this._crypt(data,0); },
  
  /**
   * Decrypt an array of 4 big-endian words.
   * @param {Array} data The ciphertext.
   * @return {Array} The plaintext.
   */
  decrypt:function (data) { return this._crypt(data,1); },
  
  /**
   * The expanded S-box and inverse S-box tables.  These will be computed
   * on the client so that we don't have to send them down the wire.
   *
   * There are two tables, _tables[0] is for encryption and
   * _tables[1] is for decryption.
   *
   * The first 4 sub-tables are the expanded S-box with MixColumns.  The
   * last (_tables[01][4]) is the S-box itself.
   *
   * @private
   */
  _tables: [[[],[],[],[],[]],[[],[],[],[],[]]],

  /**
   * Expand the S-box tables.
   *
   * @private
   */
  _precompute: function () {
   var encTable = this._tables[0], decTable = this._tables[1],
       sbox = encTable[4], sboxInv = decTable[4],
       i, x, xInv, d=[], th=[], x2, x4, x8, s, tEnc, tDec;

    // Compute double and third tables
   for (i = 0; i < 256; i++) {
     th[( d[i] = i<<1 ^ (i>>7)*283 )^i]=i;
   }
   
   for (x = xInv = 0; !sbox[x]; x ^= x2 || 1, xInv = th[xInv] || 1) {
     // Compute sbox
     s = xInv ^ xInv<<1 ^ xInv<<2 ^ xInv<<3 ^ xInv<<4;
     s = s>>8 ^ s&255 ^ 99;
     sbox[x] = s;
     sboxInv[s] = x;
     
     // Compute MixColumns
     x8 = d[x4 = d[x2 = d[x]]];
     tDec = x8*0x1010101 ^ x4*0x10001 ^ x2*0x101 ^ x*0x1010100;
     tEnc = d[s]*0x101 ^ s*0x1010100;
     
     for (i = 0; i < 4; i++) {
       encTable[i][x] = tEnc = tEnc<<24 ^ tEnc>>>8;
       decTable[i][s] = tDec = tDec<<24 ^ tDec>>>8;
     }
   }
   
   // Compactify.  Considerable speedup on Firefox.
   for (i = 0; i < 5; i++) {
     encTable[i] = encTable[i].slice(0);
     decTable[i] = decTable[i].slice(0);
   }
  },
  
  /**
   * Encryption and decryption core.
   * @param {Array} input Four words to be encrypted or decrypted.
   * @param dir The direction, 0 for encrypt and 1 for decrypt.
   * @return {Array} The four encrypted or decrypted words.
   * @private
   */
  _crypt:function (input, dir) {
    if (input.length !== 4) {
      throw "invalid aes block size";
    }
    
    var key = this._key[dir],
        // state variables a,b,c,d are loaded with pre-whitened data
        a = input[0]           ^ key[0],
        b = input[dir ? 3 : 1] ^ key[1],
        c = input[2]           ^ key[2],
        d = input[dir ? 1 : 3] ^ key[3],
        a2, b2, c2,
        
        nInnerRounds = key.length/4 - 2,
        i,
        kIndex = 4,
        out = [0,0,0,0],
        table = this._tables[dir],
        
        // load up the tables
        t0    = table[0],
        t1    = table[1],
        t2    = table[2],
        t3    = table[3],
        sbox  = table[4];
 
    // Inner rounds.  Cribbed from OpenSSL.
    for (i = 0; i < nInnerRounds; i++) {
      a2 = t0[a>>>24] ^ t1[b>>16 & 255] ^ t2[c>>8 & 255] ^ t3[d & 255] ^ key[kIndex];
      b2 = t0[b>>>24] ^ t1[c>>16 & 255] ^ t2[d>>8 & 255] ^ t3[a & 255] ^ key[kIndex + 1];
      c2 = t0[c>>>24] ^ t1[d>>16 & 255] ^ t2[a>>8 & 255] ^ t3[b & 255] ^ key[kIndex + 2];
      d  = t0[d>>>24] ^ t1[a>>16 & 255] ^ t2[b>>8 & 255] ^ t3[c & 255] ^ key[kIndex + 3];
      kIndex += 4;
      a=a2; b=b2; c=c2;
    }
        
    // Last round.
    for (i = 0; i < 4; i++) {
      out[dir ? 3&-i : i] =
        sbox[a>>>24      ]<<24 ^ 
        sbox[b>>16  & 255]<<16 ^
        sbox[c>>8   & 255]<<8  ^
        sbox[d      & 255]     ^
        key[kIndex++];
      a2=a; a=b; b=c; c=d; d=a2;
    }
    
    return out;
  }
};

///* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
///*  AES implementation in JavaScript                     (c) Chris Veness 2005-2014 / MIT Licence */
///* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
//
///* jshint node:true *//* global define */
//'use strict';
//
///**
// * AES (Rijndael cipher) encryption routines,
// *
// * Reference implementation of FIPS-197 http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf.
// *
// * @namespace
// */
//var Aes = {};
//
//
///**
// * AES Cipher function: encrypt 'input' state with Rijndael algorithm [§5.1];
// *   applies Nr rounds (10/12/14) using key schedule w for 'add round key' stage.
// *
// * @param   {number[]}   input - 16-byte (128-bit) input state array.
// * @param   {number[][]} w - Key schedule as 2D byte-array (Nr+1 x Nb bytes).
// * @returns {number[]}   Encrypted output state array.
// */
//Aes.cipher = function(input, w) {
//    var Nb = 4;               // block size (in words): no of columns in state (fixed at 4 for AES)
//    var Nr = w.length/Nb - 1; // no of rounds: 10/12/14 for 128/192/256-bit keys
//
//    var state = [[],[],[],[]];  // initialise 4xNb byte-array 'state' with input [§3.4]
//    for (var i=0; i<4*Nb; i++) state[i%4][Math.floor(i/4)] = input[i];
//
//    state = Aes.addRoundKey(state, w, 0, Nb);
//
//    for (var round=1; round<Nr; round++) {
//        state = Aes.subBytes(state, Nb);
//        state = Aes.shiftRows(state, Nb);
//        state = Aes.mixColumns(state, Nb);
//        state = Aes.addRoundKey(state, w, round, Nb);
//    }
//
//    state = Aes.subBytes(state, Nb);
//    state = Aes.shiftRows(state, Nb);
//    state = Aes.addRoundKey(state, w, Nr, Nb);
//
//    var output = new Array(4*Nb);  // convert state to 1-d array before returning [§3.4]
//    for (var i=0; i<4*Nb; i++) output[i] = state[i%4][Math.floor(i/4)];
//
//    return output;
//};
//
//
///**
// * Perform key expansion to generate a key schedule from a cipher key [§5.2].
// *
// * @param   {number[]}   key - Cipher key as 16/24/32-byte array.
// * @returns {number[][]} Expanded key schedule as 2D byte-array (Nr+1 x Nb bytes).
// */
//Aes.keyExpansion = function(key) {
//    var Nb = 4;            // block size (in words): no of columns in state (fixed at 4 for AES)
//    var Nk = key.length/4; // key length (in words): 4/6/8 for 128/192/256-bit keys
//    var Nr = Nk + 6;       // no of rounds: 10/12/14 for 128/192/256-bit keys
//
//    var w = new Array(Nb*(Nr+1));
//    var temp = new Array(4);
//
//    // initialise first Nk words of expanded key with cipher key
//    for (var i=0; i<Nk; i++) {
//        var r = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]];
//        w[i] = r;
//    }
//
//    // expand the key into the remainder of the schedule
//    for (var i=Nk; i<(Nb*(Nr+1)); i++) {
//        w[i] = new Array(4);
//        for (var t=0; t<4; t++) temp[t] = w[i-1][t];
//        // each Nk'th word has extra transformation
//        if (i % Nk == 0) {
//            temp = Aes.subWord(Aes.rotWord(temp));
//            for (var t=0; t<4; t++) temp[t] ^= Aes.rCon[i/Nk][t];
//        }
//        // 256-bit key has subWord applied every 4th word
//        else if (Nk > 6 && i%Nk == 4) {
//            temp = Aes.subWord(temp);
//        }
//        // xor w[i] with w[i-1] and w[i-Nk]
//        for (var t=0; t<4; t++) w[i][t] = w[i-Nk][t] ^ temp[t];
//    }
//
//    return w;
//};
//
//
///**
// * Apply SBox to state S [§5.1.1]
// * @private
// */
//Aes.subBytes = function(s, Nb) {
//    for (var r=0; r<4; r++) {
//        for (var c=0; c<Nb; c++) s[r][c] = Aes.sBox[s[r][c]];
//    }
//    return s;
//};
//
//
///**
// * Shift row r of state S left by r bytes [§5.1.2]
// * @private
// */
//Aes.shiftRows = function(s, Nb) {
//    var t = new Array(4);
//    for (var r=1; r<4; r++) {
//        for (var c=0; c<4; c++) t[c] = s[r][(c+r)%Nb];  // shift into temp copy
//        for (var c=0; c<4; c++) s[r][c] = t[c];         // and copy back
//    }          // note that this will work for Nb=4,5,6, but not 7,8 (always 4 for AES):
//    return s;  // see asmaes.sourceforge.net/rijndael/rijndaelImplementation.pdf
//};
//
//
///**
// * Combine bytes of each col of state S [§5.1.3]
// * @private
// */
//Aes.mixColumns = function(s, Nb) {
//    for (var c=0; c<4; c++) {
//        var a = new Array(4);  // 'a' is a copy of the current column from 's'
//        var b = new Array(4);  // 'b' is a•{02} in GF(2^8)
//        for (var i=0; i<4; i++) {
//            a[i] = s[i][c];
//            b[i] = s[i][c]&0x80 ? s[i][c]<<1 ^ 0x011b : s[i][c]<<1;
//        }
//        // a[n] ^ b[n] is a•{03} in GF(2^8)
//        s[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]; // {02}•a0 + {03}•a1 + a2 + a3
//        s[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]; // a0 • {02}•a1 + {03}•a2 + a3
//        s[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]; // a0 + a1 + {02}•a2 + {03}•a3
//        s[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]; // {03}•a0 + a1 + a2 + {02}•a3
//    }
//    return s;
//};
//
//
///**
// * Xor Round Key into state S [§5.1.4]
// * @private
// */
//Aes.addRoundKey = function(state, w, rnd, Nb) {
//    for (var r=0; r<4; r++) {
//        for (var c=0; c<Nb; c++) state[r][c] ^= w[rnd*4+c][r];
//    }
//    return state;
//};
//
//
///**
// * Apply SBox to 4-byte word w
// * @private
// */
//Aes.subWord = function(w) {
//    for (var i=0; i<4; i++) w[i] = Aes.sBox[w[i]];
//    return w;
//};
//
//
///**
// * Rotate 4-byte word w left by one byte
// * @private
// */
//Aes.rotWord = function(w) {
//    var tmp = w[0];
//    for (var i=0; i<3; i++) w[i] = w[i+1];
//    w[3] = tmp;
//    return w;
//};
//
//
//// sBox is pre-computed multiplicative inverse in GF(2^8) used in subBytes and keyExpansion [§5.1.1]
//Aes.sBox =  [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
//             0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
//             0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
//             0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
//             0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
//             0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
//             0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
//             0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
//             0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
//             0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
//             0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
//             0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
//             0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
//             0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
//             0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
//             0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16];
//
//
//// rCon is Round Constant used for the Key Expansion [1st col is 2^(r-1) in GF(2^8)] [§5.2]
//Aes.rCon = [ [0x00, 0x00, 0x00, 0x00],
//             [0x01, 0x00, 0x00, 0x00],
//             [0x02, 0x00, 0x00, 0x00],
//             [0x04, 0x00, 0x00, 0x00],
//             [0x08, 0x00, 0x00, 0x00],
//             [0x10, 0x00, 0x00, 0x00],
//             [0x20, 0x00, 0x00, 0x00],
//             [0x40, 0x00, 0x00, 0x00],
//             [0x80, 0x00, 0x00, 0x00],
//             [0x1b, 0x00, 0x00, 0x00],
//             [0x36, 0x00, 0x00, 0x00] ]; 
//
//
