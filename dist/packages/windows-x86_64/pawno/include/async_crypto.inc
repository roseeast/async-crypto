#if defined _async_crypto_included
    #endinput
#endif
#define _async_crypto_included

#define CRYPTO_STATUS_OK              (0)
#define CRYPTO_STATUS_ERROR           (1)
#define CRYPTO_STATUS_BAD_ARGUMENT    (2)
#define CRYPTO_STATUS_QUEUE_FULL      (3)
#define CRYPTO_STATUS_CALLBACK_MISSING (4)

#define CRYPTO_ARGON2_MEM_DEFAULT_KIB (65536)
#define CRYPTO_ARGON2_TIME_DEFAULT    (3)
#define CRYPTO_ARGON2_PAR_DEFAULT     (1)
#define CRYPTO_ARGON2_HASH_DEFAULT    (32)

/*
 * Callback format:
 *
 * public MyCallback(requestid, status, const result[])
 *
 * Hash result:
 * - status OK: PHC encoded Argon2id hash string.
 * - status error: human-readable error message.
 *
 * Verify result:
 * - status OK: "1" if valid, "0" if invalid.
 * - status error: human-readable error message.
 */
native Crypto_Argon2Hash(
    const password[],
    const callback[],
    mem_kib = CRYPTO_ARGON2_MEM_DEFAULT_KIB,
    iterations = CRYPTO_ARGON2_TIME_DEFAULT,
    parallelism = CRYPTO_ARGON2_PAR_DEFAULT,
    hash_len = CRYPTO_ARGON2_HASH_DEFAULT
);

native Crypto_Argon2Verify(
    const password[],
    const encoded_hash[],
    const callback[]
);

native Crypto_RandomHex(byte_len, dest[], dest_size = sizeof dest);
native Crypto_SHA256Hex(const input[], dest[], dest_size = sizeof dest);
native Crypto_HMACSHA256Hex(const key[], const input[], dest[], dest_size = sizeof dest);
native Crypto_Base64Encode(const input[], dest[], dest_size = sizeof dest);
native Crypto_Base64Decode(const input[], dest[], dest_size = sizeof dest);
