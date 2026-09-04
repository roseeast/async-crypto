#include <a_samp>
#include <async_crypto>

main() {}

public OnGameModeInit()
{
    print("Async crypto example started.");

    new random_hex[65];
    Crypto_RandomHex(32, random_hex);
    printf("random hex: %s", random_hex);

    new sha[65];
    Crypto_SHA256Hex("hello", sha);
    printf("sha256: %s", sha);

    Crypto_Argon2Hash("secret-password", "OnPasswordHashed");
    return 1;
}

public OnPasswordHashed(requestid, status, const result[])
{
    if (status != CRYPTO_STATUS_OK)
    {
        printf("Argon2 hash failed: request=%d status=%d message=%s", requestid, status, result);
        return 1;
    }

    printf("Argon2 hash: %s", result);
    Crypto_Argon2Verify("secret-password", result, "OnPasswordVerified");
    return 1;
}

public OnPasswordVerified(requestid, status, const result[])
{
    printf("Argon2 verify: request=%d status=%d match=%s", requestid, status, result);
    return 1;
}
