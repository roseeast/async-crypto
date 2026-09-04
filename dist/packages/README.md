<p align="center">
  <img src="assets/async-crypto-logo.svg" width="170" alt="Async Crypto logo">
</p>

<h1 align="center">Async Crypto</h1>

<p align="center">
  Modern async Argon2id and crypto utility plugin for SA-MP and open.mp Pawn servers.
</p>

<p align="center">
  <a href="#compatibility"><img alt="SA-MP" src="https://img.shields.io/badge/SA--MP-supported-2f6feb?style=flat-square"></a>
  <a href="#compatibility"><img alt="open.mp" src="https://img.shields.io/badge/open.mp-legacy%20plugin-00a86b?style=flat-square"></a>
  <a href="#overview"><img alt="C++20" src="https://img.shields.io/badge/C++-20-00599c?style=flat-square"></a>
  <a href="#argon2id-defaults"><img alt="Argon2id" src="https://img.shields.io/badge/Argon2id-async-7c3aed?style=flat-square"></a>
  <a href="#release-files"><img alt="Platforms" src="https://img.shields.io/badge/Linux%20%7C%20Windows-x86%20%7C%20x86__64-111827?style=flat-square"></a>
</p>

<p align="center">
  <a href="#installation">Installation</a>
  ·
  <a href="#native-api">Native API</a>
  ·
  <a href="#build-from-source">Build</a>
  ·
  <a href="#security-guidance">Security</a>
</p>

---

Async Crypto provides non-blocking Argon2id password hashing for Pawn gamemodes, plus practical crypto utilities such as secure random hex, SHA-256, HMAC-SHA256, and Base64. Expensive work runs on worker threads, then results are delivered back to Pawn from the main server thread through `ProcessTick`.

## Overview

| Item | Detail |
| --- | --- |
| Plugin name | `async_crypto` |
| Target | SA-MP and open.mp |
| Plugin type | Legacy SA-MP plugin API |
| Language | C++20 |
| Password algorithm | Argon2id |
| Async model | Worker thread queue + `ProcessTick` callback |
| External runtime deps | None beyond OS C runtime for release binaries |
| Included platforms | Linux x86, Linux x86_64, Windows x86, Windows x86_64 |
| Pawn include | `include/async_crypto.inc` |

## Features

| Feature | Native | Async | Output |
| --- | --- | ---: | --- |
| Argon2id password hashing | `Crypto_Argon2Hash` | Yes | PHC encoded Argon2id hash |
| Argon2id password verification | `Crypto_Argon2Verify` | Yes | `"1"` or `"0"` |
| Secure random bytes as hex | `Crypto_RandomHex` | No | Lowercase hex string |
| SHA-256 | `Crypto_SHA256Hex` | No | 64-char lowercase hex |
| HMAC-SHA256 | `Crypto_HMACSHA256Hex` | No | 64-char lowercase hex |
| Base64 encode | `Crypto_Base64Encode` | No | Base64 string |
| Base64 decode | `Crypto_Base64Decode` | No | Decoded string |

## Release Files

Prebuilt binaries are available in `dist/`.

| File | Platform | Architecture | Install as |
| --- | --- | --- | --- |
| `dist/async_crypto-linux-x86_64.so` | Linux | x86_64 / 64-bit | `plugins/async_crypto.so` |
| `dist/async_crypto-linux-i686.so` | Linux | i686 / 32-bit | `plugins/async_crypto.so` |
| `dist/async_crypto-windows-x86_64.dll` | Windows | x86_64 / 64-bit | `plugins/async_crypto.dll` |
| `dist/async_crypto-windows-i686.dll` | Windows | i686 / 32-bit | `plugins/async_crypto.dll` |
| `dist/async_crypto-binaries.tar.gz` | All | All packaged builds | Extract selected platform folder |
| `dist/SHA256SUMS.txt` | All | Checksums | Integrity verification |

Package layout:

```text
dist/packages/
  linux-i686/
    plugins/async_crypto.so
    pawno/include/async_crypto.inc
  linux-x86_64/
    plugins/async_crypto.so
    pawno/include/async_crypto.inc
  windows-i686/
    plugins/async_crypto.dll
    pawno/include/async_crypto.inc
  windows-x86_64/
    plugins/async_crypto.dll
    pawno/include/async_crypto.inc
```

## Compatibility

| Runtime | Status | Notes |
| --- | --- | --- |
| SA-MP Windows server | Supported | Use the matching `.dll` architecture. |
| SA-MP Linux server | Supported | Use the matching `.so` architecture. |
| open.mp Windows server | Supported as legacy plugin | Configure through `pawn.legacy_plugins` or legacy `server.cfg`. |
| open.mp Linux server | Supported as legacy plugin | Configure through `pawn.legacy_plugins` or legacy `server.cfg`. |
| Native open.mp component | Not included | This project currently targets the legacy plugin ABI for broad compatibility. |

This plugin does not hook RakNet, patch memory, or depend on SA-MP internal addresses, so it is a good fit for open.mp legacy plugin loading.

## Installation

### 1. Choose The Binary

| Server | Use this binary | Destination |
| --- | --- | --- |
| Linux 64-bit | `async_crypto-linux-x86_64.so` | `plugins/async_crypto.so` |
| Linux 32-bit | `async_crypto-linux-i686.so` | `plugins/async_crypto.so` |
| Windows 64-bit | `async_crypto-windows-x86_64.dll` | `plugins/async_crypto.dll` |
| Windows 32-bit | `async_crypto-windows-i686.dll` | `plugins/async_crypto.dll` |

### 2. Install The Pawn Include

Copy:

```text
include/async_crypto.inc
```

to your compiler include directory, for example:

| Tooling | Typical include directory |
| --- | --- |
| Pawno | `pawno/include/` |
| Qawno | `qawno/include/` |
| sampctl | Project include path or package include path |

### 3. Load The Plugin

For SA-MP or legacy `server.cfg`:

```text
plugins async_crypto
```

On some older Linux setups, include the extension:

```text
plugins async_crypto.so
```

For open.mp `config.json`:

```json
{
  "pawn": {
    "legacy_plugins": ["async_crypto"]
  }
}
```

## Native API

### Async Natives

| Native | Signature | Return | Callback result |
| --- | --- | --- | --- |
| `Crypto_Argon2Hash` | `const password[], const callback[], mem_kib, iterations, parallelism, hash_len` | `requestid > 0` or negative error | PHC encoded hash |
| `Crypto_Argon2Verify` | `const password[], const encoded_hash[], const callback[]` | `requestid > 0` or negative error | `"1"` if valid, `"0"` if invalid |

Callback format:

```pawn
public MyCallback(requestid, status, const result[])
```

Return behavior:

| Return value | Meaning |
| ---: | --- |
| `> 0` | Job accepted. Value is the `requestid`. |
| `< 0` | Job rejected before reaching the worker queue. Absolute value maps to `CRYPTO_STATUS_*`. |

### Sync Utility Natives

| Native | Signature | Return | Notes |
| --- | --- | --- | --- |
| `Crypto_RandomHex` | `byte_len, dest[], dest_size` | `1` on success, `0` on failure | `byte_len` must be `1..4096`. |
| `Crypto_SHA256Hex` | `const input[], dest[], dest_size` | `1` or `0` | Hashes input string. |
| `Crypto_HMACSHA256Hex` | `const key[], const input[], dest[], dest_size` | `1` or `0` | Useful for signed tokens/webhooks. |
| `Crypto_Base64Encode` | `const input[], dest[], dest_size` | `1` or `0` | Standard Base64. |
| `Crypto_Base64Decode` | `const input[], dest[], dest_size` | `1` or `0` | Input length must be valid Base64. |

## Status Codes

| Constant | Value | Meaning |
| --- | ---: | --- |
| `CRYPTO_STATUS_OK` | `0` | Operation succeeded. |
| `CRYPTO_STATUS_ERROR` | `1` | Runtime error, such as invalid hash format or random source failure. |
| `CRYPTO_STATUS_BAD_ARGUMENT` | `2` | Invalid native argument. |
| `CRYPTO_STATUS_QUEUE_FULL` | `3` | Async worker queue is full. |
| `CRYPTO_STATUS_CALLBACK_MISSING` | `4` | Reserved for callback-related handling. |

## Argon2id Defaults

| Parameter | Default | Allowed range | Description |
| --- | ---: | ---: | --- |
| `mem_kib` | `65536` | `8192..1048576` | Memory cost in KiB. Default is 64 MiB. |
| `iterations` | `3` | `1..16` | Time cost. |
| `parallelism` | `1` | `1..8` | Argon2 lane count. |
| `hash_len` | `32` | `16..128` | Raw hash length before PHC encoding. |
| Salt length | `16` | Fixed | Generated with OS secure random source. |

For most RP/account systems, the default Argon2id settings are a strong starting point. Increase `mem_kib` or `iterations` only after testing login/register latency on your server hardware.

## Pawn Example

```pawn
#include <async_crypto>

public OnGameModeInit()
{
    new request = Crypto_Argon2Hash("secret-password", "OnPasswordHashed");

    if (request < 0)
    {
        printf("Argon2 job rejected: %d", request);
    }

    return 1;
}

public OnPasswordHashed(requestid, status, const hash[])
{
    if (status != CRYPTO_STATUS_OK)
    {
        printf("Hash failed: request=%d status=%d message=%s", requestid, status, hash);
        return 1;
    }

    printf("Hash: %s", hash);
    Crypto_Argon2Verify("secret-password", hash, "OnPasswordVerified");
    return 1;
}

public OnPasswordVerified(requestid, status, const result[])
{
    if (status == CRYPTO_STATUS_OK && strval(result) == 1)
    {
        print("Password valid.");
    }
    else
    {
        printf("Password invalid or verification failed: request=%d status=%d result=%s", requestid, status, result);
    }

    return 1;
}
```

## Build From Source

### Linux

```bash
sudo apt install cmake g++ git
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Output:

```text
build/async_crypto.so
```

### Linux 32-bit

```bash
sudo apt install cmake g++ git g++-multilib
cmake -S . -B build-linux-i686 \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS=-m32 \
  -DCMAKE_CXX_FLAGS=-m32 \
  -DCMAKE_SHARED_LINKER_FLAGS=-m32
cmake --build build-linux-i686 -j
```

### Windows Cross-Build With MinGW

Windows x86_64:

```bash
cmake -S . -B build-win-x86_64 \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_SYSTEM_NAME=Windows \
  -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
  -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++
cmake --build build-win-x86_64 -j
```

Windows i686:

```bash
cmake -S . -B build-win-i686 \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_SYSTEM_NAME=Windows \
  -DCMAKE_C_COMPILER=i686-w64-mingw32-gcc \
  -DCMAKE_CXX_COMPILER=i686-w64-mingw32-g++
cmake --build build-win-i686 -j
```

### Offline SDK Build

By default, CMake fetches `maddinat0r/samp-plugin-sdk` and `P-H-C/phc-winner-argon2`. If your build machine cannot access GitHub, provide a local SDK checkout:

```bash
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DSAMP_PLUGIN_SDK_DIR=/path/to/samp-plugin-sdk
cmake --build build -j
```

## Build Notes

| Component | How it is linked |
| --- | --- |
| Argon2 | Built from upstream source through CMake and linked statically. |
| SHA-256 / HMAC / Base64 | Built-in implementation in `src/crypto_utils.cpp`. |
| Secure random | `getrandom` or `/dev/urandom` on Linux, `BCryptGenRandom` on Windows. |
| C++ runtime on Linux | Static libstdc++/libgcc for release builds. |
| C++ runtime on Windows | Static libstdc++/libgcc for MinGW builds. |

## Security Guidance

| Do | Avoid |
| --- | --- |
| Hash passwords with `Crypto_Argon2Hash`. | Encrypting passwords with AES or reversible encryption. |
| Store the full PHC encoded hash string. | Storing raw hash bytes without parameters and salt. |
| Verify passwords with `Crypto_Argon2Verify`. | Comparing password strings manually in Pawn. |
| Use random salts generated by the plugin. | Reusing one salt for every player. |
| Keep login/register flow async. | Running expensive password hashing on the main server thread. |

Password storage should keep the complete Argon2id PHC string, for example:

```text
$argon2id$v=19$m=65536,t=3,p=1$...$...
```

The encoded string already contains the algorithm, version, memory cost, time cost, parallelism, salt, and hash.

## Project Structure

| Path | Purpose |
| --- | --- |
| `src/plugin.cpp` | SA-MP/open.mp plugin entry points, AMX native registration, worker queue, callbacks. |
| `src/crypto_utils.cpp` | Secure random, SHA-256, HMAC-SHA256, Base64 helpers. |
| `include/async_crypto.inc` | Pawn include and native declarations. |
| `example.pwn` | Minimal Pawn usage example. |
| `exports/async_crypto.def` | Windows export list. |
| `dist/` | Prebuilt binaries and packaged release files. |

## Checksums

Use `dist/SHA256SUMS.txt` to verify release files:

```bash
cd dist
sha256sum -c SHA256SUMS.txt
```

## License

Project license is not declared yet. Add a `LICENSE` file before publishing binaries publicly.
