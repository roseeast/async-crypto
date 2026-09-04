#include "crypto_utils.hpp"

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <fstream>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif
#endif

namespace {

constexpr std::array<uint32_t, 64> kSha256K = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

constexpr std::array<unsigned char, 64> kBase64Alphabet = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
};

uint32_t load_be32(const unsigned char *p) {
    return (static_cast<uint32_t>(p[0]) << 24U) |
           (static_cast<uint32_t>(p[1]) << 16U) |
           (static_cast<uint32_t>(p[2]) << 8U) |
           static_cast<uint32_t>(p[3]);
}

void store_be32(unsigned char *p, uint32_t v) {
    p[0] = static_cast<unsigned char>(v >> 24U);
    p[1] = static_cast<unsigned char>(v >> 16U);
    p[2] = static_cast<unsigned char>(v >> 8U);
    p[3] = static_cast<unsigned char>(v);
}

void store_be64(unsigned char *p, uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        p[7 - i] = static_cast<unsigned char>(v >> (i * 8));
    }
}

std::array<unsigned char, 32> sha256_raw(std::string_view input) {
    uint32_t h[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
    };

    std::vector<unsigned char> data(input.begin(), input.end());
    const uint64_t bit_len = static_cast<uint64_t>(data.size()) * 8ULL;
    data.push_back(0x80U);
    while ((data.size() % 64U) != 56U) {
        data.push_back(0U);
    }
    const std::size_t old_size = data.size();
    data.resize(old_size + 8);
    store_be64(data.data() + old_size, bit_len);

    for (std::size_t offset = 0; offset < data.size(); offset += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = load_be32(data.data() + offset + static_cast<std::size_t>(i * 4));
        }
        for (int i = 16; i < 64; ++i) {
            const uint32_t s0 = std::rotr(w[i - 15], 7) ^ std::rotr(w[i - 15], 18) ^ (w[i - 15] >> 3U);
            const uint32_t s1 = std::rotr(w[i - 2], 17) ^ std::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10U);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        uint32_t f = h[5];
        uint32_t g = h[6];
        uint32_t hh = h[7];

        for (int i = 0; i < 64; ++i) {
            const uint32_t s1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
            const uint32_t ch = (e & f) ^ ((~e) & g);
            const uint32_t temp1 = hh + s1 + ch + kSha256K[i] + w[i];
            const uint32_t s0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
            const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t temp2 = s0 + maj;

            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    std::array<unsigned char, 32> digest{};
    for (int i = 0; i < 8; ++i) {
        store_be32(digest.data() + static_cast<std::size_t>(i * 4), h[i]);
    }
    return digest;
}

int base64_value(unsigned char c) {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

} // namespace

std::optional<std::vector<unsigned char>> secure_random_bytes(std::size_t len) {
    std::vector<unsigned char> out(len);
    if (len == 0) {
        return out;
    }

#if defined(_WIN32)
    if (BCryptGenRandom(nullptr, out.data(), static_cast<ULONG>(out.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0) {
        return out;
    }
    return std::nullopt;
#else
#if defined(__linux__)
    std::size_t done = 0;
    while (done < out.size()) {
        const ssize_t n = getrandom(out.data() + done, out.size() - done, 0);
        if (n > 0) {
            done += static_cast<std::size_t>(n);
            continue;
        }
        if (errno == EINTR) {
            continue;
        }
        break;
    }
    if (done == out.size()) {
        return out;
    }
#endif

    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (!urandom.read(reinterpret_cast<char *>(out.data()), static_cast<std::streamsize>(out.size()))) {
        return std::nullopt;
    }
    return out;
#endif
}

std::string hex_encode(const unsigned char *data, std::size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out[i * 2] = kHex[(data[i] >> 4U) & 0x0fU];
        out[i * 2 + 1] = kHex[data[i] & 0x0fU];
    }
    return out;
}

std::optional<std::string> sha256_hex(std::string_view input) {
    const auto digest = sha256_raw(input);
    return hex_encode(digest.data(), digest.size());
}

std::optional<std::string> hmac_sha256_hex(std::string_view key, std::string_view input) {
    std::array<unsigned char, 64> key_block{};
    if (key.size() > key_block.size()) {
        const auto digest = sha256_raw(key);
        std::copy(digest.begin(), digest.end(), key_block.begin());
    } else {
        std::copy(key.begin(), key.end(), key_block.begin());
    }

    std::string outer;
    std::string inner;
    outer.resize(64);
    inner.resize(64);
    for (std::size_t i = 0; i < key_block.size(); ++i) {
        outer[i] = static_cast<char>(key_block[i] ^ 0x5cU);
        inner[i] = static_cast<char>(key_block[i] ^ 0x36U);
    }

    inner.append(input);
    const auto inner_digest = sha256_raw(inner);
    outer.append(reinterpret_cast<const char *>(inner_digest.data()), inner_digest.size());
    const auto result = sha256_raw(outer);
    return hex_encode(result.data(), result.size());
}

std::optional<std::string> base64_encode(std::string_view input) {
    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);

    for (std::size_t i = 0; i < input.size(); i += 3) {
        const uint32_t b0 = static_cast<unsigned char>(input[i]);
        const uint32_t b1 = (i + 1 < input.size()) ? static_cast<unsigned char>(input[i + 1]) : 0U;
        const uint32_t b2 = (i + 2 < input.size()) ? static_cast<unsigned char>(input[i + 2]) : 0U;
        const uint32_t triple = (b0 << 16U) | (b1 << 8U) | b2;

        out.push_back(static_cast<char>(kBase64Alphabet[(triple >> 18U) & 0x3fU]));
        out.push_back(static_cast<char>(kBase64Alphabet[(triple >> 12U) & 0x3fU]));
        out.push_back(i + 1 < input.size() ? static_cast<char>(kBase64Alphabet[(triple >> 6U) & 0x3fU]) : '=');
        out.push_back(i + 2 < input.size() ? static_cast<char>(kBase64Alphabet[triple & 0x3fU]) : '=');
    }

    return out;
}

std::optional<std::string> base64_decode(std::string_view input) {
    if (input.size() % 4 != 0) {
        return std::nullopt;
    }

    std::string out;
    out.reserve((input.size() / 4) * 3);

    for (std::size_t i = 0; i < input.size(); i += 4) {
        const int v0 = base64_value(static_cast<unsigned char>(input[i]));
        const int v1 = base64_value(static_cast<unsigned char>(input[i + 1]));
        const bool pad2 = input[i + 2] == '=';
        const bool pad3 = input[i + 3] == '=';
        const int v2 = pad2 ? 0 : base64_value(static_cast<unsigned char>(input[i + 2]));
        const int v3 = pad3 ? 0 : base64_value(static_cast<unsigned char>(input[i + 3]));

        if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0 || (pad2 && !pad3)) {
            return std::nullopt;
        }

        const uint32_t triple = (static_cast<uint32_t>(v0) << 18U) |
                                (static_cast<uint32_t>(v1) << 12U) |
                                (static_cast<uint32_t>(v2) << 6U) |
                                static_cast<uint32_t>(v3);

        out.push_back(static_cast<char>((triple >> 16U) & 0xffU));
        if (!pad2) {
            out.push_back(static_cast<char>((triple >> 8U) & 0xffU));
        }
        if (!pad3) {
            out.push_back(static_cast<char>(triple & 0xffU));
        }
    }

    return out;
}
