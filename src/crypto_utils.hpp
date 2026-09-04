#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

std::optional<std::vector<unsigned char>> secure_random_bytes(std::size_t len);
std::string hex_encode(const unsigned char *data, std::size_t len);
std::optional<std::string> sha256_hex(std::string_view input);
std::optional<std::string> hmac_sha256_hex(std::string_view key, std::string_view input);
std::optional<std::string> base64_encode(std::string_view input);
std::optional<std::string> base64_decode(std::string_view input);
