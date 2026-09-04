#include <cstddef>
#include <cstdint>

#include <plugincommon.h>
#include <amx/amx.h>

#include "crypto_utils.hpp"

#include <argon2.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using logprintf_t = void (*)(const char *, ...);

static logprintf_t logprintf = nullptr;
extern void *pAMXFunctions;

namespace {

constexpr cell kStatusOk = 0;
constexpr cell kStatusError = 1;
constexpr cell kStatusBadArgument = 2;
constexpr cell kStatusQueueFull = 3;
constexpr std::size_t kMaxPendingJobs = 4096;
constexpr std::size_t kMaxCallbackResultsPerTick = 128;

struct AmxInstance {
    AMX *amx;
};

struct Job {
    enum class Type {
        Hash,
        Verify,
    };

    Type type;
    int request_id;
    AMX *amx;
    std::string callback;
    std::string password;
    std::string encoded_hash;
    uint32_t mem_kib;
    uint32_t iterations;
    uint32_t parallelism;
    uint32_t hash_len;
};

struct Result {
    int request_id;
    AMX *amx;
    std::string callback;
    cell status;
    std::string payload;
};

std::atomic_bool g_running{false};
std::atomic_int g_next_request_id{1};
std::mutex g_amx_mutex;
std::vector<AmxInstance> g_amx_instances;

std::mutex g_jobs_mutex;
std::condition_variable g_jobs_cv;
std::deque<Job> g_jobs;
std::vector<std::thread> g_workers;

std::mutex g_results_mutex;
std::deque<Result> g_results;

std::string get_string(AMX *amx, cell param) {
    cell *addr = nullptr;
    if (amx_GetAddr(amx, param, &addr) != AMX_ERR_NONE || addr == nullptr) {
        return {};
    }

    int len = 0;
    amx_StrLen(addr, &len);
    std::string value(static_cast<std::size_t>(len), '\0');
    amx_GetString(value.data(), addr, 0, len + 1);
    return value;
}

bool set_string(AMX *amx, cell param, std::string_view value, cell dest_size) {
    cell *addr = nullptr;
    if (dest_size <= 0 || amx_GetAddr(amx, param, &addr) != AMX_ERR_NONE || addr == nullptr) {
        return false;
    }

    return amx_SetString(addr, value.data(), 0, 0, static_cast<size_t>(dest_size)) == AMX_ERR_NONE;
}

std::size_t encoded_argon2_len(
    uint32_t iterations,
    uint32_t mem_kib,
    uint32_t parallelism,
    uint32_t salt_len,
    uint32_t hash_len) {
    return argon2_encodedlen(iterations, mem_kib, parallelism, salt_len, hash_len, Argon2_id);
}

Result run_hash_job(const Job &job) {
    constexpr uint32_t kSaltLen = 16;
    auto salt = secure_random_bytes(kSaltLen);
    if (!salt.has_value()) {
        return {job.request_id, job.amx, job.callback, kStatusError, "secure random generation failed"};
    }

    std::string encoded(encoded_argon2_len(job.iterations, job.mem_kib, job.parallelism, kSaltLen, job.hash_len), '\0');
    const int rc = argon2id_hash_encoded(
        job.iterations,
        job.mem_kib,
        job.parallelism,
        job.password.data(),
        job.password.size(),
        salt->data(),
        salt->size(),
        job.hash_len,
        encoded.data(),
        encoded.size());

    if (rc != ARGON2_OK) {
        return {job.request_id, job.amx, job.callback, kStatusError, argon2_error_message(rc)};
    }

    encoded.resize(std::strlen(encoded.c_str()));
    return {job.request_id, job.amx, job.callback, kStatusOk, encoded};
}

Result run_verify_job(const Job &job) {
    const int rc = argon2id_verify(
        job.encoded_hash.c_str(),
        job.password.data(),
        job.password.size());

    if (rc == ARGON2_OK) {
        return {job.request_id, job.amx, job.callback, kStatusOk, "1"};
    }
    if (rc == ARGON2_VERIFY_MISMATCH) {
        return {job.request_id, job.amx, job.callback, kStatusOk, "0"};
    }
    return {job.request_id, job.amx, job.callback, kStatusError, argon2_error_message(rc)};
}

void push_result(Result result) {
    std::lock_guard lock(g_results_mutex);
    g_results.push_back(std::move(result));
}

void worker_main() {
    while (g_running.load()) {
        Job job;
        {
            std::unique_lock lock(g_jobs_mutex);
            g_jobs_cv.wait(lock, [] {
                return !g_running.load() || !g_jobs.empty();
            });

            if (!g_running.load() && g_jobs.empty()) {
                return;
            }

            job = std::move(g_jobs.front());
            g_jobs.pop_front();
        }

        if (job.type == Job::Type::Hash) {
            push_result(run_hash_job(job));
        } else {
            push_result(run_verify_job(job));
        }
    }
}

bool amx_is_loaded(AMX *amx) {
    std::lock_guard lock(g_amx_mutex);
    return std::any_of(g_amx_instances.begin(), g_amx_instances.end(), [amx](const AmxInstance &instance) {
        return instance.amx == amx;
    });
}

cell enqueue_job(Job job) {
    const int request_id = job.request_id;
    {
        std::lock_guard lock(g_jobs_mutex);
        if (g_jobs.size() >= kMaxPendingJobs) {
            return -kStatusQueueFull;
        }
        g_jobs.push_back(std::move(job));
    }
    g_jobs_cv.notify_one();
    return request_id;
}

bool validate_argon2_params(uint32_t mem_kib, uint32_t iterations, uint32_t parallelism, uint32_t hash_len) {
    return mem_kib >= 8192 &&
           mem_kib <= 1048576 &&
           iterations >= 1 &&
           iterations <= 16 &&
           parallelism >= 1 &&
           parallelism <= 8 &&
           hash_len >= 16 &&
           hash_len <= 128;
}

cell AMX_NATIVE_CALL n_Crypto_Argon2Hash(AMX *amx, cell *params) {
    if (params[0] < 6 * static_cast<cell>(sizeof(cell))) {
        return -kStatusBadArgument;
    }

    const std::string password = get_string(amx, params[1]);
    const std::string callback = get_string(amx, params[2]);
    const auto mem_kib = static_cast<uint32_t>(params[3]);
    const auto iterations = static_cast<uint32_t>(params[4]);
    const auto parallelism = static_cast<uint32_t>(params[5]);
    const auto hash_len = static_cast<uint32_t>(params[6]);

    if (password.empty() || callback.empty() || !validate_argon2_params(mem_kib, iterations, parallelism, hash_len)) {
        return -kStatusBadArgument;
    }

    const int request_id = g_next_request_id.fetch_add(1);
    return enqueue_job(Job{
        Job::Type::Hash,
        request_id,
        amx,
        callback,
        password,
        {},
        mem_kib,
        iterations,
        parallelism,
        hash_len,
    });
}

cell AMX_NATIVE_CALL n_Crypto_Argon2Verify(AMX *amx, cell *params) {
    if (params[0] < 3 * static_cast<cell>(sizeof(cell))) {
        return -kStatusBadArgument;
    }

    const std::string password = get_string(amx, params[1]);
    const std::string encoded_hash = get_string(amx, params[2]);
    const std::string callback = get_string(amx, params[3]);

    if (password.empty() || encoded_hash.empty() || callback.empty()) {
        return -kStatusBadArgument;
    }

    const int request_id = g_next_request_id.fetch_add(1);
    return enqueue_job(Job{
        Job::Type::Verify,
        request_id,
        amx,
        callback,
        password,
        encoded_hash,
        0,
        0,
        0,
        0,
    });
}

cell AMX_NATIVE_CALL n_Crypto_RandomHex(AMX *amx, cell *params) {
    if (params[0] < 3 * static_cast<cell>(sizeof(cell)) || params[1] <= 0 || params[1] > 4096) {
        return 0;
    }

    auto bytes = secure_random_bytes(static_cast<std::size_t>(params[1]));
    if (!bytes.has_value()) {
        return 0;
    }

    const std::string out = hex_encode(bytes->data(), bytes->size());
    return set_string(amx, params[2], out, params[3]) ? 1 : 0;
}

cell AMX_NATIVE_CALL n_Crypto_SHA256Hex(AMX *amx, cell *params) {
    if (params[0] < 3 * static_cast<cell>(sizeof(cell))) {
        return 0;
    }

    const auto out = sha256_hex(get_string(amx, params[1]));
    if (!out.has_value()) {
        return 0;
    }
    return set_string(amx, params[2], *out, params[3]) ? 1 : 0;
}

cell AMX_NATIVE_CALL n_Crypto_HMACSHA256Hex(AMX *amx, cell *params) {
    if (params[0] < 4 * static_cast<cell>(sizeof(cell))) {
        return 0;
    }

    const auto out = hmac_sha256_hex(get_string(amx, params[1]), get_string(amx, params[2]));
    if (!out.has_value()) {
        return 0;
    }
    return set_string(amx, params[3], *out, params[4]) ? 1 : 0;
}

cell AMX_NATIVE_CALL n_Crypto_Base64Encode(AMX *amx, cell *params) {
    if (params[0] < 3 * static_cast<cell>(sizeof(cell))) {
        return 0;
    }

    const auto out = base64_encode(get_string(amx, params[1]));
    if (!out.has_value()) {
        return 0;
    }
    return set_string(amx, params[2], *out, params[3]) ? 1 : 0;
}

cell AMX_NATIVE_CALL n_Crypto_Base64Decode(AMX *amx, cell *params) {
    if (params[0] < 3 * static_cast<cell>(sizeof(cell))) {
        return 0;
    }

    const auto out = base64_decode(get_string(amx, params[1]));
    if (!out.has_value()) {
        return 0;
    }
    return set_string(amx, params[2], *out, params[3]) ? 1 : 0;
}

AMX_NATIVE_INFO g_natives[] = {
    {"Crypto_Argon2Hash", n_Crypto_Argon2Hash},
    {"Crypto_Argon2Verify", n_Crypto_Argon2Verify},
    {"Crypto_RandomHex", n_Crypto_RandomHex},
    {"Crypto_SHA256Hex", n_Crypto_SHA256Hex},
    {"Crypto_HMACSHA256Hex", n_Crypto_HMACSHA256Hex},
    {"Crypto_Base64Encode", n_Crypto_Base64Encode},
    {"Crypto_Base64Decode", n_Crypto_Base64Decode},
    {nullptr, nullptr},
};

void call_pawn_callback(const Result &result) {
    if (!amx_is_loaded(result.amx)) {
        return;
    }

    int public_index = -1;
    if (amx_FindPublic(result.amx, result.callback.c_str(), &public_index) != AMX_ERR_NONE) {
        if (logprintf != nullptr) {
            logprintf("[async_crypto] callback not found: %s", result.callback.c_str());
        }
        return;
    }

    cell string_addr = 0;
    cell *physical_addr = nullptr;
    if (amx_PushString(result.amx, &string_addr, &physical_addr, result.payload.c_str(), 0, 0) != AMX_ERR_NONE) {
        return;
    }

    amx_Push(result.amx, result.status);
    amx_Push(result.amx, result.request_id);

    cell retval = 0;
    amx_Exec(result.amx, &retval, public_index);
    amx_Release(result.amx, string_addr);
}

} // namespace

PLUGIN_EXPORT unsigned int PLUGIN_CALL Supports() {
    return SUPPORTS_VERSION | SUPPORTS_AMX_NATIVES | SUPPORTS_PROCESS_TICK;
}

PLUGIN_EXPORT bool PLUGIN_CALL Load(void **ppData) {
    pAMXFunctions = ppData[PLUGIN_DATA_AMX_EXPORTS];
    logprintf = reinterpret_cast<logprintf_t>(ppData[PLUGIN_DATA_LOGPRINTF]);

    const unsigned int hardware_threads = std::max(1u, std::thread::hardware_concurrency());
    const unsigned int worker_count = std::clamp(hardware_threads / 2u, 1u, 4u);

    g_running.store(true);
    for (unsigned int i = 0; i < worker_count; ++i) {
        g_workers.emplace_back(worker_main);
    }

    if (logprintf != nullptr) {
        logprintf("[async_crypto] loaded with %u worker thread(s)", worker_count);
    }
    return true;
}

PLUGIN_EXPORT void PLUGIN_CALL Unload() {
    g_running.store(false);
    g_jobs_cv.notify_all();

    for (std::thread &worker : g_workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    g_workers.clear();

    {
        std::lock_guard lock(g_jobs_mutex);
        g_jobs.clear();
    }
    {
        std::lock_guard lock(g_results_mutex);
        g_results.clear();
    }
    {
        std::lock_guard lock(g_amx_mutex);
        g_amx_instances.clear();
    }

    if (logprintf != nullptr) {
        logprintf("[async_crypto] unloaded");
    }
}

PLUGIN_EXPORT int PLUGIN_CALL AmxLoad(AMX *amx) {
    {
        std::lock_guard lock(g_amx_mutex);
        g_amx_instances.push_back({amx});
    }
    return amx_Register(amx, g_natives, -1);
}

PLUGIN_EXPORT int PLUGIN_CALL AmxUnload(AMX *amx) {
    std::lock_guard lock(g_amx_mutex);
    g_amx_instances.erase(
        std::remove_if(g_amx_instances.begin(), g_amx_instances.end(), [amx](const AmxInstance &instance) {
            return instance.amx == amx;
        }),
        g_amx_instances.end());
    return AMX_ERR_NONE;
}

PLUGIN_EXPORT void PLUGIN_CALL ProcessTick() {
    for (std::size_t i = 0; i < kMaxCallbackResultsPerTick; ++i) {
        Result result;
        {
            std::lock_guard lock(g_results_mutex);
            if (g_results.empty()) {
                return;
            }
            result = std::move(g_results.front());
            g_results.pop_front();
        }
        call_pawn_callback(result);
    }
}
