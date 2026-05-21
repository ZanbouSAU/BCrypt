// ======================================================
// bcrypt.cpp
// BCrypt 密码哈希算法的实现文件
// 
// 包含 BlowfishState 的方法实现、核心 crypt_raw 算法、
// base64 编解码、hash 解析等完整逻辑。
// 
// 重要说明:
//   - 本文件实现了经典的 bcrypt 算法 (EksBlowfish)
//   - crypt_raw 是整个安全性的核心，请谨慎修改
//   - 所有比较使用 secure_equals 防止时序攻击
// ======================================================

#include "bcrypt.hpp"

namespace lukas {

    // ======================================================
    // BlowfishState::initialize
    // 用固定的原始 P_ORIG 和 S_ORIG 初始化状态
    // ======================================================
    void bcrypt_base::BlowfishState::initialize() {
        p = P_ORIG;
        s = S_ORIG;
    }

    // ======================================================
    // BlowfishState::key
    // 标准的 Blowfish Key Schedule
    // 
    // 1. 用 key_bytes 循环异或 P-array
    // 2. 用全零 block 连续加密，更新 P 和 S
    // ======================================================
    void bcrypt_base::BlowfishState::key(const std::vector<uint8_t>& key_bytes) {
        int k_of_p = 0;
        std::array<uint32_t, 2> lr = {0, 0};

        for (size_t i = 0; i < p.size(); ++i) {
            p[i] ^= stream_to_word(key_bytes, k_of_p);
        }

        for (size_t i = 0; i < p.size(); i += 2) {
            encipher(lr, 0);
            p[i] = lr[0];
            p[i + 1] = lr[1];
        }

        for (size_t i = 0; i < s.size(); i += 2) {
            encipher(lr, 0);
            s[i] = lr[0];
            s[i + 1] = lr[1];
        }
    }

    // ======================================================
    // BlowfishState::eks_key
    // bcrypt 特有的 Expensive Key Schedule (EKS)
    // 
    // 这是 bcrypt 比普通 Blowfish 更慢、更抗攻击的关键：
    //   - 先用 input_bytes (password) 异或 P-array
    //   - 然后在加密过程中不断混入 salt_bytes
    // ======================================================
    void bcrypt_base::BlowfishState::eks_key(const std::vector<uint8_t>& salt_bytes, const std::vector<uint8_t>& input_bytes) {
        int password_offset = 0;
        int salt_offset = 0;
        std::array<uint32_t, 2> lr = {0, 0};

        for (size_t i = 0; i < p.size(); ++i) {
            p[i] ^= stream_to_word(input_bytes, password_offset);
        }

        for (size_t i = 0; i < p.size(); i += 2) {
            lr[0] ^= stream_to_word(salt_bytes, salt_offset);
            lr[1] ^= stream_to_word(salt_bytes, salt_offset);
            encipher(lr, 0);
            p[i] = lr[0];
            p[i + 1] = lr[1];
        }

        for (size_t i = 0; i < s.size(); i += 2) {
            lr[0] ^= stream_to_word(salt_bytes, salt_offset);
            lr[1] ^= stream_to_word(salt_bytes, salt_offset);
            encipher(lr, 0);
            s[i] = lr[0];
            s[i + 1] = lr[1];
        }
    }

    // ======================================================
    // BlowfishState::encipher
    // Blowfish 标准加密函数 (16 轮 Feistel 结构)
    // 
    // 使用 4 个 S-box 进行 F 函数计算
    // 这是 Blowfish 的核心加密逻辑
    // ======================================================
    template <size_t N>
    void bcrypt_base::BlowfishState::encipher(std::array<uint32_t, N>& block_array, int offset) {
        uint32_t block = block_array[offset];
        uint32_t r = block_array[offset + 1];

        block ^= p[0];

        for (uint32_t round = 0; round <= BLOWFISH_NUM_ROUNDS - 2; ) {
            uint32_t n = s[block >> 24 & 0xff];
            n += s[0x100 | block >> 16 & 0xff];
            n ^= s[0x200 | block >> 8 & 0xff];
            n += s[0x300 | block & 0xff];
            r ^= n ^ p[++round];

            n = s[r >> 24 & 0xff];
            n += s[0x100 | r >> 16 & 0xff];
            n ^= s[0x200 | r >> 8 & 0xff];
            n += s[0x300 | r & 0xff];
            block ^= n ^ p[++round];
        }

        block_array[offset] = r ^ p[BLOWFISH_NUM_ROUNDS + 1];
        block_array[offset + 1] = block;
    }

    // ======================================================
    // create_password_hash
    // 解析 salt 字符串，准备 input_bytes，然后调用 hash_bytes
    // 
    // 支持标准 bcrypt 版本字符 (a/b/x/y)
    // 支持 enhanced hash (预先对密码做 SHA 等处理)
    // ======================================================
    std::string bcrypt_base::create_password_hash(
        const std::string& input_key,
        const std::string& salt,
        hash_type type,
        const std::function<std::vector<uint8_t>(const std::string&, hash_type, char)>* enhanced_hash_key_gen) {

        if (input_key.empty()) {
            throw std::invalid_argument("input_key: Value cannot be null or empty");
        }
        if (salt.empty()) {
            throw std::invalid_argument("salt: Invalid salt: salt cannot be null or empty");
        }
        if (!enhanced_hash_key_gen && type != hash_type::none) {
            throw std::invalid_argument(
                "hash_type: Invalid hash_type, You can't have an enhanced hash without an implementation of the key generator.");
        }

        int starting_offset = 0;
        char bcrypt_minor_revision = '\0';

        if (salt[0] != '$' || salt[1] != '2') {
            throw std::invalid_argument("Invalid salt version");
        }

        if (salt[2] == '$') {
            starting_offset = 3;
        } else {
            bcrypt_minor_revision = salt[2];
            if ((bcrypt_minor_revision != 'a' && bcrypt_minor_revision != 'b' &&
                 bcrypt_minor_revision != 'x' && bcrypt_minor_revision != 'y') ||
                salt[3] != '$') {
                throw std::invalid_argument("Invalid salt revision");
            }
            starting_offset = 4;
        }

        if (salt[starting_offset + 2] > '$') {
            throw std::invalid_argument("Missing salt rounds");
        }

        const int work_factor = std::stoi(salt.substr(starting_offset, 2));
        if (work_factor < 1 || work_factor > 31) {
            throw std::invalid_argument("Salt rounds out of range");
        }

        std::vector<uint8_t> input_bytes;
        switch (type) {
            case hash_type::none: {
                // 标准 bcrypt：对于 >= 'a' 的版本，在密码末尾添加 null 终止符
                std::string key_with_null = input_key + (bcrypt_minor_revision >= 'a' ? "\0" : "");
                input_bytes.assign(key_with_null.begin(), key_with_null.end());
                break;
            }
            default: {
                if (!enhanced_hash_key_gen) {
                    throw std::invalid_argument(
                        "hash_type: Invalid hash_type, You can't have an enhanced hash without an implementation of the key generator.");
                }
                input_bytes = (*enhanced_hash_key_gen)(input_key, type, bcrypt_minor_revision);
                break;
            }
        }

        return hash_bytes(input_bytes, salt.substr(starting_offset + 3, 22), bcrypt_minor_revision, work_factor);
    }

    // ======================================================
    // hash_bytes
    // 解码 salt → 调用 crypt_raw → 组装最终的 $2x$xx$... 字符串
    // ======================================================
    std::string bcrypt_base::hash_bytes(
        const std::vector<uint8_t>& input_bytes,
        const std::string& extracted_salt,
        const char bcrypt_minor_revision,
        const int work_factor) {

        const std::vector<uint8_t> salt_bytes = decode_base64(extracted_salt, BCRYPT_SALT_LEN);
        const auto hashed = crypt_raw(input_bytes, salt_bytes, work_factor);

        std::string result = std::format("$2{}{:02d}$", bcrypt_minor_revision, work_factor);
        result += encode_base64(salt_bytes, salt_bytes.size());
        result += encode_base64(hashed, BF_CRYPT_CIPHERTEXT_LENGTH * 4 - 1);

        return result;
    }

    // ======================================================
    // generate_salt
    // 生成 cryptographically secure 的随机 salt 并格式化
    // ======================================================
    std::string bcrypt_base::generate_salt(int work_factor, char bcrypt_minor_revision) {
        if (work_factor < MIN_ROUNDS || work_factor > MAX_ROUNDS) {
            throw std::out_of_range(
                std::format("The work factor must be between {} and {} (inclusive). Provided value: {}",
                MIN_ROUNDS, MAX_ROUNDS, work_factor)
            );
        }
        if (bcrypt_minor_revision != 'a' && bcrypt_minor_revision != 'b' && bcrypt_minor_revision != 'x' &&
            bcrypt_minor_revision != 'y') {
            throw std::invalid_argument(
                std::format("bcrypt_minor_revision: BCrypt Revision should be 'a', 'b', 'x' or 'y'. Provided value was: '{}'",
                bcrypt_minor_revision)
            );
        }

        std::vector<uint8_t> salt_bytes(BCRYPT_SALT_LEN);
        std::ranges::generate(salt_bytes, std::ref(rng_csp));

        std::string result = std::format("$2{}${:02d}$", bcrypt_minor_revision, work_factor);
        result += encode_base64(salt_bytes, salt_bytes.size());
        return result;
    }

    // ======================================================
    // secure_equals
    // 恒定时间比较，防止时序攻击
    // ======================================================
    bool bcrypt_base::secure_equals(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        if (a.empty() && b.empty()) return true;
        if (a.size() != b.size()) return false;

        int diff = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    // ======================================================
    // encode_base64
    // bcrypt 专用的 base64 编码 (使用 ./A-Za-z0-9 字符集)
    // ======================================================
    std::string bcrypt_base::encode_base64(std::span<const uint8_t> byte_array, size_t length) {
        if (length == 0 || length > byte_array.size()) {
            throw std::invalid_argument("Invalid length");
        }

        const auto encoded_size = static_cast<size_t>(std::ceil(static_cast<double>(length) * 4.0 / 3.0));
        std::string encoded;
        encoded.reserve(encoded_size);

        size_t off = 0;
        while (off < length) {
            uint32_t c1 = byte_array[off++] & 0xff;
            encoded += BASE64_CODE[c1 >> 2 & 0x3f];
            c1 = (c1 & 0x03) << 4;

            if (off >= length) {
                encoded += BASE64_CODE[c1 & 0x3f];
                break;
            }

            uint32_t c2 = byte_array[off++] & 0xff;
            c1 |= c2 >> 4 & 0x0f;
            encoded += BASE64_CODE[c1 & 0x3f];
            c1 = (c2 & 0x0f) << 2;

            if (off >= length) {
                encoded += BASE64_CODE[c1 & 0x3f];
                break;
            }

            c2 = byte_array[off++] & 0xff;
            c1 |= c2 >> 6 & 0x03;
            encoded += BASE64_CODE[c1 & 0x3f];
            encoded += BASE64_CODE[c2 & 0x3f];
        }
        return encoded;
    }

    // ======================================================
    // decode_base64
    // bcrypt 专用的 base64 解码
    // ======================================================
    std::vector<uint8_t> bcrypt_base::decode_base64(const std::string& encoded_string, const int maximum_bytes) {
        const size_t source_length = encoded_string.size();
        size_t output_length = 0;

        if (maximum_bytes <= 0) {
            throw std::invalid_argument("Invalid maximum bytes value");
        }

        std::vector<uint8_t> result(maximum_bytes);
        size_t position = 0;

        while (position < source_length - 1 && output_length < static_cast<size_t>(maximum_bytes)) {
            const int c1 = char_64(encoded_string[position++]);
            const int c2 = char_64(encoded_string[position++]);
            if (c1 == -1 || c2 == -1) break;

            result[output_length] = static_cast<uint8_t>(c1 << 2 | (c2 & 0x30) >> 4);
            if (++output_length >= static_cast<size_t>(maximum_bytes) || position >= source_length) break;

            const int c3 = char_64(encoded_string[position++]);
            if (c3 == -1) break;

            result[output_length] = static_cast<uint8_t>((c2 & 0x0f) << 4 | (c3 & 0x3c) >> 2);
            if (++output_length >= static_cast<size_t>(maximum_bytes) || position >= source_length) break;

            const int c4 = char_64(encoded_string[position++]);
            result[output_length] = static_cast<uint8_t>((c3 & 0x03) << 6 | c4);
            ++output_length;
        }
        return result;
    }

    // ======================================================
    // crypt_raw - **最核心的 bcrypt 算法**
    // 
    // 完整流程:
    //   1. 检查 work_factor 和 salt 长度
    //   2. 初始化 BlowfishState
    //   3. 调用 eks_key (password + salt)
    //   4. 进行 (1 << work_factor) 轮的 key(password) + key(salt) 交替
    //   5. 用最终状态对 magic ciphertext 加密 64 次
    //   6. 返回 24 字节结果
    // 
    // work_factor 每增加 1，计算时间翻倍。这是 bcrypt 抗暴力破解的核心。
    // ======================================================
    std::array<uint8_t, 24> bcrypt_base::crypt_raw(
        const std::vector<uint8_t>& input_bytes,
        const std::vector<uint8_t>& salt_bytes,
        const int work_factor) {

        if (work_factor < MIN_ROUNDS || work_factor > MAX_ROUNDS) {
            throw std::invalid_argument("Bad number of rounds");
        }
        if (salt_bytes.size() != BCRYPT_SALT_LEN) {
            throw std::invalid_argument("Bad salt Length");
        }

        const uint32_t rounds = 1u << work_factor;
        if (rounds < 1) {
            throw std::invalid_argument("Bad number of rounds");
        }

        std::array<uint32_t, 6> cdata = BF_CRYPT_CIPHERTEXT;
        constexpr size_t clen = cdata.size();

        BlowfishState state;
        state.initialize();
        state.eks_key(salt_bytes, input_bytes);

        // Expensive key schedule 的核心循环
        for (uint32_t i = 0; i != rounds; ++i) {
            state.key(input_bytes);
            state.key(salt_bytes);
        }

        // 对 magic ciphertext 进行 64 轮加密
        for (int i = 0; i < 64; ++i) {
            for (size_t j = 0; j < clen >> 1; ++j) {
                state.encipher(cdata, static_cast<int>(j << 1));
            }
        }

        // 将 6 个 uint32 转换为 24 字节
        std::array<uint8_t, 24> ret{};
        for (size_t i = 0, j = 0; i < clen; ++i) {
            ret[j++] = static_cast<uint8_t>(cdata[i] >> 24 & 0xff);
            ret[j++] = static_cast<uint8_t>(cdata[i] >> 16 & 0xff);
            ret[j++] = static_cast<uint8_t>(cdata[i] >> 8 & 0xff);
            ret[j++] = static_cast<uint8_t>(cdata[i] & 0xff);
        }
        return ret;
    }

    int bcrypt_base::char_64(const char character) {
        const auto uc = static_cast<unsigned char>(character);
        return uc < std::size(INDEX_64) ? INDEX_64[uc] : -1;
    }

    uint32_t bcrypt_base::stream_to_word(const std::vector<uint8_t>& data, int& offset) {
        uint32_t word = 0;
        for (int i = 0; i < 4; ++i) {
            word = word << 8 | data[offset] & 0xff;
            offset = (offset + 1) % static_cast<int>(data.size());
        }
        return word;
    }

    // ======================================================
    // hash_parser 实现
    // ======================================================

    hash_information hash_parser::get_hash_information(const std::string& hash) {
        hash_format_descriptor format{0};
        if (!is_valid_hash(hash, format)) {
            throw_invalid_hash_format();
        }
        int work_factor = 10 * (hash[format.workfactor_offset] - '0') + (hash[format.workfactor_offset + 1] - '0');
        return {
            hash.substr(0, format.setting_length),
            hash.substr(1, format.version_length),
            work_factor,
            hash.substr(format.hash_offset)};
    }

    int hash_parser::get_work_factor(const std::string& hash) {
        hash_format_descriptor format{0};
        if (!is_valid_hash(hash, format)) {
            throw_invalid_hash_format();
        }
        const int offset = format.workfactor_offset;
        return 10 * (hash[offset] - '0') + (hash[offset + 1] - '0');
    }

    std::string hash_parser::get_salt(const std::string& hash) {
        hash_format_descriptor format{0};
        if (!is_valid_hash(hash, format)) {
            throw_invalid_hash_format();
        }
        if (hash.empty() || hash.size() < 29) {
            throw std::invalid_argument("Invalid BCrypt hash.");
        }
        return hash.substr(0, 22 + format.hash_offset);
    }

    bool hash_parser::is_valid_hash(const std::string& hash, hash_format_descriptor& format) {
        if (hash.empty()) {
            throw std::invalid_argument("hash: Value cannot be null or empty");
        }
        if (hash.size() != 59 && hash.size() != 60) {
            format = hash_format_descriptor(0);
            return false;
        }
        if (hash.substr(0, 2) != "$2") {
            format = hash_format_descriptor(0);
            return false;
        }

        size_t offset = 2;
        if (is_valid_bcrypt_version_char(hash[offset])) {
            offset++;
            format = NEW_FORMAT_DESCRIPTOR;
        } else {
            format = OLD_FORMAT_DESCRIPTOR;
        }

        if (hash[offset++] != '$') {
            format = hash_format_descriptor(0);
            return false;
        }
        if (!is_ascii_numeric(hash[offset++]) || !is_ascii_numeric(hash[offset++])) {
            format = hash_format_descriptor(0);
            return false;
        }
        if (hash[offset++] != '$') {
            format = hash_format_descriptor(0);
            return false;
        }
        for (size_t i = offset; i < hash.size(); ++i) {
            if (!is_valid_bcrypt_base64_char(hash[i])) {
                format = hash_format_descriptor(0);
                return false;
            }
        }
        return true;
    }

    bool hash_parser::is_valid_bcrypt_version_char(const char value) {
        return value == 'a' || value == 'b' || value == 'x' || value == 'y';
    }

    bool hash_parser::is_valid_bcrypt_base64_char(const char value) {
        return value == '.' || value == '/' ||
               (value >= '0' && value <= '9') ||
               (value >= 'A' && value <= 'Z') ||
               (value >= 'a' && value <= 'z');
    }

    bool hash_parser::is_ascii_numeric(const char value) {
        return value >= '0' && value <= '9';
    }

    void hash_parser::throw_invalid_hash_format() {
        throw std::invalid_argument("Invalid Hash Format");
    }

    // ======================================================
    // bcrypt 高层 API 实现
    // ======================================================

    std::string bcrypt::validate_and_upgrade_hash(
        const std::string& current_key,
        const std::string& current_hash,
        const std::string& new_key,
        int work_factor,
        const bool force_work_factor) {

        if (current_key.empty())
            throw std::invalid_argument("current_key: Value cannot be null or empty");
        if (current_hash.size() != 60)
            throw std::invalid_argument("current_hash: Invalid Hash");
        if (!verify(current_key, current_hash))
            throw std::runtime_error("Current credentials could not be authenticated");
        if (current_hash[0] != '$' || current_hash[1] != '2')
            throw std::invalid_argument("Invalid bcrypt version");
        if (work_factor < 1 || work_factor > 31)
            throw std::invalid_argument("Work factor out of range");

        int starting_offset = 3;
        if (current_hash[2] != '$') {
            if (const char minor = current_hash[2];
                (minor != 'a' && minor != 'b' && minor != 'x' && minor != 'y') || current_hash[3] != '$') {
                throw std::invalid_argument("Invalid bcrypt revision");
            }
            starting_offset = 4;
        }

        if (current_hash.size() <= starting_offset + 2 || current_hash[starting_offset + 2] > '$') {
            throw std::invalid_argument("Missing work factor");
        }

        if (const int current_work_factor = std::stoi(current_hash.substr(starting_offset, 2));
            !force_work_factor && current_work_factor > work_factor) {
            work_factor = current_work_factor;
        }

        return hash_password(new_key, generate_salt(work_factor));
    }

    bool bcrypt::verify(const std::string& text, const std::string& hash) {
        return secure_equals(get_bytes(hash), get_bytes(hash_password(text, hash)));
    }

    std::string bcrypt::hash_password(const std::string& input_key, int work_factor) {
        return hash_password(input_key, generate_salt(work_factor, DEFAULT_HASH_VERSION));
    }

    std::string bcrypt::hash_password(const std::string& input_key, const std::string& salt) {
        return create_password_hash(input_key, salt);
    }

    bool bcrypt::password_needs_rehash(const std::string& hash, int new_minimum_work_load) {
        if (hash.size() < 7) return true;
        const int starting_offset = hash[2] == '$' ? 3 : 4;
        const int work_factor = std::stoi(hash.substr(starting_offset, 2));
        return work_factor < new_minimum_work_load;
    }

    hash_information bcrypt::interrogate_hash(const std::string& hash) {
        try {
            return hash_parser::get_hash_information(hash);
        } catch (const std::exception& ex) {
            throw hash_information_exception("Error handling string interrogation", ex);
        }
    }

} // namespace lukas