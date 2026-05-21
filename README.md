# BCrypt

一个现代化的 C++ BCrypt 密码哈希库（Shared Library）。

本库基于经典的 **EksBlowfish** 算法实现 BCrypt，提供安全、易用、高性能的密码哈希功能，适用于 C++20 项目。

---

## ✨ 特性

- 完整的 BCrypt 实现（支持 `$2a$`、`$2b$`、`$2x$`、`$2y$` 版本）
- 支持可配置的 **work factor**（成本因子，推荐 10~12）
- 内置安全的随机 salt 生成
- 提供恒定时间比较（`secure_equals`），防止时序攻击
- 支持 hash 解析、验证、升级
- 现代 C++20 实现（`std::format`、`std::span`、`std::ranges`）
- 符号可见性控制（`hidden` visibility），适合制作共享库
- 支持自定义增强哈希（通过回调 + SHA256/SHA512 等）
- CMake 构建系统友好

---

## 📦 构建

### 依赖

- C++20 编译器（GCC 10+ / Clang 12+ / MSVC 2019+ 推荐）
- CMake 3.20 或更高版本

### 构建步骤

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j
```

构建完成后会生成：

- `libLukasLibrary.so`（Linux）
- `LukasLibrary.dll`（Windows）
- `LukasLibrary.lib`（Windows 导入库）

---

## 🚀 快速开始

### 1. 哈希密码

```cpp
#include "bcrypt.hpp"
#include <iostream>

int main() {
    // 使用默认 work factor (11)
    std::string hash = lukas::bcrypt::hash_password("my_secure_password");
    std::cout << "Hash: " << hash << std::endl;

    // 指定 work factor（越高越安全，但越慢）
    std::string strong_hash = lukas::bcrypt::hash_password("my_secure_password", 12);
}
```

### 2. 验证密码

```cpp
bool is_valid = lukas::bcrypt::verify("my_secure_password", hash);
if (is_valid) {
    std::cout << "密码正确！" << std::endl;
}
```

### 3. 检查是否需要重新哈希（升级 work factor）

```cpp
if (lukas::bcrypt::password_needs_rehash(hash, 12)) {
    // 需要重新哈希（例如把 work factor 从 11 升级到 12）
    std::string new_hash = lukas::bcrypt::hash_password("my_secure_password", 12);
}
```

### 4. 解析 Hash 信息

```cpp
auto info = lukas::bcrypt::interrogate_hash(hash);
std::cout << "版本: " << info.version << std::endl;
std::cout << "Work Factor: " << info.work_factor << std::endl;
std::cout << info.to_string() << std::endl;
```

### 5. 生成 Salt（高级用法）

```cpp
std::string salt = lukas::bcrypt::generate_salt(12, 'b');
std::string hash = lukas::bcrypt::hash_password("password", salt);
```

---

## 📚 主要 API

### `lukas::bcrypt` 类（推荐使用）

| 方法 | 说明 |
|------|------|
| `hash_password(key, work_factor)` | 生成 BCrypt hash |
| `verify(text, hash)` | 验证密码是否正确 |
| `password_needs_rehash(hash, min_work_factor)` | 判断是否需要重新哈希 |
| `interrogate_hash(hash)` | 解析 hash，返回结构化信息 |
| `generate_salt(work_factor, version)` | 生成随机 salt |
| `validate_and_upgrade_hash(...)` | 验证旧密码并用新密码重新哈希（支持升级 work factor） |

### 其他工具类

- `lukas::hash_parser`：解析和验证 BCrypt hash 格式
- `lukas::hash_information`：存储解析后的 hash 信息
- `lukas::bcrypt_base`：底层实现（通常不需要直接使用）

---

## ⚠️ 注意事项

1. **Work Factor 推荐值**
   - 开发/测试环境：`10` ~ `11`
   - 生产环境：`12` 及以上（根据服务器性能调整）
   - 每增加 1，计算时间大约翻倍

2. **版本字符**
   - 推荐使用 `'b'`（修复了早期版本的一些问题）
   - 默认使用 `'a'`

3. **符号可见性**
   - 本库已开启 `hidden` visibility，外部只能看到使用 `LUKASLIBRARY_API` 导出的符号。
   - Windows 下需要正确定义 `LUKASLIBRARY_EXPORTS`（CMake 已处理）。

4. **线程安全**
   - `generate_salt()` 使用 `std::random_device`，多线程下是安全的。
   - 哈希计算本身是线程安全的。

---

## 📁 项目结构

```
LukasLibrary/
├── bcrypt.hpp          # 头文件（公共 API）
├── bcrypt.cpp          # 实现文件
├── CMakeLists.txt      # 构建脚本
└── README.md
```

---

## 🛠️ 高级用法

### 使用增强哈希（预哈希密码）

```cpp
// 示例：先对密码做 SHA-512，再进行 bcrypt
auto enhanced_key_gen = [](const std::string& password, 
                           lukas::hash_type type, 
                           char revision) -> std::vector<uint8_t> {
    // 这里可以实现 SHA256 / SHA512 等逻辑
    return lukas::bcrypt_base::get_bytes(password); // 示例，实际应做哈希
};

std::string hash = lukas::bcrypt_base::create_password_hash(
    "password", 
    salt, 
    lukas::hash_type::sha512, 
    &enhanced_key_gen
);
```

---

## 📄 许可证

本项目采用 MIT License。

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

**LukasLibrary** —— 简单、安全、现代的 C++ BCrypt 实现。
