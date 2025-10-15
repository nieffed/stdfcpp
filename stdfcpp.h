#ifndef STDFCPP_H
#define STDFCPP_H

static_assert(__cplusplus >= 201703L, "C++17 or newer standard is required.");

#include <vector>
#include <string>
#include <iterator>
#include <cstddef>
#include <climits>
#include <array>
#include <charconv>
#include <stdexcept>
#include <fstream>
#include <cassert>
#include <functional>
#include <cstdint>
#include <iostream>
#include <chrono>
#include <cstring>
#include <cerrno>
#include <variant>
#include <map>

namespace stdfcpp
{




#pragma region Exceptions
struct Exception : public std::runtime_error
{
    inline explicit Exception(const std::string& message)
        : std::runtime_error{message}
    {
    }
};

struct BadReadException : public Exception
{
    inline explicit BadReadException(std::size_t position)
        : Exception{std::string("Stream error (badbit) occurred at position ")
            + std::to_string(position) + "."}
    {
    }
};

struct EofException : public Exception
{
    inline explicit EofException(std::size_t position)
        : Exception{"EOF occurred at position " + std::to_string(position) +
            "."}
    {
    }
};

struct FormatException : public Exception
{
    inline explicit FormatException(
        const std::string& message)
        : Exception{message}
    {
    }
};

struct RecordTooSmallException : public FormatException
{
    inline explicit RecordTooSmallException(const std::string& memberName,
        std::size_t neededBytes,
        std::size_t bytesLeft)
        : FormatException{"Field " + memberName + ": need " +
            std::to_string(neededBytes) + " bytes, have " +
            std::to_string(bytesLeft) + " bytes."}
    {
    }
};

struct RecordTooLargeException : public FormatException
{
    inline explicit RecordTooLargeException(
        std::size_t parsedBytes,
        std::size_t totalBytes)
        : FormatException{"Only " + std::to_string(parsedBytes) + " of " +
            std::to_string(totalBytes) + " bytes were parsed."}
    {
    }
};

struct InvalidGdrType : public FormatException
{
    inline explicit InvalidGdrType(uint8_t typeCode)
        : FormatException{"Invalid GEN_DATA type code: " +
            std::to_string(typeCode)}
    {
    }
};

struct NotImplementedException : public Exception
{
    inline explicit NotImplementedException(const std::string& message)
        : Exception{message}
    {
    }
};
#pragma endregion Exceptions




#pragma region Helper Functions
inline std::string to_hex(uint8_t v)
{
    static constexpr char k[] = "0123456789ABCDEF";
    std::string s(2, '0');
    s[0] = k[(v >> 4) & 0xF];
    s[1] = k[v & 0xF];
    return "0x" + s; // e.g. "0x0A"
}
#pragma endregion Helper Functions




#pragma region Nibbles
class Nibble
{
    uint8_t _value;

    static constexpr uint8_t create_value(uint8_t value, bool strict)
    {
        if (strict && value & 0xf0)
            throw std::invalid_argument("Nibble: high nibble must be zero");
        return value & 0x0f;
    }

public:
    constexpr explicit Nibble(uint8_t value, bool strict = false)
        : _value{create_value(value, strict)}
    {
    }

    constexpr uint8_t get_value() const noexcept
    {
        return _value;
    }

    void set_value(uint8_t value, bool strict = false)
    {
        _value = create_value(value, strict);
    }
};

struct NibbleVector
{
    using storage_type = std::vector<std::byte>;
    using size_type    = std::size_t;
    using value_type   = Nibble; // each nibble as 0..15

    inline NibbleVector()
        : _data{}
        , _nibbleCount{0}
    {
    }

    // Construct from packed bytes + explicit nibble count.
    // For odd nibble counts, the high nibble of the final byte is padding
    // (ignored on iteration).
    inline NibbleVector(storage_type data, size_type nibbleCount)
        : _data{std::move(data)}
        , _nibbleCount{nibbleCount}
    {
        if (_data.size() * 2 < _nibbleCount)
            throw std::invalid_argument("Not enough bytes for nibbleCount");
    }

    // Accessors
    inline const storage_type& data() const noexcept { return _data; }
    inline size_type size() const noexcept { return _nibbleCount; }
    inline bool empty() const noexcept { return _nibbleCount == 0; }

    // Random-access read of a nibble. LOW nibble first within each byte.
    inline value_type operator[](size_type idx) const noexcept
    {
        // caller must ensure idx < _nibbleCount
        const size_type byte_i = idx >> 1;
        const bool use_low = ((idx & 1u) == 0u); // 0->low, 1->high
        const uint8_t b = std::to_integer<uint8_t>(_data[byte_i]);
        return use_low ? static_cast<value_type>( b       & 0x0F)
                       : static_cast<value_type>((b >> 4) & 0x0F);
    }

    inline value_type at(size_type idx) const
    {
        if (idx >= _nibbleCount) throw std::out_of_range("nibble index");
        return (*this)[idx];
    }

    // ---- Const forward iterator over nibbles (read-only) ----
    class const_iterator
    {
    public:
        using iterator_category = std::forward_iterator_tag;
        using value_type        = NibbleVector::value_type;
        using difference_type   = std::ptrdiff_t;
        using pointer           = const value_type*;  // not used
        using reference         = value_type;         // by value

        inline const_iterator() = default;

        inline reference operator*() const noexcept { return _owner->operator[](_pos); }
        inline const_iterator& operator++() noexcept { ++_pos; return *this; }
        inline const_iterator operator++(int) noexcept { auto tmp=*this; ++(*this); return tmp; }

        inline friend bool operator==(const const_iterator& a, const const_iterator& b)
        {
            return a._owner == b._owner && a._pos == b._pos;
        }

        inline friend bool operator!=(const const_iterator& a, const const_iterator& b)
        {
            return !(a == b);
        }

    private:
        friend class NibbleVector;
        const NibbleVector* _owner = nullptr;
        size_type _pos = 0;
        const_iterator(const NibbleVector* o, size_type p) : _owner{o}, _pos{p} {}
    };

    inline const_iterator begin() const noexcept { return const_iterator(this, 0); }
    inline const_iterator end()   const noexcept { return const_iterator(this, _nibbleCount); }
    inline const_iterator cbegin() const noexcept { return begin(); }
    inline const_iterator cend() const noexcept { return end(); }

private:
    storage_type _data;
    size_type _nibbleCount;
};
#pragma endregion Nibbles




#pragma region Record Parser
using GdrData = std::vector<std::variant<std::monostate, uint8_t, uint16_t,
        uint32_t, int8_t, int16_t, int32_t, float, double, std::string,
        std::vector<std::byte>, std::vector<bool>, Nibble>>;

class RecordParsingSettings
{
    bool _bigEndian;
    bool _vaxFloat;
    bool _strictNibbles;
    bool _strictBitVectors;

public:
    constexpr RecordParsingSettings()
        : _bigEndian{false}
        , _vaxFloat{false}
        , _strictNibbles{true}
        , _strictBitVectors{true}
    {
    }

    constexpr bool get_big_endian() const noexcept
    {
        return _bigEndian;
    }

    constexpr bool get_vax_float() const noexcept
    {
        return _vaxFloat;
    }

    constexpr bool get_strict_nibbles() const noexcept
    {
        return _strictNibbles;
    }

    constexpr bool get_strict_bit_vectors() const noexcept
    {
        return _strictBitVectors;
    }

    [[deprecated("Setting endianness is not recommended")]]
    inline RecordParsingSettings& set_big_endian(bool set) noexcept
    {
        _bigEndian = set;
        return *this;
    }

    [[deprecated("Setting float type is not recommended")]]
    inline RecordParsingSettings& set_vax_float(bool set) noexcept
    {
        _vaxFloat = set;
        return *this;
    }

    inline RecordParsingSettings& set_strict_nibbles(bool set) noexcept
    {
        _strictNibbles = set;
        return *this;
    }

    inline RecordParsingSettings& set_strict_bit_vectors(bool set) noexcept
    {
        _strictBitVectors = set;
        return *this;
    }

    friend class StdfReader;
};

class RecordParser
{
    const RecordParsingSettings _settings;
    const std::byte* _b;
    const uint16_t _len;
    uint16_t _i;

    inline uint16_t get_uint16_unchecked()
    {
        uint8_t b0 = std::to_integer<uint8_t>(_b[_i    ]);
        uint8_t b1 = std::to_integer<uint8_t>(_b[_i + 1]);
        uint16_t ret = _settings.get_big_endian()
            ? (uint16_t{b0} << 8)
            | (uint16_t{b1}     )
            : (uint16_t{b0}     )
            | (uint16_t{b1} << 8);
        _i += sizeof(uint16_t);
        return ret;
    }

    inline uint32_t get_uint32_unchecked()
    {
        uint8_t b0 = std::to_integer<uint8_t>(_b[_i    ]);
        uint8_t b1 = std::to_integer<uint8_t>(_b[_i + 1]);
        uint8_t b2 = std::to_integer<uint8_t>(_b[_i + 2]);
        uint8_t b3 = std::to_integer<uint8_t>(_b[_i + 3]);
        uint32_t ret = _settings.get_big_endian()
            ? (uint32_t{b0} << 24)
            | (uint32_t{b1} << 16)
            | (uint32_t{b2} <<  8)
            | (uint32_t{b3}      )
            : (uint32_t{b0}      )
            | (uint32_t{b1} <<  8)
            | (uint32_t{b2} << 16)
            | (uint32_t{b3} << 24);
        _i += sizeof(uint32_t);
        return ret;
    }

    inline uint64_t get_uint64_unchecked()
    {
        uint8_t b0 = std::to_integer<uint8_t>(_b[_i    ]);
        uint8_t b1 = std::to_integer<uint8_t>(_b[_i + 1]);
        uint8_t b2 = std::to_integer<uint8_t>(_b[_i + 2]);
        uint8_t b3 = std::to_integer<uint8_t>(_b[_i + 3]);
        uint8_t b4 = std::to_integer<uint8_t>(_b[_i + 4]);
        uint8_t b5 = std::to_integer<uint8_t>(_b[_i + 5]);
        uint8_t b6 = std::to_integer<uint8_t>(_b[_i + 6]);
        uint8_t b7 = std::to_integer<uint8_t>(_b[_i + 7]);
        uint64_t ret = _settings.get_big_endian()
            ? (uint64_t{b0} << 56)
            | (uint64_t{b1} << 48)
            | (uint64_t{b2} << 40)
            | (uint64_t{b3} << 32)
            | (uint64_t{b4} << 24)
            | (uint64_t{b5} << 16)
            | (uint64_t{b6} <<  8)
            | (uint64_t{b7}      )
            : (uint64_t{b0}      )
            | (uint64_t{b1} <<  8)
            | (uint64_t{b2} << 16)
            | (uint64_t{b3} << 24)
            | (uint64_t{b4} << 32)
            | (uint64_t{b5} << 40)
            | (uint64_t{b6} << 48)
            | (uint64_t{b7} << 56);
        _i += sizeof(uint64_t);
        return ret;
    }

    static inline float vax_f_floating_to_float(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3)
    {
        // Rebuild logical order from VAX byte address order (b1 b0 b3 b2).
        const uint32_t vax_bits = (uint32_t(b1) << 24)
                                | (uint32_t(b0) << 16)
                                | (uint32_t(b3) <<  8)
                                | (uint32_t(b2)      );
        const uint32_t sign = (vax_bits >> 31) & 0x1u;
        const uint32_t expv = (vax_bits >> 23) & 0xFFu;      // VAX bias 128
        const uint32_t frac = (vax_bits      ) & 0x7FFFFFu;  // 23-bit fraction

        // expv == 0 : zero iff frac==0; otherwise reserved -> qNaN
        if (expv == 0)
        {
            const uint32_t out_bits = (frac == 0)
                ? ( sign << 31)
                : ((sign << 31) | 0x7FC00000u);
            float out;
            std::memcpy(&out, &out_bits, sizeof(out));
            return out;
        }

        // Exponent mapping: IEEE e = expv - 2
        int e = int(expv) - 2;

        // Normal case
        if (e > 0)
        {
            // **Key fix**: do NOT shift the VAX fraction; copy as-is.
            const uint32_t out_bits = (sign << 31) | (uint32_t(e) << 23) | frac;
            float out;
            std::memcpy(&out, &out_bits, sizeof(out));
            return out;
        }

        // Subnormal case (e <= 0): shift a 24-bit mantissa (1.frac) with RNE.
        const uint32_t mant = (1u << 23) | frac;  // 1.frac in 24 bits
        const int shift = 1 - e;                  // >=1 (expv is 1 or 2)

        // Truncate
        uint32_t frac_out = (shift >= 24) ? 0u : (mant >> shift);

        // Round-to-nearest-even
        const uint32_t rem     = (shift == 0) ? 0u : (mant & ((1u << shift) - 1u));
        const uint32_t halfway = (shift == 0) ? 0u : (1u << (shift - 1));
        if (rem > halfway || (rem == halfway && (frac_out & 1u)))
        {
            ++frac_out;
            if (frac_out == (1u << 23))  // rounded into a normal
            {
                // exp=1, frac=0 (smallest normal)
                const uint32_t out_bits = (sign << 31) | (1u << 23);
                float out;
                std::memcpy(&out, &out_bits, sizeof(out));
                return out;
            }
        }

        const uint32_t out_bits = (sign << 31) | frac_out;  // exponent field = 0 (subnormal)
        float out;
        std::memcpy(&out, &out_bits, sizeof(out));
        return out;
    }

    static inline double vax_d_floating_to_double(
        uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3,
        uint8_t b4, uint8_t b5, uint8_t b6, uint8_t b7)
    {
        // VAX D_floating byte address order is 1,0,3,2,5,4,7,6
        // (16-bit little-endian pairs in big-endian pair order)
        const uint16_t w0 = (uint16_t(b1) << 8) | uint16_t(b0);
        const uint16_t w1 = (uint16_t(b3) << 8) | uint16_t(b2);
        const uint16_t w2 = (uint16_t(b5) << 8) | uint16_t(b4);
        const uint16_t w3 = (uint16_t(b7) << 8) | uint16_t(b6);
        const uint64_t vax_bits = (uint64_t(w0) << 48)
                                | (uint64_t(w1) << 32)
                                | (uint64_t(w2) << 16)
                                |  uint64_t(w3);

        const uint64_t sign   = (vax_bits >> 63) & 0x1u;
        const uint64_t expv   = (vax_bits >> 55) & 0xffu;                  // bias 128
        const uint64_t frac55 =  vax_bits        & 0x007FFFFFFFFFFFFFULL;  // 55-bit fraction

        if (expv == 0)
        {
            // zero iff fraction==0; otherwise map to qNaN (policy choice)
            const uint64_t out_bits = (frac55 == 0)
                ? ( sign << 63)                            // +0 or -0 (keeps sign bit)
                : ((sign << 63) | 0x7FF8000000000000ULL);  // qNaN
            double out;
            std::memcpy(&out, &out_bits, sizeof(out));
            return out;
        }

        // Exponent mapping:
        // IEEE(bias 1023) needs E_ieee = (expv - 128 /*VAX bias*/) - 1  (to shift 0.1m -> 1.m),
        // so field = E_ieee + 1023 = expv + 894.
        uint64_t e_ieee = expv + 894u;  // fits well within [1,2046]
                                        // VAX D normals never become subnormals in IEEE.

        // Shrink 55 fraction bits (m) to IEEE's 52, with round-to-nearest-even.
        uint64_t frac52 = frac55 >> 3;         // keep top 52 bits
        const uint64_t rem = frac55 & 0x7ULL;  // 3 dropped bits
        const uint64_t half = 0x4ULL;          // 0b100

        if (rem > half || (rem == half && (frac52 & 1ULL)))
        {
            ++frac52;
            if (frac52 == (1ULL << 52))
            {
                // carry spilled into the hidden 1 -> bump exponent, clear fraction
                frac52 = 0;
                ++e_ieee;  // still far from 2047 given VAX range
            }
        }

        const uint64_t out_bits = (sign << 63) | (e_ieee << 52) | frac52;
        double out;
        std::memcpy(&out, &out_bits, sizeof(out));
        return out;
    }

    inline float get_float_unchecked()
    {
        float out;
        if (_settings.get_vax_float())
        {
            out = vax_f_floating_to_float(
                std::to_integer<uint8_t>(_b[_i    ]),
                std::to_integer<uint8_t>(_b[_i + 1]),
                std::to_integer<uint8_t>(_b[_i + 2]),
                std::to_integer<uint8_t>(_b[_i + 3]));
            _i += sizeof(out);
        }
        else
        {
            uint32_t u = get_uint32_unchecked();
            std::memcpy(&out, &u, sizeof(out));
        }
        return out;
    }

    inline double get_double_unchecked()
    {
        double out;
        if (_settings.get_vax_float())
        {
            out = vax_d_floating_to_double(
                std::to_integer<uint8_t>(_b[_i    ]),
                std::to_integer<uint8_t>(_b[_i + 1]),
                std::to_integer<uint8_t>(_b[_i + 2]),
                std::to_integer<uint8_t>(_b[_i + 3]),
                std::to_integer<uint8_t>(_b[_i + 4]),
                std::to_integer<uint8_t>(_b[_i + 5]),
                std::to_integer<uint8_t>(_b[_i + 6]),
                std::to_integer<uint8_t>(_b[_i + 7]));
            _i += sizeof(out);
        }
        else
        {
            uint64_t u = get_uint64_unchecked();
            std::memcpy(&out, &u, sizeof(out));
        }
        return out;
    }

public:
    inline RecordParser() = delete;

    inline explicit RecordParser(const RecordParsingSettings& settings, const std::byte* b,
        uint16_t len)
        : _settings{settings}
        , _b{b}
        , _len{len}
        , _i{0}
    {
    }

    inline uint16_t get_bytes_left() const
    {
        return _len - _i;
    }

    // Useful for parsing U*1 data types
    inline uint8_t get_uint8(const std::string& name)
    {
        if (get_bytes_left() < sizeof(uint8_t))
            throw RecordTooSmallException(name, sizeof(uint8_t), get_bytes_left());
        uint8_t ret{std::to_integer<uint8_t>(_b[_i])};
        _i += 1;
        return ret;
    }

    // Useful for parsing U*1 data types conditionally
    inline uint8_t get_uint8_cond(const std::string& name, bool condition, uint8_t valueIfFalse)
    {
        if (condition) return get_uint8(name);
        else return valueIfFalse;
    }

    // Useful for parsing U*2 data types
    inline uint16_t get_uint16(const std::string& name)
    {
        if (get_bytes_left() < sizeof(uint16_t))
            throw RecordTooSmallException(name, sizeof(uint16_t), get_bytes_left());
        return get_uint16_unchecked();
    }

    // Useful for parsing U*2 data types conditionally
    inline uint16_t get_uint16_cond(const std::string& name, bool condition, uint16_t valueIfFalse)
    {
        if (condition) return get_uint16(name);
        else return valueIfFalse;
    }

    // Useful for parsing U*4 data types
    inline uint32_t get_uint32(const std::string& name)
    {
        if (get_bytes_left() < sizeof(uint32_t))
            throw RecordTooSmallException(name, sizeof(uint32_t), get_bytes_left());
        return get_uint32_unchecked();
    }

    // Useful for parsing U*4 data types conditionally
    inline uint32_t get_uint32_cond(const std::string& name, bool condition, uint32_t valueIfFalse)
    {
        if (condition) return get_uint32(name);
        else return valueIfFalse;
    }
    
    // Useful for parsing U*8 data types
    inline uint64_t get_uint64(const std::string& name)
    {
        if (get_bytes_left() < sizeof(uint64_t))
            throw RecordTooSmallException(name, sizeof(uint64_t), get_bytes_left());
        return get_uint64_unchecked();
    }

    // Useful for parsing C*1 types
    inline char get_char(const std::string& name)
    {
        return (char)get_uint8(name);
    }

    // Useful for parsing C*12 and C*f data types
    inline std::string get_string(const std::string& name, uint8_t len)
    {
        if (get_bytes_left() < len)
            throw RecordTooSmallException(name, len, get_bytes_left());
        std::string ret(reinterpret_cast<const char*>(_b) + _i, len);
        _i += len;
        return ret;
    }

    // Useful for parsing C*n data types
    inline std::string get_string(const std::string& name)
    {
        return get_string(name, get_uint8(name));
    }

    // Useful for parsing C*n data types conditionally
    inline std::string get_string_cond(const std::string& name, bool condition,
        const std::string& valueIfFalse)
    {
        if (condition) return get_string(name);
        else return valueIfFalse;
    }

    // Useful for parsing kxU*1 data types
    inline std::vector<uint8_t> get_uint8_vector(const std::string& name, uint16_t len)
    {
        if (len == 0)
            return {};
        std::size_t bytesNeeded = (std::size_t)len * sizeof(uint8_t);
        if (get_bytes_left() < bytesNeeded)
            throw RecordTooSmallException(name, bytesNeeded, get_bytes_left());
        auto* p = reinterpret_cast<const uint8_t*>(_b) + _i;
        std::vector<uint8_t> ret(p, p + bytesNeeded);
        _i += bytesNeeded;
        return ret;
    }

    // Useful for parsing kxU*2 data types
    inline std::vector<uint16_t> get_uint16_vector(const std::string& name, uint16_t len)
    {
        if (len == 0)
            return {};
        std::size_t bytesNeeded = (std::size_t)len * sizeof(uint16_t);
        if (get_bytes_left() < bytesNeeded)
            throw RecordTooSmallException(name, bytesNeeded, get_bytes_left());
        std::vector<uint16_t> ret;
        ret.reserve(len);
        for (uint16_t i = 0; i < len; i++)
            ret.emplace_back(get_uint16_unchecked());
        return ret;
    }

    // Useful for parsing kxU*2 data types conditionally
    inline std::vector<uint16_t> get_uint16_vector_cond(const std::string& name, uint16_t len,
        bool condition, const std::vector<uint16_t> valueIfFalse)
    {
        if (condition) return get_uint16_vector(name, len);
        else return valueIfFalse;
    }

    // Useful for parsing kxC*n data types
    inline std::vector<std::string> get_string_vector(const std::string& name, uint16_t len)
    {
        std::vector<std::string> ret;
        ret.reserve(len);
        for (uint16_t i = 0; i < len; i++)
            ret.emplace_back(get_string(name));
        return ret;
    }

    // Useful for parsing R*4 data types
    inline float get_float(const std::string& name)
    {
        if (get_bytes_left() < sizeof(float))
            throw RecordTooSmallException(name, sizeof(float), get_bytes_left());
        return get_float_unchecked();
    }

    // Useful for parsing R*4 data types conditionally
    inline float get_float_cond(const std::string& name, bool condition, float valueIfFalse)
    {
        if (condition) return get_float(name);
        else return valueIfFalse;
    }

    inline std::vector<float> get_float_vector(const std::string& name, uint16_t len)
    {
        std::vector<float> ret;
        ret.reserve(len);
        for (uint16_t i = 0; i < len; i++)
            ret.emplace_back(get_float(name));
        return ret;
    }

    // Useful for parsing R*8 data types
    inline double get_double(const std::string& name)
    {
        if (get_bytes_left() < sizeof(double))
            throw RecordTooSmallException(name, sizeof(double), get_bytes_left());
        return get_double_unchecked();
    }

    // Useful for parsing I*1 data types
    inline int8_t get_int8(const std::string& name)
    {
        return (int8_t)get_uint8(name);
    }

    // Useful for parsing I*1 data types conditionally
    inline int8_t get_int8_cond(const std::string& name, bool condition, int8_t valueIfFalse)
    {
        if (condition) return get_int8(name);
        else return valueIfFalse;
    }

    // Useful for parsing I*2 data types
    inline int16_t get_int16(const std::string& name)
    {
        uint16_t u = get_uint16(name);
        int16_t i;
        std::memcpy(&i, &u, sizeof(i));
        return i;
    }

    // Useful for parsing I*2 data types conditionally
    inline int16_t get_int16_cond(const std::string& name, bool condition, int16_t valueIfFalse)
    {
        if (condition) return get_int16(name);
        else return valueIfFalse;
    }

    // Useful for parsing I*4 data types
    inline int32_t get_int32(const std::string& name)
    {
        uint32_t u = get_uint32(name);
        int32_t i;
        std::memcpy(&i, &u, sizeof(i));
        return i;
    }

    // Useful for parsing I*4 data types conditionally
    inline int32_t get_int32_cond(const std::string& name, bool condition, int32_t valueIfFalse)
    {
        if (condition) return get_int32(name);
        else return valueIfFalse;
    }

    // Useful for parsing B*n data types
    inline std::vector<std::byte> get_byte_vector(const std::string& name, uint16_t len)
    {
        if (get_bytes_left() < len)
            throw RecordTooSmallException(name, len, get_bytes_left());
        std::vector<std::byte> ret(_b + _i, _b + _i + len);
        _i += len;
        return ret;
    }

    // Useful for parsing B*n data types
    inline std::vector<std::byte> get_byte_vector(const std::string& name)
    {
        return get_byte_vector(name, get_uint8(name));
    }

    // Useful for parsing D*n data types
    inline std::vector<bool> get_bit_vector(const std::string& name, uint16_t len)
    {
        std::vector<bool> ret;
        ret.reserve(len);
        auto bytes = get_byte_vector(name, len / 8 + (len % 8 ? 1 : 0));

        // STDF v4: Unused bits at the high-order end of the last byte must be zero.
        // We store data LSB-first, so the "unused high-order" means the top (8 - (len%8)) bits.
        if (_settings.get_strict_bit_vectors() && !bytes.empty())
        {
            const uint8_t numBitsInLastByte = (len & 7u); // 0..7 data bits in the last byte
            if (numBitsInLastByte != 0)
            {
                const uint8_t lastByte = std::to_integer<uint8_t>(bytes.back());
                // mask of the padding (high-order) bits that must be zero
                const uint8_t paddingMask =
                    static_cast<uint8_t>(~((1u << numBitsInLastByte) - 1u)); // e.g. data_bits=5 -> 0xE0
                if ((lastByte & paddingMask) != 0)
                {
                    throw FormatException{"D*n padding bits must be zero (" + name + "): last="
                        + to_hex(lastByte) + ", pad_mask=" + to_hex(paddingMask)};
                }
            }
        }

        uint16_t outBits{0};
        for (auto b : bytes)
        {
            auto value = std::to_integer<uint8_t>(b);
            for (int bit = 0; bit < 8 && outBits < len; ++bit)
            {
                ret.push_back((value >> bit) & 1); // LSB first
                ++outBits;
            }
        }
        return ret;
    }

    // Useful for parsing D*n data types
    inline std::vector<bool> get_bit_vector(const std::string& name)
    {
        return get_bit_vector(name, get_uint16(name));
    }

    // Useful for parsing D*n data types conditionally
    inline std::vector<bool> get_bit_vector_cond(const std::string& name, bool condition,
        const std::vector<bool>& valueIfFalse)
    {
        if (condition) return get_bit_vector(name);
        else return valueIfFalse;
    }

    // Useful for parsing N*1 data types
    inline Nibble get_nibble(const std::string& name)
    {
        return Nibble{get_uint8(name), _settings.get_strict_nibbles()};
    }

    // Useful for parsing kxN*1 data types
    inline NibbleVector get_nibble_vector(const std::string& name, uint16_t len)
    {
        bool evenNibbleCount = len % 2 == 0;
        uint16_t byteCount = evenNibbleCount ? len / 2 : (len + 1) / 2;
        std::vector<std::byte> byteVector = get_byte_vector(name, byteCount);
        if (_settings.get_strict_nibbles() && !evenNibbleCount)
        {
            uint8_t lastByte = std::to_integer<uint8_t>(byteVector.back());
            if (lastByte & 0xF0)
                throw FormatException("kxN*1 padding bits must be zero (" + name + "): last="
                    + to_hex(lastByte) + ", pad_mask=0xF0");
        }
        return {byteVector, len};
    }

    // Useful for parsing kxN*1 data types conditionally
    inline NibbleVector get_nibble_vector_cond(const std::string& name, uint16_t len, bool condition,
        const NibbleVector& valueIfFalse)
    {
        if (condition) return get_nibble_vector(name, len);
        else return valueIfFalse;
    }

    inline GdrData get_gdr_data(uint16_t len)
    {
        std::string name{"GEN_DATA"};
        GdrData ret;
        ret.reserve(len);
        while (len)
        {
            uint8_t typeCode = get_uint8(name);
            switch (typeCode)
            {
                case 0: ret.emplace_back(std::monostate{}); break;
                case 1: ret.emplace_back(get_uint8(name)); break;
                case 2: ret.emplace_back(get_uint16(name)); break;
                case 3: ret.emplace_back(get_uint32(name)); break;
                case 4: ret.emplace_back(get_int8(name)); break;
                case 5: ret.emplace_back(get_int16(name)); break;
                case 6: ret.emplace_back(get_int32(name)); break;
                case 7: ret.emplace_back(get_float(name)); break;
                case 8: ret.emplace_back(get_double(name)); break;
                case 10: ret.emplace_back(get_string(name)); break;
                case 11: ret.emplace_back(get_byte_vector(name)); break;
                case 12: ret.emplace_back(get_bit_vector(name)); break;
                case 13: ret.emplace_back(get_nibble(name)); break;
                default: throw InvalidGdrType{typeCode};
            }
            len -= 1;
        }
        return ret;
    }

    // Ensure no bytes are left to parse
    inline void throw_if_leftover_bytes()
    {
        if (get_bytes_left())
            throw RecordTooLargeException(_i, _len);
    }
};
#pragma endregion Record Parser




#pragma region Record Header
class RecordHeader
{
    uint16_t _recLen;
    uint8_t _recTyp;
    uint8_t _recSub;

    inline explicit RecordHeader(RecordParser p)
        : _recLen{p.get_uint16("REC_LEN")}
        , _recTyp{p.get_uint8("REC_TYP")}
        , _recSub{p.get_uint8("REC_SUB")}
    {
        p.throw_if_leftover_bytes();
    }

public:
    constexpr RecordHeader()
        : _recLen{0}
        , _recTyp{0}
        , _recSub{0}
    {
    }

    inline explicit RecordHeader(const RecordParsingSettings& settings, const std::byte* b,
        uint16_t len)
        : RecordHeader{RecordParser{settings, b, len}}
    {
    }

    inline uint16_t get_rec_len() const noexcept
    {
        return _recLen;
    }

    inline uint8_t get_rec_typ() const noexcept
    {
        return _recTyp;
    }

    inline uint8_t get_rec_sub() const noexcept
    {
        return _recSub;
    }
};
#pragma endregion Record Header




#pragma region FAR
class Far
{
    uint8_t _cpuType;
    uint8_t _stdfVer;

    inline explicit Far(RecordParser p)
        : _cpuType{p.get_uint8("CPU_TYPE")}
        , _stdfVer{p.get_uint8("STDF_VER")}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Far() = delete;

    inline explicit Far(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Far{RecordParser{settings, b, len}}
    {
    }

    constexpr uint8_t get_cpu_type() const noexcept
    {
        return _cpuType;
    }

    constexpr uint8_t get_stdf_ver() const noexcept
    {
        return _stdfVer;
    }
};
#pragma endregion FAR




#pragma region ATR
class Atr
{
    uint32_t _modTim;
    std::string _cmdLine;

    inline explicit Atr(RecordParser p)
        : _modTim{p.get_uint32("MOD_TIM")}
        , _cmdLine{p.get_string("CMD_LINE")}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Atr() = delete;

    inline explicit Atr(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Atr{RecordParser{settings, b, len}}
    {
    }

    constexpr uint32_t get_mod_tim() const noexcept
    {
        return _modTim;
    }

    constexpr const std::string& get_cmd_line() const noexcept
    {
        return _cmdLine;
    }
};
#pragma endregion ATR




#pragma region MIR
class Mir
{
    uint32_t _setupT;
    uint32_t _startT;
    uint8_t _statNum;
    char _modeCod;
    char _rtstCod;
    char _protCod;
    uint16_t _burnTim;
    char _cmodCod;
    std::string _lotId;
    std::string _partTyp;
    std::string _nodeNam;
    std::string _tstrTyp;
    std::string _jobNam;
    std::string _jobRev;
    std::string _sblotId;
    std::string _operNam;
    std::string _execTyp;
    std::string _execVer;
    std::string _testCod;
    std::string _tstTemp;
    std::string _userTxt;
    std::string _auxFile;
    std::string _pkgTyp;
    std::string _famlyId;
    std::string _dateCod;
    std::string _facilId;
    std::string _floorId;
    std::string _procId;
    std::string _operFrq;
    std::string _specNam;
    std::string _specVer;
    std::string _flowId;
    std::string _setupId;
    std::string _dsgnRev;
    std::string _engId;
    std::string _romCod;
    std::string _serlNum;
    std::string _suprNam;

    inline explicit Mir(RecordParser p)
        : _setupT{p.get_uint32("SETUP_T")}
        , _startT{p.get_uint32("START_T")}
        , _statNum{p.get_uint8("STAT_NUM")}
        , _modeCod{p.get_char("MODE_COD")}
        , _rtstCod{p.get_char("RTST_COD")}
        , _protCod{p.get_char("PROT_COD")}
        , _burnTim{p.get_uint16("BURN_TIM")}
        , _cmodCod{p.get_char("CMOD_COD")}
        , _lotId{p.get_string("LOT_ID")}
        , _partTyp{p.get_string("PART_TYP")}
        , _nodeNam{p.get_string("NODE_NAM")}
        , _tstrTyp{p.get_string("TSTR_TYP")}
        , _jobNam{p.get_string("JOB_NAM")}
        , _jobRev{p.get_string("JOB_REV")}
        , _sblotId{p.get_string("SBLOT_ID")}
        , _operNam{p.get_string("OPER_NAM")}
        , _execTyp{p.get_string("EXEC_TYP")}
        , _execVer{p.get_string("EXEC_VER")}
        , _testCod{p.get_string("TEST_COD")}
        , _tstTemp{p.get_string("TST_TEMP")}
        , _userTxt{p.get_string("USER_TXT")}
        , _auxFile{p.get_string("AUX_FILE")}
        , _pkgTyp{p.get_string("PKG_TYP")}
        , _famlyId{p.get_string("FAMLY_ID")}
        , _dateCod{p.get_string("DATE_COD")}
        , _facilId{p.get_string("FACIL_ID")}
        , _floorId{p.get_string("FLOOR_ID")}
        , _procId{p.get_string("PROC_ID")}
        , _operFrq{p.get_string("OPER_FRQ")}
        , _specNam{p.get_string("SPEC_NAM")}
        , _specVer{p.get_string("SPEC_VER")}
        , _flowId{p.get_string("FLOW_ID")}
        , _setupId{p.get_string("SETUP_ID")}
        , _dsgnRev{p.get_string("DSGN_REV")}
        , _engId{p.get_string("ENG_ID")}
        , _romCod{p.get_string("ROM_COD")}
        , _serlNum{p.get_string("SERL_NUM")}
        , _suprNam{p.get_string("SUPR_NAM")}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Mir() = delete;
    
    inline explicit Mir(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Mir{RecordParser{settings, b, len}}
    {
    }

    constexpr uint32_t get_setup_t() const noexcept
    {
        return _setupT;
    }

    constexpr uint32_t get_start_t() const noexcept
    {
        return _startT;
    }

    constexpr uint8_t get_stat_num() const noexcept
    {
        return _statNum;
    }

    constexpr char get_mode_cod() const noexcept
    {
        return _modeCod;
    }

    constexpr char get_rtst_cod() const noexcept
    {
        return _rtstCod;
    }

    constexpr char get_prot_cod() const noexcept
    {
        return _protCod;
    }

    constexpr uint16_t get_burn_tim() const noexcept
    {
        return _burnTim;
    }

    constexpr char get_cmod_cod() const noexcept
    {
        return _cmodCod;
    }

    constexpr const std::string& get_lot_id() const noexcept
    {
        return _lotId;
    }

    constexpr const std::string& get_part_typ() const noexcept
    {
        return _partTyp;
    }

    constexpr const std::string& get_node_nam() const noexcept
    {
        return _nodeNam;
    }

    constexpr const std::string& get_tstr_typ() const noexcept
    {
        return _tstrTyp;
    }

    constexpr const std::string& get_job_nam() const noexcept
    {
        return _jobNam;
    }

    constexpr const std::string& get_job_rev() const noexcept
    {
        return _jobRev;
    }

    constexpr const std::string& get_sblot_id() const noexcept
    {
        return _sblotId;
    }

    constexpr const std::string& get_oper_nam() const noexcept
    {
        return _operNam;
    }

    constexpr const std::string& get_exec_typ() const noexcept
    {
        return _execTyp;
    }

    constexpr const std::string& get_exec_ver() const noexcept
    {
        return _execVer;
    }

    constexpr const std::string& get_test_cod() const noexcept
    {
        return _testCod;
    }

    constexpr const std::string& get_tst_temp() const noexcept
    {
        return _tstTemp;
    }

    constexpr const std::string& get_user_txt() const noexcept
    {
        return _userTxt;
    }

    constexpr const std::string& get_aux_file() const noexcept
    {
        return _auxFile;
    }

    constexpr const std::string& get_pkg_typ() const noexcept
    {
        return _pkgTyp;
    }

    constexpr const std::string& get_famly_id() const noexcept
    {
        return _famlyId;
    }

    constexpr const std::string& get_date_cod() const noexcept
    {
        return _dateCod;
    }

    constexpr const std::string& get_facil_id() const noexcept
    {
        return _facilId;
    }

    constexpr const std::string& get_floor_id() const noexcept
    {
        return _floorId;
    }

    constexpr const std::string& get_proc_id() const noexcept
    {
        return _procId;
    }

    constexpr const std::string& get_oper_frq() const noexcept
    {
        return _operFrq;               
    }

    constexpr const std::string& get_spec_nam() const noexcept
    {
        return _specNam;
    }

    constexpr const std::string& get_spec_ver() const noexcept
    {
        return _specVer;
    }

    constexpr const std::string& get_flow_id() const noexcept
    {
        return _flowId;
    }

    constexpr const std::string& get_setup_id() const noexcept
    {
        return _setupId;
    }

    constexpr const std::string& get_dsgn_rev() const noexcept
    {
        return _dsgnRev;
    }

    constexpr const std::string& get_eng_id() const noexcept
    {
        return _engId;
    }

    constexpr const std::string& get_rom_cod() const noexcept
    {
        return _romCod;
    }

    constexpr const std::string& get_serl_num() const noexcept
    {
        return _serlNum;
    }

    constexpr const std::string& get_supr_nam() const noexcept
    {
        return _suprNam;
    }
};
#pragma endregion MIR




#pragma region MRR
class Mrr
{
    uint32_t _finishT;
    char _dispCod;
    std::string _usrDesc;
    std::string _excDesc;

    inline explicit Mrr(RecordParser p)
        : _finishT{p.get_uint32("FINISH_T")}
        , _dispCod{p.get_char("DISP_COD")}
        , _usrDesc{p.get_string("USR_DESC")}
        , _excDesc{p.get_string("EXC_DESC")}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Mrr() = delete;

    inline explicit Mrr(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Mrr{RecordParser{settings, b, len}}
    {
    }

    constexpr uint32_t get_finish_t() const noexcept
    {
        return _finishT;
    }

    constexpr char get_disp_cod() const noexcept
    {
        return _dispCod;
    }

    constexpr const std::string& get_usr_desc() const noexcept
    {
        return _usrDesc;
    }

    constexpr const std::string& get_exc_desc() const noexcept
    {
        return _excDesc;
    }
};
#pragma endregion MRR




#pragma region PCR
class Pcr
{
    uint8_t _headNum;
    uint8_t _siteNum;
    uint32_t _partCnt;
    uint32_t _rtstCnt;
    uint32_t _abrtCnt;
    uint32_t _goodCnt;
    uint32_t _funcCnt;

    inline explicit Pcr(RecordParser p)
        : _headNum{p.get_uint8("HEAD_NUM")}
        , _siteNum{p.get_uint8("SITE_NUM")}
        , _partCnt{p.get_uint32("PART_CNT")}
        , _rtstCnt{p.get_uint32("RTST_CNT")}
        , _abrtCnt{p.get_uint32("ABRT_CNT")}
        , _goodCnt{p.get_uint32("GOOD_CNT")}
        , _funcCnt{p.get_uint32("FUNC_CNT")}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Pcr() = delete;

    inline explicit Pcr(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Pcr{RecordParser{settings, b, len}}
    {
    }

    constexpr uint8_t get_head_num() const noexcept
    {
        return _headNum;
    }

    constexpr uint8_t get_site_num() const noexcept
    {
        return _siteNum;
    }

    constexpr uint32_t get_part_cnt() const noexcept
    {
        return _partCnt;
    }

    constexpr uint32_t get_rtst_cnt() const noexcept
    {
        return _rtstCnt;
    }

    constexpr uint32_t get_abrt_cnt() const noexcept
    {
        return _abrtCnt;
    }

    constexpr uint32_t get_good_cnt() const noexcept
    {
        return _goodCnt;
    }

    constexpr uint32_t get_func_cnt() const noexcept
    {
        return _funcCnt;
    }
};
#pragma endregion PCR




#pragma region HBR
class Hbr
{
    uint8_t _headNum;
    uint8_t _siteNum;
    uint16_t _hbinNum;
    uint32_t _hbinCnt;
    char _hbinPf;
    std::string _hbinNam;

    inline explicit Hbr(RecordParser p)
        : _headNum{p.get_uint8("HEAD_NUM")}
        , _siteNum{p.get_uint8("SITE_NUM")}
        , _hbinNum{p.get_uint16("HBIN_NUM")}
        , _hbinCnt{p.get_uint32("HBIN_CNT")}
        , _hbinPf{p.get_char("HBIN_PF")}
        , _hbinNam{p.get_string("HBIN_NAM")}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Hbr() = delete;

    inline explicit Hbr(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Hbr{RecordParser{settings, b, len}}
    {
    }

    constexpr uint8_t get_head_num() const noexcept
    {
        return _headNum;
    }

    constexpr uint8_t get_site_num() const noexcept
    {
        return _siteNum;
    }

    constexpr uint16_t get_hbin_num() const noexcept
    {
        return _hbinNum;
    }

    constexpr uint32_t get_hbin_cnt() const noexcept
    {
        return _hbinCnt;
    }

    constexpr char get_hbin_pf() const noexcept
    {
        return _hbinPf;
    }

    constexpr const std::string& get_hbin_nam() const noexcept
    {
        return _hbinNam;
    }
};
#pragma endregion HBR




#pragma region SBR
class Sbr
{
    uint8_t _headNum;
    uint8_t _siteNum;
    uint16_t _sbinNum;
    uint32_t _sbinCnt;
    char _sbinPf;
    std::string _sbinNam;

    inline explicit Sbr(RecordParser p)
        : _headNum{p.get_uint8("HEAD_NUM")}
        , _siteNum{p.get_uint8("SITE_NUM")}
        , _sbinNum{p.get_uint16("SBIN_NUM")}
        , _sbinCnt{p.get_uint32("SBIN_CNT")}
        , _sbinPf{p.get_char("SBIN_PF")}
        , _sbinNam{p.get_string("SBIN_NAM")}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Sbr() = delete;

    inline explicit Sbr(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Sbr{RecordParser{settings, b, len}}
    {
    }

    constexpr uint8_t get_head_num() const noexcept
    {
        return _headNum;
    }

    constexpr uint8_t get_site_num() const noexcept
    {
        return _siteNum;
    }

    constexpr uint16_t get_sbin_num() const noexcept
    {
        return _sbinNum;
    }

    constexpr uint32_t get_sbin_cnt() const noexcept
    {
        return _sbinCnt;
    }

    constexpr char get_sbin_pf() const noexcept
    {
        return _sbinPf;
    }

    constexpr const std::string& get_sbin_nam() const noexcept
    {
        return _sbinNam;
    }
};
#pragma endregion SBR




#pragma region PMR
class Pmr
{
    uint16_t _pmrIndx;
    uint16_t _chanTyp;
    std::string _chanNam;
    std::string _phyNam;
    std::string _logNam;
    uint8_t _headNum;
    uint8_t _siteNum;

    inline explicit Pmr(RecordParser p)
        : _pmrIndx{p.get_uint16("PMR_INDX")}
        , _chanTyp{p.get_uint16("CHAN_TYP")}
        , _chanNam{p.get_string("CHAN_NAM")}
        , _phyNam{p.get_string("PHY_NAM")}
        , _logNam{p.get_string("LOG_NAM")}
        , _headNum{p.get_uint8("HEAD_NUM")}
        , _siteNum{p.get_uint8("SITE_NUM")}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Pmr() = delete;

    inline explicit Pmr(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Pmr{RecordParser{settings, b, len}}
    {
    }

    constexpr uint16_t get_pmr_indx() const noexcept
    {
        return _pmrIndx;
    }

    constexpr uint16_t get_chan_typ() const noexcept
    {
        return _chanTyp;
    }

    constexpr const std::string& get_chan_nam() const noexcept
    {
        return _chanNam;
    }

    constexpr const std::string& get_phy_nam() const noexcept
    {
        return _phyNam;
    }

    constexpr const std::string& get_log_nam() const noexcept
    {
        return _logNam;
    }

    constexpr uint8_t get_head_num() const noexcept
    {
        return _headNum;
    }

    constexpr uint8_t get_site_num() const noexcept
    {
        return _siteNum;
    }
};
#pragma endregion PMR




#pragma region PGR
class Pgr
{
    uint16_t _grpIndx;
    std::string _grpNam;
    uint16_t _indxCnt;
    std::vector<uint16_t> _pmrIndx;

    inline explicit Pgr(RecordParser p)
        : _grpIndx{p.get_uint16("GRP_INDX")}
        , _grpNam{p.get_string("GRP_NAM")}
        , _indxCnt{p.get_uint16("INDX_CNT")}
        , _pmrIndx{p.get_uint16_vector("PMR_INDX", _indxCnt)}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Pgr() = delete;

    inline explicit Pgr(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Pgr{RecordParser{settings, b, len}}
    {
    }

    constexpr uint16_t get_grp_indx() const noexcept
    {
        return _grpIndx;
    }

    constexpr const std::string& get_grp_nam() const noexcept
    {
        return _grpNam;
    }

    constexpr uint16_t get_indx_cnt() const noexcept
    {
        return _indxCnt;
    }

    constexpr const std::vector<uint16_t>& get_pmr_indx() const noexcept
    {
        return _pmrIndx;
    }
};
#pragma endregion PGR




#pragma region PLR
class Plr
{
    uint16_t _grpCnt;
    std::vector<uint16_t> _grpIndx;
    std::vector<uint16_t> _grpMode;
    std::vector<uint8_t> _grpRadx;
    std::vector<std::string> _pgmChar;
    std::vector<std::string> _rtnChar;
    std::vector<std::string> _pgmChal;
    std::vector<std::string> _rtnChal;

    inline explicit Plr(RecordParser p)
        : _grpCnt{p.get_uint16("GRP_CNT")}
        , _grpIndx{p.get_uint16_vector("GRP_INDX", _grpCnt)}
        , _grpMode{p.get_uint16_vector("GRP_MODE", _grpCnt)}
        , _grpRadx{p.get_uint8_vector("GRP_RADX", _grpCnt)}
        , _pgmChar{p.get_string_vector("PGM_CHAR", _grpCnt)}
        , _rtnChar{p.get_string_vector("RTN_CHAR", _grpCnt)}
        , _pgmChal{p.get_string_vector("PGM_CHAL", _grpCnt)}
        , _rtnChal{p.get_string_vector("RTN_CHAL", _grpCnt)}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Plr() = delete;

    inline explicit Plr(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Plr{RecordParser{settings, b, len}}
    {
    }

    inline uint16_t get_grp_cnt() const noexcept
    {
        return _grpCnt;
    }

    constexpr const std::vector<uint16_t>& get_grp_indx() const noexcept
    {
        return _grpIndx;
    }

    constexpr const std::vector<uint16_t>& get_grp_mode() const noexcept
    {
        return _grpMode;
    }

    constexpr const std::vector<uint8_t>& get_grp_radx() const noexcept
    {
        return _grpRadx;
    }
    
    constexpr const std::vector<std::string>& get_pgm_char() const noexcept
    {
        return _pgmChar;
    }

    constexpr const std::vector<std::string>& get_rtn_char() const noexcept
    {
        return _rtnChar;
    }

    constexpr const std::vector<std::string>& get_pgm_chal() const noexcept
    {
        return _pgmChal;
    }

    constexpr const std::vector<std::string>& get_rtn_chal() const noexcept
    {
        return _rtnChal;
    }
};
#pragma endregion PLR




#pragma region RDR
class Rdr
{
    uint16_t _numBins;
    std::vector<uint16_t> _rtstBin;

    inline explicit Rdr(RecordParser p)
        : _numBins{p.get_uint16("NUM_BINS")}
        , _rtstBin{p.get_uint16_vector("RTST_BIN", _numBins)}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Rdr() = delete;

    inline explicit Rdr(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Rdr{RecordParser{settings, b, len}}
    {
    }

    constexpr uint16_t get_num_bins() const noexcept
    {
        return _numBins;
    }

    constexpr const std::vector<uint16_t>& get_rtst_bin() const noexcept
    {
        return _rtstBin;
    }
};
#pragma endregion RDR




#pragma region SDR
class Sdr
{
    uint8_t _headNum;
    uint8_t _siteGrp;
    uint8_t _siteCnt;
    std::vector<uint8_t> _siteNum;
    std::string _handTyp;
    std::string _handId;
    std::string _cardTyp;
    std::string _cardId;
    std::string _loadTyp;
    std::string _loadId;
    std::string _dibTyp;
    std::string _dibId;
    std::string _cablTyp;
    std::string _cablId;
    std::string _contTyp;
    std::string _contId;
    std::string _lasrTyp;
    std::string _lasrId;
    std::string _extrTyp;
    std::string _extrId;

    inline explicit Sdr(RecordParser p)
        : _headNum{p.get_uint8("HEAD_NUM")}
        , _siteGrp{p.get_uint8("SITE_GRP")}
        , _siteCnt{p.get_uint8("SITE_CNT")}
        , _siteNum{p.get_uint8_vector("SITE_NUM", _siteCnt)}
        , _handTyp{p.get_string("HAND_TYP")}
        , _handId{p.get_string("HAND_ID")}
        , _cardTyp{p.get_string("CARD_TYP")}
        , _cardId{p.get_string("CARD_ID")}
        , _loadTyp{p.get_string("LOAD_TYP")}
        , _loadId{p.get_string("LOAD_ID")}
        , _dibTyp{p.get_string("DIB_TYP")}
        , _dibId{p.get_string("DIB_ID")}
        , _cablTyp{p.get_string("CABL_TYP")}
        , _cablId{p.get_string("CABL_ID")}
        , _contTyp{p.get_string("CONT_TYP")}
        , _contId{p.get_string("CONT_ID")}
        , _lasrTyp{p.get_string("LASR_TYP")}
        , _lasrId{p.get_string("LASR_ID")}
        , _extrTyp{p.get_string("EXTR_TYP")}
        , _extrId{p.get_string("EXTR_ID")}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Sdr() = delete;

    inline explicit Sdr(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Sdr{RecordParser{settings, b, len}}
    {
    }

    constexpr uint8_t get_head_num() const noexcept
    {
        return _headNum;
    }

    constexpr uint8_t get_site_grp() const noexcept
    {
        return _siteGrp;
    }

    constexpr uint8_t get_site_cnt() const noexcept
    {
        return _siteCnt;
    }

    constexpr const std::vector<uint8_t>& get_site_num() const noexcept
    {
        return _siteNum;
    }

    constexpr const std::string& get_hand_typ() const noexcept
    {
        return _handTyp;
    }

    constexpr const std::string& get_hand_id() const noexcept
    {
        return _handId;
    }

    constexpr const std::string& get_card_typ() const noexcept
    {
        return _cardTyp;
    }

    constexpr const std::string& get_card_id() const noexcept
    {
        return _cardId;
    }

    constexpr const std::string& get_load_typ() const noexcept
    {
        return _loadTyp;
    }

    constexpr const std::string& get_load_id() const noexcept
    {
        return _loadId;
    }

    constexpr const std::string& get_dib_typ() const noexcept
    {
        return _dibTyp;
    }

    constexpr const std::string& get_dib_id() const noexcept
    {
        return _dibId;
    }

    constexpr const std::string& get_cabl_typ() const noexcept
    {
        return _cablTyp;
    }

    constexpr const std::string& get_cabl_id() const noexcept
    {
        return _cablId;
    }

    constexpr const std::string& get_cont_typ() const noexcept
    {
        return _contTyp;
    }

    constexpr const std::string& get_cont_id() const noexcept
    {
        return _contId;
    }

    constexpr const std::string& get_lasr_typ() const noexcept
    {
        return _lasrTyp;
    }

    constexpr const std::string& get_lasr_id() const noexcept
    {
        return _lasrId;
    }

    constexpr const std::string& get_extr_typ() const noexcept
    {
        return _extrTyp;
    }

    constexpr const std::string& get_extr_id() const noexcept
    {
        return _extrId;
    }
};
#pragma endregion SDR




#pragma region WIR
class Wir
{
    uint8_t _headNum;
    uint8_t _siteGrp;
    uint32_t _startT;
    std::string _waferId;

    inline explicit Wir(RecordParser p)
        : _headNum{p.get_uint8("HEAD_NUM")}
        , _siteGrp{p.get_uint8("SITE_GRP")}
        , _startT{p.get_uint32("START_T")}
        , _waferId{p.get_string("WAFER_ID")}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Wir() = delete;

    inline explicit Wir(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Wir{RecordParser{settings, b, len}}
    {
    }

    constexpr uint8_t get_head_num() const noexcept
    {
        return _headNum;
    }

    constexpr uint8_t get_site_grp() const noexcept
    {
        return _siteGrp;
    }

    constexpr uint32_t get_start_t() const noexcept
    {
        return _startT;
    }

    constexpr const std::string& get_wafer_id() const noexcept
    {
        return _waferId;
    }
};
#pragma endregion WIR




#pragma region WRR
class Wrr
{
    uint8_t _headNum;
    uint8_t _siteGrp;
    uint32_t _finishT;
    uint32_t _partCnt;
    uint32_t _rtstCnt;
    uint32_t _abrtCnt;
    uint32_t _goodCnt;
    uint32_t _funcCnt;
    std::string _waferId;
    std::string _fabwfId;
    std::string _frameId;
    std::string _maskId;
    std::string _usrDesc;
    std::string _excDesc;

    inline explicit Wrr(RecordParser p)
        : _headNum{p.get_uint8("HEAD_NUM")}
        , _siteGrp{p.get_uint8("SITE_GRP")}
        , _finishT{p.get_uint32("FINISH_T")}
        , _partCnt{p.get_uint32("PART_CNT")}
        , _rtstCnt{p.get_uint32("RTST_CNT")}
        , _abrtCnt{p.get_uint32("ABRT_CNT")}
        , _goodCnt{p.get_uint32("GOOD_CNT")}
        , _funcCnt{p.get_uint32("FUNC_CNT")}
        , _waferId{p.get_string("WAFER_ID")}
        , _fabwfId{p.get_string("FABWF_ID")}
        , _frameId{p.get_string("FRAME_ID")}
        , _maskId{p.get_string("MASK_ID")}
        , _usrDesc{p.get_string("USR_DESC")}
        , _excDesc{p.get_string("EXC_DESC")}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Wrr() = delete;

    inline explicit Wrr(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Wrr{RecordParser{settings, b, len}}
    {
    }

    constexpr uint8_t get_head_num() const noexcept
    {
        return _headNum;
    }

    constexpr uint8_t get_site_grp() const noexcept
    {
        return _siteGrp;
    }

    constexpr uint32_t get_finish_t() const noexcept
    {
        return _finishT;
    }

    constexpr uint32_t get_part_cnt() const noexcept
    {
        return _partCnt;
    }

    constexpr uint32_t get_rtst_cnt() const noexcept
    {
        return _rtstCnt;
    }

    constexpr uint32_t get_abrt_cnt() const noexcept
    {
        return _abrtCnt;
    }

    constexpr uint32_t get_good_cnt() const noexcept
    {
        return _goodCnt;
    }

    constexpr uint32_t get_func_cnt() const noexcept
    {
        return _funcCnt;
    }

    constexpr const std::string& get_wafer_id() const noexcept
    {
        return _waferId;
    }

    constexpr const std::string& get_fabwf_id() const noexcept
    {
        return _fabwfId;
    }

    constexpr const std::string& get_frame_id() const noexcept
    {
        return _frameId;
    }

    constexpr const std::string& get_mask_id() const noexcept
    {
        return _maskId;
    }

    constexpr const std::string& get_usr_desc() const noexcept
    {
        return _usrDesc;
    }

    constexpr const std::string& get_exc_desc() const noexcept
    {
        return _excDesc;
    }
};
#pragma endregion WRR




#pragma region WCR
class Wcr
{
    float _wafrSiz;
    float _dieHt;
    float _dieWid;
    uint8_t _wfUnits;
    char _wfFlat;
    int16_t _centerX;
    int16_t _centerY;
    char _posX;
    char _posY;

    inline explicit Wcr(RecordParser p)
        : _wafrSiz{p.get_float("WAFR_SIZ")}
        , _dieHt{p.get_float("DIE_HT")}
        , _dieWid{p.get_float("DIE_WID")}
        , _wfUnits{p.get_uint8("WF_UNITS")}
        , _wfFlat{p.get_char("WF_FLAT")}
        , _centerX{p.get_int16("CENTER_X")}
        , _centerY{p.get_int16("CENTER_Y")}
        , _posX{p.get_char("POS_X")}
        , _posY{p.get_char("POS_Y")}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Wcr() = delete;

    inline explicit Wcr(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Wcr{RecordParser{settings, b, len}}
    {
    }

    constexpr float get_wafr_siz() const noexcept
    {
        return _wafrSiz;
    }

    constexpr float get_die_ht() const noexcept
    {
        return _dieHt;
    }

    constexpr float get_die_wid() const noexcept
    {
        return _dieWid;
    }

    constexpr uint8_t get_wf_units() const noexcept
    {
        return _wfUnits;
    }

    constexpr char get_wf_flat() const noexcept
    {
        return _wfFlat;
    }

    constexpr int16_t get_center_x() const noexcept
    {
        return _centerX;
    }

    constexpr int16_t get_center_y() const noexcept
    {
        return _centerY;
    }

    constexpr char get_pos_x() const noexcept
    {
        return _posX;
    }

    constexpr char get_pos_y() const noexcept
    {
        return _posY;
    }
};
#pragma endregion WCR




#pragma region PIR
class Pir
{
    uint8_t _headNum;
    uint8_t _siteNum;

    inline explicit Pir(RecordParser p)
        : _headNum{p.get_uint8("HEAD_NUM")}
        , _siteNum{p.get_uint8("SITE_NUM")}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Pir() = delete;

    inline explicit Pir(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Pir{RecordParser{settings, b, len}}
    {
    }

    constexpr uint8_t get_head_num() const noexcept
    {
        return _headNum;
    }

    constexpr uint8_t get_site_num() const noexcept
    {
        return _siteNum;
    }
};
#pragma endregion PIR




#pragma region PRR
class Prr
{
    uint8_t _headNum;
    uint8_t _siteNum;
    uint8_t _partFlg;
    uint16_t _numTest;
    uint16_t _hardBin;
    uint16_t _softBin;
    int16_t _xCoord;
    int16_t _yCoord;
    uint32_t _testT;
    std::string _partId;
    std::string _partTxt;
    std::vector<std::byte> _partFix;

    inline explicit Prr(RecordParser p)
        : _headNum{p.get_uint8("HEAD_NUM")}
        , _siteNum{p.get_uint8("SITE_NUM")}
        , _partFlg{p.get_uint8("PART_FLG")}
        , _numTest{p.get_uint16("NUM_TEST")}
        , _hardBin{p.get_uint16("HARD_BIN")}
        , _softBin{p.get_uint16("SOFT_BIN")}
        , _xCoord{p.get_int16("X_COORD")}
        , _yCoord{p.get_int16("Y_COORD")}
        , _testT{p.get_uint32("TEST_T")}
        , _partId{p.get_string("PART_ID")}
        , _partTxt{p.get_string("PART_TXT")}
        , _partFix{p.get_byte_vector("PART_FIX")}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Prr() = delete;

    inline explicit Prr(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Prr{RecordParser{settings, b, len}}
    {
    }

    constexpr uint8_t get_head_num() const noexcept
    {
        return _headNum;
    }

    constexpr uint8_t get_site_num() const noexcept
    {
        return _siteNum;
    }

    constexpr uint8_t get_part_flg() const noexcept
    {
        return _partFlg;
    }

    constexpr uint16_t get_num_test() const noexcept
    {
        return _numTest;
    }

    constexpr uint16_t get_hard_bin() const noexcept
    {
        return _hardBin;
    }

    constexpr uint16_t get_soft_bin() const noexcept
    {
        return _softBin;
    }

    constexpr int16_t get_x_coord() const noexcept
    {
        return _xCoord;
    }

    constexpr int16_t get_y_coord() const noexcept
    {
        return _yCoord;
    }

    constexpr uint32_t get_test_t() const noexcept
    {
        return _testT;
    }

    constexpr const std::string& get_part_id() const noexcept
    {
        return _partId;
    }

    constexpr const std::string& get_part_txt() const noexcept
    {
        return _partTxt;
    }

    constexpr const std::vector<std::byte>& get_part_fix() const noexcept
    {
        return _partFix;
    }
};
#pragma endregion PRR




#pragma region TSR
class Tsr
{
    uint8_t _headNum;
    uint8_t _siteNum;
    char _testTyp;
    uint32_t _testNum;
    uint32_t _execCnt;
    uint32_t _failCnt;
    uint32_t _alrmCnt;
    std::string _testNam;
    std::string _seqName;
    std::string _testLbl;

    uint8_t _optFlag;
    float _testTim;
    float _testMin;
    float _testMax;
    float _tstSums;
    float _tstSqrs;

    enum OptionalFlags
    {
        INVALID_TEST_MIN = (1 << 0),
        INVALID_TEST_MAX = (1 << 1),
        INVALID_TEST_TIM = (1 << 2),
        // RESERVED         = (1 << 3),
        INVALID_TST_SUMS = (1 << 4),
        INVALID_TST_SQRS = (1 << 5),
        // RESERVED         = (1 << 6),
        // RESERVED         = (1 << 7),
    };

    inline explicit Tsr(RecordParser p)
        : _headNum{p.get_uint8("HEAD_NUM")}
        , _siteNum{p.get_uint8("SITE_NUM")}
        , _testTyp{p.get_char("TEST_TYP")}
        , _testNum(p.get_uint32("TEST_NUM"))
        , _execCnt{p.get_uint32("EXEC_CNT")}
        , _failCnt{p.get_uint32("FAIL_CNT")}
        , _alrmCnt{p.get_uint32("ALRM_CNT")}
        , _testNam{p.get_string("TEST_NAM")}
        , _seqName{p.get_string("SEQ_NAME")}
        , _testLbl{p.get_string("TEST_LBL")}
        , _optFlag{p.get_uint8_cond("OPT_FLAG", p.get_bytes_left() > 0, UINT8_MAX)}
        , _testTim{p.get_float_cond("TEST_TIM", (_optFlag & INVALID_TEST_TIM) == 0, 0)}
        , _testMin{p.get_float_cond("TEST_MIN", (_optFlag & INVALID_TEST_MIN) == 0, 0)}
        , _testMax{p.get_float_cond("TEST_MAX", (_optFlag & INVALID_TEST_MAX) == 0, 0)}
        , _tstSums{p.get_float_cond("TST_SUMS", (_optFlag & INVALID_TST_SUMS) == 0, 0)}
        , _tstSqrs{p.get_float_cond("TST_SQRS", (_optFlag & INVALID_TST_SQRS) == 0, 0)}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Tsr() = delete;

    inline explicit Tsr(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Tsr{RecordParser{settings, b, len}}
    {
    }

    constexpr uint8_t get_head_num() const noexcept
    {
        return _headNum;
    }

    constexpr uint8_t get_site_num() const noexcept
    {
        return _siteNum;
    }

    constexpr char get_test_typ() const noexcept
    {
        return _testTyp;
    }

    constexpr uint32_t get_test_num() const noexcept
    {
        return _testNum;
    }

    constexpr uint32_t get_exec_cnt() const noexcept
    {
        return _execCnt;
    }

    constexpr uint32_t get_fail_cnt() const noexcept
    {
        return _failCnt;
    }

    constexpr uint32_t get_alrm_cnt() const noexcept
    {
        return _alrmCnt;
    }

    constexpr const std::string& get_test_nam() const noexcept
    {
        return _testNam;
    }

    constexpr const std::string& get_seq_name() const noexcept
    {
        return _seqName;
    }

    constexpr const std::string& get_test_lbl() const noexcept
    {
        return _testLbl;
    }

    constexpr uint8_t get_opt_flag() const noexcept
    {
        return _optFlag;
    }

    constexpr float get_test_tim() const noexcept
    {
        return _testTim;
    }

    constexpr float get_test_min() const noexcept
    {
        return _testMin;
    }

    constexpr float get_test_max() const noexcept
    {
        return _testMax;
    }

    constexpr float get_tst_sums() const noexcept
    {
        return _tstSums;
    }

    constexpr float _get_tst_sqrs() const noexcept
    {
        return _tstSqrs;
    }
};
#pragma endregion TSR




#pragma region PTR
class Ptr
{
    uint32_t _testNum;
    uint8_t _headNum;
    uint8_t _siteNum;
    uint8_t _testFlg;
    uint8_t _parmFlg;
    float _result;
    std::string _testTxt;
    std::string _alarmId;

    uint8_t _optFlag;
    int8_t _resScal;
    int8_t _llmScal;
    int8_t _hlmScal;
    float _loLimit;
    float _hiLimit;
    std::string _units;
    std::string _cResfmt;
    std::string _cLlmfmt;
    std::string _cHlmfmt;
    float _loSpec;
    float _hiSpec;

    enum TestFlags
    {
        ALARM_DURING_TEST = (1 << 0),
        RESULT_INVALID    = (1 << 1),
        RESULT_UNRELIABLE = (1 << 2),
        TIMEOUT_OCCURRED  = (1 << 3),
        TEST_NOT_EXECUTED = (1 << 4),
        TEST_ABORTED      = (1 << 5),
        NO_PASS_OR_FAIL   = (1 << 6),
        TEST_FAILED       = (1 << 7)
    };

    enum ParametricFlags
    {
        SCALE_ERROR          = (1 << 0),
        DRIFT_ERROR          = (1 << 1),
        OSCILLATION_DETECTED = (1 << 2),
        VALUE_OVER_HI_LIMIT  = (1 << 3),
        VALUE_UNDER_LO_LIMIT = (1 << 4),
        PASSED_ALT_LIMITS    = (1 << 5),
        LO_LIMIT_IS_PASSING  = (1 << 6),
        HI_LIMIT_IS_PASSING  = (1 << 7)
    };

    enum OptionalFlags
    {
        INVALID_RES_SCAL = (1 << 0),
        // RESERVED         = (1 << 1),
        NO_LO_SPEC_LIMIT = (1 << 2),
        NO_HI_SPEC_LIMIT = (1 << 3),
        INVALID_LO_LIMIT = (1 << 4),
        INVALID_HI_LIMIT = (1 << 5),
        NO_LO_LIMIT      = (1 << 6),
        NO_HI_LIMIT      = (1 << 7)
    };

    inline explicit Ptr(RecordParser p, uint32_t testNum, const Ptr* def,
        std::map<uint32_t, Ptr>& defs)
        : _testNum{testNum}
        , _headNum{p.get_uint8("HEAD_NUM")}
        , _siteNum{p.get_uint8("SITE_NUM")}
        , _testFlg{p.get_uint8("TEST_FLG")}
        , _parmFlg{p.get_uint8("PARM_FLG")}
        , _result{p.get_float("RESULT")}
        , _testTxt{p.get_string("TEST_TXT")}
        , _alarmId{p.get_string("ALARM_ID")}
        , _optFlag{p.get_uint8_cond(
            "OPT_FLAG", def == nullptr || p.get_bytes_left() > 0, UINT8_MAX)}
        , _resScal{p.get_int8_cond(
            "RES_SCAL", def == nullptr || (_optFlag & INVALID_RES_SCAL) == 0, 0)}
        , _llmScal{p.get_int8_cond(
            "LLM_SCAL", def == nullptr || (_optFlag & (INVALID_LO_LIMIT | NO_LO_LIMIT)) == 0, 0)}
        , _hlmScal{p.get_int8_cond(
            "HLM_SCAL", def == nullptr || (_optFlag & (INVALID_HI_LIMIT | NO_HI_LIMIT)) == 0, 0)}
        , _loLimit{p.get_float_cond(
            "LO_LIMIT", def == nullptr || (_optFlag & (INVALID_LO_LIMIT | NO_LO_LIMIT)) == 0, 0)}
        , _hiLimit{p.get_float_cond(
            "HI_LIMIT", def == nullptr || (_optFlag & (INVALID_HI_LIMIT | NO_HI_LIMIT)) == 0, 0)}
        , _units{p.get_string_cond(
            "UNITS", def == nullptr || p.get_bytes_left() > 0, {})}
        , _cResfmt{p.get_string_cond(
            "C_RESFMT", def == nullptr || p.get_bytes_left() > 0, {})}
        , _cLlmfmt{p.get_string_cond(
            "C_LLMFMT", def == nullptr || p.get_bytes_left() > 0, {})}
        , _cHlmfmt{p.get_string_cond(
            "C_HLMFMT", def == nullptr || p.get_bytes_left() > 0, {})}
        , _loSpec{p.get_float_cond(
            "LO_SPEC", def == nullptr || (_optFlag & NO_LO_SPEC_LIMIT) == 0, 0)}
        , _hiSpec{p.get_float_cond(
            "HI_SPEC", def == nullptr || (_optFlag & NO_HI_SPEC_LIMIT) == 0, 0)}
    {
        p.throw_if_leftover_bytes();
        if (def == nullptr)
            defs[testNum] = *this;
    }

    inline static const Ptr* get_def_or_nullptr(uint32_t testNum,
        const std::map<uint32_t, Ptr>& defs)
    {
        auto found = defs.find(testNum);
        if (found == defs.end())
            return nullptr;
        return &found->second;
    }

    inline explicit Ptr(uint32_t testNum, std::map<uint32_t, Ptr>& defs,
        RecordParser p)
        : Ptr{std::move(p), testNum, get_def_or_nullptr(testNum, defs), defs}
    {
    }

    inline explicit Ptr(RecordParser p, std::map<uint32_t, Ptr>& defs)
        : Ptr{p.get_uint32("TEST_NUM"), defs, std::move(p)}
    {
    }

public:
    inline Ptr() = delete;

    inline explicit Ptr(const RecordParsingSettings& settings,
        const std::byte* b, uint16_t len, std::map<uint32_t, Ptr>& defs)
        : Ptr{RecordParser{settings, b, len}, defs}
    {
    }
    
    constexpr uint32_t get_test_num() const noexcept
    {
        return _testNum;
    }

    constexpr uint8_t get_head_num() const noexcept
    {
        return _headNum;
    }

    constexpr uint8_t get_site_num() const noexcept
    {
        return _siteNum;
    }
    
    constexpr uint8_t get_test_flg() const noexcept
    {
        return _testFlg;
    }

    constexpr uint8_t get_parm_flg() const noexcept
    {
        return _parmFlg;
    }

    constexpr float get_result() const noexcept
    {
        return _result;
    }

    constexpr const std::string& get_test_txt() const noexcept
    {
        return _testTxt;
    }

    constexpr const std::string& get_alarm_id() const noexcept
    {
        return _alarmId;
    }

    constexpr uint8_t get_opt_flag() const noexcept
    {
        return _optFlag;
    }

    constexpr int8_t get_res_scal() const noexcept
    {
        return _resScal;
    }

    constexpr int8_t get_llm_scal() const noexcept
    {
        return _llmScal;
    }

    constexpr int8_t get_hlm_scal() const noexcept
    {
        return _hlmScal;
    }

    constexpr float get_lo_limit() const noexcept
    {
        return _loLimit;
    }

    constexpr float get_hi_limit() const noexcept
    {
        return _hiLimit;
    }

    constexpr const std::string& get_units() const noexcept
    {
        return _units;
    }

    constexpr const std::string& get_c_resfmt() const noexcept
    {
        return _cResfmt;
    }

    constexpr const std::string& get_c_llmfmt() const noexcept
    {
        return _cLlmfmt;
    }

    constexpr const std::string& get_c_hlmfmt() const noexcept
    {
        return _cHlmfmt;
    }

    constexpr float get_lo_spec() const noexcept
    {
        return _loSpec;
    }

    constexpr float get_hi_spec() const noexcept
    {
        return _hiSpec;
    }
};
#pragma endregion PTR




#pragma region MPR
class Mpr
{
    uint32_t _testNum;
    uint8_t _headNum;
    uint8_t _siteNum;
    uint8_t _testFlg;
    uint8_t _parmFlg;
    uint16_t _rtnIcnt;
    uint16_t _rsltCnt;
    NibbleVector _rtnStat;
    std::vector<float> _rtnRslt;
    std::string _testTxt;
    std::string _alarmId;

    uint8_t _optFlag;
    int8_t _resScal;
    int8_t _llmScal;
    int8_t _hlmScal;
    float _loLimit;
    float _hiLimit;
    float _startIn;
    float _incrIn;
    std::vector<uint16_t> _rtnIndx;
    std::string _units;
    std::string _unitsIn;
    std::string _cResfmt;
    std::string _cLlmfmt;
    std::string _cHlmfmt;
    float _loSpec;
    float _hiSpec;

    enum OptionalFlags : uint8_t
    {
        INVALID_RES_SCAL = (1 << 0),
        INVALID_START_IN = (1 << 1),
        NO_LO_SPEC_LIMIT = (1 << 2),
        NO_HI_SPEC_LIMIT = (1 << 3),
        INVALID_LO_LIMIT = (1 << 4),
        INVALID_HI_LIMIT = (1 << 5),
        NO_LO_LIMIT      = (1 << 6),
        NO_HI_LIMIT      = (1 << 7)
    };

    inline explicit Mpr(RecordParser p)
        : _testNum{p.get_uint32("TEST_NUM")}
        , _headNum{p.get_uint8("HEAD_NUM")}
        , _siteNum{p.get_uint8("SITE_NUM")}
        , _testFlg{p.get_uint8("TEST_FLG")}
        , _parmFlg{p.get_uint8("PARM_FLG")}
        , _rtnIcnt{p.get_uint16("RTN_ICNT")}
        , _rsltCnt{p.get_uint16("RSLT_CNT")}
        , _rtnStat{p.get_nibble_vector("RTN_STAT", _rtnIcnt)}
        , _rtnRslt{p.get_float_vector("RTN_RSLT", _rsltCnt)}
        , _testTxt{p.get_string("TEST_TXT")}
        , _alarmId{p.get_string("ALARM_ID")}
        , _optFlag{p.get_uint8_cond("OPT_FLAG", p.get_bytes_left() > 0, UINT8_MAX)}
        , _resScal{p.get_int8_cond("RES_SCAL", (_optFlag & INVALID_RES_SCAL) == 0, 0)}
        , _llmScal{p.get_int8_cond(
            "LLM_SCAL", (_optFlag & (INVALID_LO_LIMIT | NO_LO_LIMIT)) == 0, 0)}
        , _hlmScal{p.get_int8_cond(
            "HLM_SCAL", (_optFlag & (INVALID_HI_LIMIT | NO_HI_LIMIT)) == 0, 0)}
        , _loLimit{p.get_float_cond(
            "LO_LIMIT", (_optFlag & (INVALID_LO_LIMIT | NO_LO_LIMIT)) == 0, 0)}
        , _hiLimit{p.get_float_cond(
            "HI_LIMIT", (_optFlag & (INVALID_HI_LIMIT | NO_HI_LIMIT)) == 0, 0)}
        , _startIn{p.get_float_cond("START_IN", (_optFlag & INVALID_START_IN) == 0, 0)}
        , _incrIn{p.get_float_cond("INCR_IN", (_optFlag & INVALID_START_IN) == 0, 0)}
        , _rtnIndx{p.get_uint16_vector_cond("RTN_INDX", _rtnIcnt, p.get_bytes_left() > 0, {})}
        , _units{p.get_string_cond("UNITS", p.get_bytes_left() > 0, {})}
        , _unitsIn{p.get_string_cond("UNITS_IN", p.get_bytes_left() > 0, {})}
        , _cResfmt{p.get_string_cond("C_RESFMT", p.get_bytes_left() > 0, {})}
        , _cLlmfmt{p.get_string_cond("C_LLMFMT", p.get_bytes_left() > 0, {})}
        , _cHlmfmt{p.get_string_cond("C_HLMFMT", p.get_bytes_left() > 0, {})}
        , _loSpec{p.get_float_cond("LO_SPEC", (_optFlag & NO_LO_SPEC_LIMIT) == 0, 0)}
        , _hiSpec{p.get_float_cond("HI_SPEC", (_optFlag & NO_HI_SPEC_LIMIT) == 0, 0)}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Mpr() = delete;

    inline explicit Mpr(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Mpr{RecordParser{settings, b, len}}
    {
    }

    constexpr uint32_t get_test_num() const noexcept
    {
        return _testNum;
    }

    constexpr uint8_t get_head_num() const noexcept
    {
        return _headNum;
    }

    constexpr uint8_t get_site_num() const noexcept
    {
        return _siteNum;
    }

    constexpr uint8_t get_test_flg() const noexcept
    {
        return _testFlg;
    }

    constexpr uint8_t get_parm_flg() const noexcept
    {
        return _parmFlg;
    }

    constexpr uint16_t get_rtn_icnt() const noexcept
    {
        return _rtnIcnt;
    }

    constexpr uint16_t get_rslt_cnt() const noexcept
    {
        return _rsltCnt;
    }

    constexpr const NibbleVector& get_rtn_stat() const noexcept
    {
        return _rtnStat;
    }

    constexpr const std::vector<float>& get_rtn_rslt() const noexcept
    {
        return _rtnRslt;
    }

    constexpr const std::string& get_test_txt() const noexcept
    {
        return _testTxt;
    }

    constexpr const std::string& get_alarm_id() const noexcept
    {
        return _alarmId;
    }

    constexpr uint8_t get_opt_flag() const noexcept
    {
        return _optFlag;
    }

    constexpr int8_t get_res_scal() const noexcept
    {
        return _resScal;
    }

    constexpr int8_t get_llm_scal() const noexcept
    {
        return _llmScal;
    }

    constexpr int8_t get_hlm_scal() const noexcept
    {
        return _hlmScal;
    }

    constexpr float get_lo_limit() const noexcept
    {
        return _loLimit;
    }

    constexpr float get_hi_limit() const noexcept
    {
        return _hiLimit;
    }

    constexpr float get_start_in() const noexcept
    {
        return _startIn;
    }

    constexpr float get_incr_in() const noexcept
    {
        return _incrIn;
    }

    constexpr const std::vector<uint16_t>& get_rtn_indx() const noexcept
    {
        return _rtnIndx;
    }

    constexpr const std::string& get_units() const noexcept
    {
        return _units;
    }

    constexpr const std::string& get_units_in() const noexcept
    {
        return _unitsIn;
    }

    constexpr const std::string& get_c_resfmt() const noexcept
    {
        return _cResfmt;
    }

    constexpr const std::string& get_c_llmfmt() const noexcept
    {
        return _cLlmfmt;
    }

    constexpr const std::string& get_c_hlmfmt() const noexcept
    {
        return _cHlmfmt;
    }

    constexpr float get_lo_spec() const noexcept
    {
        return _loSpec;
    }

    constexpr float get_hi_spec() const noexcept
    {
        return _hiSpec;
    }
};
#pragma endregion MPR




#pragma region FTR
class Ftr
{
    uint32_t _testNum;
    uint8_t _headNum;
    uint8_t _siteNum;
    uint8_t _testFlg;

    enum OptionalFlags : uint8_t
    {
        INVALID_CYCL_CNT = (1 << 0),
        INVALID_REL_VADR = (1 << 1),
        INVALID_REPT_CNT = (1 << 2),
        INVALID_NUM_FAIL = (1 << 3),
        INVALID_FAIL_ADR = (1 << 4),
        INVALID_VECT_OFF = (1 << 5)
    };

    uint8_t _optFlag;
    uint32_t _cyclCnt;
    uint32_t _relVadr;
    uint32_t _reptCnt;
    uint32_t _numFail;
    int32_t _xfailAd;
    int32_t _yfailAd;
    int16_t _vectOff;
    uint16_t _rtnIcnt;
    uint16_t _pgmIcnt;
    std::vector<uint16_t> _rtnIndx;
    NibbleVector _rtnStat;
    std::vector<uint16_t> _pgmIndx;
    NibbleVector _pgmStat;
    std::vector<bool> _failPin;
    std::string _vectNam;
    std::string _timeSet;
    std::string _opCode;
    std::string _testTxt;
    std::string _alarmId;
    std::string _progTxt;
    std::string _rsltTxt;

    uint8_t _patgNum;
    std::vector<bool> _spinMap;

    inline explicit Ftr(RecordParser p)
        : _testNum{p.get_uint32("TEST_NUM")}
        , _headNum{p.get_uint8("HEAD_NUM")}
        , _siteNum{p.get_uint8("SITE_NUM")}
        , _testFlg{p.get_uint8("TEST_FLG")}
        , _optFlag{p.get_uint8_cond("OPT_FLAG", p.get_bytes_left() > 0, UINT8_MAX)}
        , _cyclCnt{p.get_uint32_cond("CYCL_CNT", (_optFlag & INVALID_CYCL_CNT) == 0, 0)}
        , _relVadr{p.get_uint32_cond("REL_VADR", (_optFlag & INVALID_REL_VADR) == 0, 0)}
        , _reptCnt{p.get_uint32_cond("REPT_CNT", (_optFlag & INVALID_REPT_CNT) == 0, 0)}
        , _numFail{p.get_uint32_cond("NUM_FAIL", (_optFlag & INVALID_NUM_FAIL) == 0, 0)}
        , _xfailAd{p.get_int32_cond("XFAIL_AD", (_optFlag & INVALID_FAIL_ADR) == 0, 0)}
        , _yfailAd{p.get_int32_cond("YFAIL_AD", (_optFlag & INVALID_FAIL_ADR) == 0, 0)}
        , _vectOff{p.get_int16_cond("VECT_OFF", (_optFlag & INVALID_VECT_OFF) == 0, 0)}
        , _rtnIcnt{p.get_uint16_cond("RTN_ICNT", p.get_bytes_left() > 0, 0)}
        , _pgmIcnt{p.get_uint16_cond("PGM_ICNT", p.get_bytes_left() > 0, 0)}
        , _rtnIndx{p.get_uint16_vector_cond("RTN_INDX", _rtnIcnt, p.get_bytes_left() > 0, {})}
        , _rtnStat{p.get_nibble_vector_cond("RTN_STAT", _rtnIcnt, p.get_bytes_left() > 0, {})}
        , _pgmIndx{p.get_uint16_vector_cond("PGM_INDX", _pgmIcnt, p.get_bytes_left() > 0, {})}
        , _pgmStat{p.get_nibble_vector_cond("PGM_STAT", _pgmIcnt, p.get_bytes_left() > 0, {})}
        , _failPin{p.get_bit_vector_cond("FAIL_PIN", p.get_bytes_left() > 0, {})}
        , _vectNam{p.get_string_cond("VECT_NAM", p.get_bytes_left() > 0, {})}
        , _timeSet{p.get_string_cond("TIME_SET", p.get_bytes_left() > 0, {})}
        , _opCode{p.get_string_cond("OP_CODE", p.get_bytes_left() > 0, {})}
        , _testTxt{p.get_string_cond("TEST_TXT", p.get_bytes_left() > 0, {})}
        , _alarmId{p.get_string_cond("ALARM_ID", p.get_bytes_left() > 0, {})}
        , _progTxt{p.get_string_cond("PROG_TXT", p.get_bytes_left() > 0, {})}
        , _rsltTxt{p.get_string_cond("RSLT_TXT", p.get_bytes_left() > 0, {})}
        , _patgNum{p.get_uint8_cond("PATG_NUM", p.get_bytes_left() > 0, 0)}
        , _spinMap{p.get_bit_vector_cond("SPIN_MAP", p.get_bytes_left() > 0, {})}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Ftr() = delete;

    inline explicit Ftr(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Ftr{RecordParser{settings, b, len}}
    {}

    constexpr uint32_t get_test_num() const noexcept
    {
        return _testNum;
    }

    constexpr uint8_t get_head_num() const noexcept
    {
        return _headNum;
    }

    constexpr uint8_t get_site_num() const noexcept
    {
        return _siteNum;
    }

    constexpr uint8_t get_test_flg() const noexcept
    {
        return _testFlg;
    }

    constexpr uint8_t get_opt_flag() const noexcept
    {
        return _optFlag;
    }

    constexpr uint32_t get_cycl_cnt() const noexcept
    {
        return _cyclCnt;
    }

    constexpr uint32_t get_rel_vadr() const noexcept
    {
        return _relVadr;
    }

    constexpr uint32_t get_rept_cnt() const noexcept
    {
        return _reptCnt;
    }

    constexpr uint32_t get_num_fail() const noexcept
    {
        return _numFail;
    }

    constexpr int32_t get_xfail_ad() const noexcept
    {
        return _xfailAd;
    }

    constexpr int32_t get_yfail_ad() const noexcept
    {
        return _yfailAd;
    }

    constexpr int16_t get_vect_off() const noexcept
    {
        return _vectOff;
    }

    constexpr uint16_t get_rtn_icnt() const noexcept
    {
        return _rtnIcnt;
    }

    constexpr uint16_t get_pgm_icnt() const noexcept
    {
        return _pgmIcnt;
    }

    constexpr const std::vector<uint16_t>& get_rtn_indx() const noexcept
    {
        return _rtnIndx;
    }

    constexpr const NibbleVector& get_rtn_stat() const noexcept
    {
        return _rtnStat;
    }

    constexpr const std::vector<uint16_t>& get_pgm_indx() const noexcept
    {
        return _pgmIndx;
    }

    constexpr const NibbleVector& get_pgm_stat() const noexcept
    {
        return _pgmStat;
    }

    constexpr const std::vector<bool>& get_fail_pin() const noexcept
    {
        return _failPin;
    }

    constexpr const std::string& get_vect_nam() const noexcept
    {
        return _vectNam;
    }

    constexpr const std::string& get_time_set() const noexcept
    {
        return _timeSet;
    }

    constexpr const std::string& get_op_code() const noexcept
    {
        return _opCode;
    }

    constexpr const std::string& get_test_txt() const noexcept
    {
        return _testTxt;
    }

    constexpr const std::string& get_alarm_id() const noexcept
    {
        return _alarmId;
    }

    constexpr const std::string& get_prog_txt() const noexcept
    {
        return _progTxt;
    }

    constexpr const std::string& get_rslt_txt() const noexcept
    {
        return _rsltTxt;
    }

    constexpr uint8_t get_patg_num() const noexcept
    {
        return _patgNum;
    }

    constexpr const std::vector<bool>& get_spin_map() const noexcept
    {
        return _spinMap;
    }
};
#pragma endregion FTR




#pragma region BPS
class Bps
{
    std::string _seqName;

    inline explicit Bps(RecordParser p)
        : _seqName{p.get_string("SEQ_NAME")}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Bps() = delete;

    inline explicit Bps(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Bps{RecordParser{settings, b, len}}
    {
    }

    constexpr const std::string& get_seq_name() const noexcept
    {
        return _seqName;
    }
};
#pragma endregion BPS




#pragma region EPS
struct Eps
{
    inline explicit Eps(RecordParser p)
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Eps() = delete;

    inline explicit Eps(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Eps{RecordParser{settings, b, len}}
    {
    }
};
#pragma endregion EPS




#pragma region GDR
class Gdr
{
    uint16_t _fldCnt;
    GdrData _genData;

    inline explicit Gdr(RecordParser p)
        : _fldCnt(p.get_uint16("FLD_CNT"))
        , _genData(p.get_gdr_data(_fldCnt))
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Gdr() = delete;

    inline explicit Gdr(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Gdr{RecordParser{settings, b, len}}
    {
    }

    constexpr uint16_t get_fld_cnt() const noexcept
    {
        return _fldCnt;
    }

    constexpr const GdrData& get_gen_data() const noexcept
    {
        return _genData;
    }
};
#pragma endregion GDR




#pragma region DTR
class Dtr
{
    std::string _textDat;

    inline explicit Dtr(RecordParser p)
        : _textDat{p.get_string("TEXT_DAT")}
    {
        p.throw_if_leftover_bytes();
    }

public:
    inline Dtr() = delete;

    inline explicit Dtr(const RecordParsingSettings& settings, const std::byte* b, uint16_t len)
        : Dtr{RecordParser{settings, b, len}}
    {
    }

    constexpr const std::string& get_text_dat() const noexcept
    {
        return _textDat;
    }
};
#pragma endregion DTR




#pragma region STDF Reader
class StdfReader
{
    std::istream& _istream;
    std::array<std::byte, USHRT_MAX> _b;  // _istream reading buffer
    std::size_t _totalBytesRead;
    bool _isUnread;
    RecordParsingSettings _settings;
    RecordHeader _header;  // header for record to be read
    std::function<void(const RecordParsingSettings&, const RecordHeader&,
        const std::byte*)> _unknownRecordHandler;
    std::function<void(const Far&)> _farHandler;
    std::function<void(const Atr&)> _atrHandler;
    std::function<void(const Mir&)> _mirHandler;
    std::function<void(const Mrr&)> _mrrHandler;
    std::function<void(const Pcr&)> _pcrHandler;
    std::function<void(const Hbr&)> _hbrHandler;
    std::function<void(const Sbr&)> _sbrHandler;
    std::function<void(const Pmr&)> _pmrHandler;
    std::function<void(const Pgr&)> _pgrHandler;
    std::function<void(const Plr&)> _plrHandler;
    std::function<void(const Rdr&)> _rdrHandler;
    std::function<void(const Sdr&)> _sdrHandler;
    std::function<void(const Wir&)> _wirHandler;
    std::function<void(const Wrr&)> _wrrHandler;
    std::function<void(const Wcr&)> _wcrHandler;
    std::function<void(const Pir&)> _pirHandler;
    std::function<void(const Prr&)> _prrHandler;
    std::function<void(const Tsr&)> _tsrHandler;
    std::function<void(const Ptr&)> _ptrHandler;
    std::function<void(const Mpr&)> _mprHandler;
    std::function<void(const Ftr&)> _ftrHandler;
    std::function<void(const Bps&)> _bpsHandler;
    std::function<void(const Eps&)> _epsHandler;
    std::function<void(const Gdr&)> _gdrHandler;
    std::function<void(const Dtr&)> _dtrHandler;
    std::map<uint32_t, Ptr> _ptrDefaults;

    inline void read_exact(uint16_t bytesNeeded)
    {
        uint16_t bytesRead(0);
        while (bytesRead < bytesNeeded)
        {
            _istream.read(reinterpret_cast<char*>(_b.data()) + bytesRead,
                            bytesNeeded - bytesRead);
            if (_istream.gcount() > 0)
            {
                bytesRead += _istream.gcount();
                _totalBytesRead += _istream.gcount();
            }
            if (bytesRead == bytesNeeded) break;
            if (_istream.eof()) throw EofException(_totalBytesRead);
            if (_istream.bad()) throw BadReadException(_totalBytesRead);
            if (_istream.fail())
            {
                // If failbit is set without eof, clear and continue;
                // some libc++ set fail on short reads
                _istream.clear(_istream.rdstate() & ~std::ios::failbit);
            }
        }
    }
    
    inline bool guess_if_big_endian() const
    {
        uint8_t b0 = std::to_integer<uint8_t>(_b[0]);
        uint8_t b1 = std::to_integer<uint8_t>(_b[1]);

        if (b0 == 2 && b1 == 0)
        {
            return false;
        }
        else if (b0 == 0 && b1 == 2)
        {
            return true;
        }
        else 
        {
            throw FormatException("First two bytes of file should be [2,0] or [0,2] (found: ["
                    + std::to_string(b0) + "," + std::to_string(b1) + "]).");
        }
    }

    inline void make_unknown_record()
    {
        if (_unknownRecordHandler)
            _unknownRecordHandler(_settings, _header, _b.data());
    }

    inline void make_far()
    {
        Far far{_settings, _b.data(), _header.get_rec_len()};
        uint8_t cpuType = far.get_cpu_type();
        _settings._bigEndian = cpuType == 1;
        _settings._vaxFloat = cpuType == 0;
        if (_farHandler)
            _farHandler(far);
    }

    inline void make_atr()
    {
        if (_atrHandler)
            _atrHandler(Atr{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_mir()
    {
        if (_mirHandler)
            _mirHandler(Mir{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_mrr()
    {
        if (_mrrHandler)
            _mrrHandler(Mrr{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_pcr()
    {
        if (_pcrHandler)
            _pcrHandler(Pcr{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_hbr()
    {
        if (_hbrHandler)
            _hbrHandler(Hbr{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_sbr()
    {
        if (_sbrHandler)
            _sbrHandler(Sbr{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_pmr()
    {
        if (_pmrHandler)
            _pmrHandler(Pmr{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_pgr()
    {
        if (_pgrHandler)
            _pgrHandler(Pgr{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_plr()
    {
        if (_plrHandler)
            _plrHandler(Plr{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_rdr()
    {
        if (_rdrHandler)
            _rdrHandler(Rdr{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_sdr()
    {
        if (_sdrHandler)
            _sdrHandler(Sdr{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_wir()
    {
        if (_wirHandler)
            _wirHandler(Wir{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_wrr()
    {
        if (_wrrHandler)
            _wrrHandler(Wrr{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_wcr()
    {
        if (_wcrHandler)
            _wcrHandler(Wcr{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_pir()
    {
        if (_pirHandler)
            _pirHandler(Pir{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_prr()
    {
        if (_prrHandler)
            _prrHandler(Prr{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_tsr()
    {
        if (_tsrHandler)
            _tsrHandler(Tsr{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_ptr()
    {
        if (_ptrHandler)
            _ptrHandler(Ptr{_settings, _b.data(), _header.get_rec_len(), _ptrDefaults});
    }

    inline void make_mpr()
    {
        if (_mprHandler)
            _mprHandler(Mpr{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_ftr()
    {
        if (_ftrHandler)
            _ftrHandler(Ftr{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_bps()
    {
        if (_bpsHandler)
            _bpsHandler(Bps{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_eps()
    {
        if (_epsHandler)
            _epsHandler(Eps{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_gdr()
    {
        if (_gdrHandler)
            _gdrHandler(Gdr{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void make_dtr()
    {
        if (_dtrHandler)
            _dtrHandler(Dtr{_settings, _b.data(), _header.get_rec_len()});
    }

    inline void read_header()
    {
        read_exact(4);
        if (_isUnread)
        {
            _isUnread = false;
            _settings._bigEndian = guess_if_big_endian();
        }
        _header = RecordHeader(_settings, _b.data(), 4);
    }

    inline void read_record()
    {
        read_exact(_header.get_rec_len());
        if (_header.get_rec_typ() == 0)
        {
            if      (_header.get_rec_sub() == 10) return make_far();
            else if (_header.get_rec_sub() == 20) return make_atr();
        }
        else if (_header.get_rec_typ() == 1)
        {
            if      (_header.get_rec_sub() == 10) return make_mir();
            else if (_header.get_rec_sub() == 20) return make_mrr();
            else if (_header.get_rec_sub() == 30) return make_pcr();
            else if (_header.get_rec_sub() == 40) return make_hbr();
            else if (_header.get_rec_sub() == 50) return make_sbr();
            else if (_header.get_rec_sub() == 60) return make_pmr();
            else if (_header.get_rec_sub() == 62) return make_pgr();
            else if (_header.get_rec_sub() == 63) return make_plr();
            else if (_header.get_rec_sub() == 70) return make_rdr();
            else if (_header.get_rec_sub() == 80) return make_sdr();
        }
        else if (_header.get_rec_typ() == 2)
        {
            if      (_header.get_rec_sub() == 10) return make_wir();
            else if (_header.get_rec_sub() == 20) return make_wrr();
            else if (_header.get_rec_sub() == 30) return make_wcr();
        }
        else if (_header.get_rec_typ() == 5)
        {
            if      (_header.get_rec_sub() == 10) return make_pir();
            else if (_header.get_rec_sub() == 20) return make_prr();
        }
        else if (_header.get_rec_typ() == 10)
        {
            if      (_header.get_rec_sub() == 30) return make_tsr();
        }
        else if (_header.get_rec_typ() == 15)
        {
            if      (_header.get_rec_sub() == 10) return make_ptr();
            else if (_header.get_rec_sub() == 15) return make_mpr();
            else if (_header.get_rec_sub() == 20) return make_ftr();
        }
        else if (_header.get_rec_typ() == 20)
        {
            if      (_header.get_rec_sub() == 10) return make_bps();
            else if (_header.get_rec_sub() == 20) return make_eps();
        }
        else if (_header.get_rec_typ() == 50)
        {
            if      (_header.get_rec_sub() == 10) return make_gdr();
            else if (_header.get_rec_sub() == 30) return make_dtr();
        }
        make_unknown_record();
    }

public:
    inline StdfReader() = delete;

    inline explicit StdfReader(std::istream& istream)
        : _istream{istream}
        , _b{}
        , _totalBytesRead{0}
        , _isUnread{true}
        , _settings{}
        , _header{}
        , _unknownRecordHandler{}
        , _farHandler{}
        , _atrHandler{}
        , _mirHandler{}
        , _mrrHandler{}
        , _pcrHandler{}
        , _hbrHandler{}
        , _sbrHandler{}
        , _pmrHandler{}
        , _pgrHandler{}
        , _plrHandler{}
        , _rdrHandler{}
        , _sdrHandler{}
        , _wirHandler{}
        , _wrrHandler{}
        , _wcrHandler{}
        , _pirHandler{}
        , _prrHandler{}
        , _tsrHandler{}
        , _ptrHandler{}
        , _mprHandler{}
        , _ftrHandler{}
        , _bpsHandler{}
        , _epsHandler{}
        , _gdrHandler{}
        , _dtrHandler{}
        , _ptrDefaults{}
    {
    }

    inline void set_unknown_record_handler(const std::function<void(const RecordParsingSettings&,
        const RecordHeader&, const std::byte*)>& unknownRecordHandler)
    {
        _unknownRecordHandler = unknownRecordHandler;
    }

    inline void set_far_handler(const std::function<void(const Far&)>& farHandler)
    {
        _farHandler = farHandler;
    }

    inline void set_atr_handler(const std::function<void(const Atr&)>& atrHandler)
    {
        _atrHandler = atrHandler;
    }

    inline void set_mir_handler(const std::function<void(const Mir&)>& mirHandler)
    {
        _mirHandler = mirHandler;
    }

    inline void set_mrr_handler(const std::function<void(const Mrr&)>& mrrHandler)
    {
        _mrrHandler = mrrHandler;
    }

    inline void set_pcr_handler(const std::function<void(const Pcr&)>& pcrHandler)
    {
        _pcrHandler = pcrHandler;
    }

    inline void set_hbr_handler(const std::function<void(const Hbr&)>& hbrHandler)
    {
        _hbrHandler = hbrHandler;
    }

    inline void set_sbr_handler(const std::function<void(const Sbr&)>& sbrHandler)
    {
        _sbrHandler = sbrHandler;
    }

    inline void set_pmr_handler(const std::function<void(const Pmr&)>& pmrHandler)
    {
        _pmrHandler = pmrHandler;
    }

    inline void set_pgr_handler(const std::function<void(const Pgr&)>& pgrHandler)
    {
        _pgrHandler = pgrHandler;
    }

    inline void set_plr_handler(const std::function<void(const Plr&)>& plrHandler)
    {
        _plrHandler = plrHandler;
    }

    inline void set_rdr_handler(const std::function<void(const Rdr&)>& rdrHandler)
    {
        _rdrHandler = rdrHandler;
    }

    inline void set_sdr_handler(const std::function<void(const Sdr&)>& sdrHandler)
    {
        _sdrHandler = sdrHandler;
    }

    inline void set_wir_handler(const std::function<void(const Wir&)>& wirHandler)
    {
        _wirHandler = wirHandler;
    }

    inline void set_wrr_handler(const std::function<void(const Wrr&)>& wrrHandler)
    {
        _wrrHandler = wrrHandler;
    }

    inline void set_wcr_handler(const std::function<void(const Wcr&)>& wcrHandler)
    {
        _wcrHandler = wcrHandler;
    }

    inline void set_pir_handler(const std::function<void(const Pir&)>& pirHandler)
    {
        _pirHandler = pirHandler;
    }

    inline void set_prr_handler(const std::function<void(const Prr&)>& prrHandler)
    {
        _prrHandler = prrHandler;
    }

    inline void set_tsr_handler(const std::function<void(const Tsr&)>& tsrHandler)
    {
        _tsrHandler = tsrHandler;
    }

    inline void set_ptr_handler(const std::function<void(const Ptr&)>& ptrHandler)
    {
        _ptrHandler = ptrHandler;
    }

    inline void set_mpr_handler(const std::function<void(const Mpr&)>& mprHandler)
    {
        _mprHandler = mprHandler;
    }

    inline void set_ftr_handler(const std::function<void(const Ftr&)>& ftrHandler)
    {
        _ftrHandler = ftrHandler;
    }

    inline void set_bps_handler(const std::function<void(const Bps&)>& bpsHandler)
    {
        _bpsHandler = bpsHandler;
    }

    inline void set_eps_handler(const std::function<void(const Eps&)>& epsHandler)
    {
        _epsHandler = epsHandler;
    }

    inline void set_gdr_handler(const std::function<void(const Gdr&)>& gdrHandler)
    {
        _gdrHandler = gdrHandler;
    }

    inline void set_dtr_handler(const std::function<void(const Dtr&)>& dtrHandler)
    {
        _dtrHandler = dtrHandler;
    }

    inline RecordParsingSettings& get_parsing_settings() noexcept
    {
        return _settings;
    }

    inline const RecordParsingSettings& get_parsing_settings() const noexcept
    {
        return _settings;
    }

    inline bool read()
    {
        if (!_istream) return false;
        std::size_t currentPosition = _totalBytesRead;

        try
        {
            read_header();
        }
        catch (const EofException& e)
        {
            if (currentPosition == _totalBytesRead) return false;
            else throw;                    
        }

        try
        {
            read_record();
        }
        catch (const Exception& e)
        {
            throw Exception("In record at position " + std::to_string(currentPosition) + ": " +
                e.what());
        }
        return true;
    }
};
#pragma endregion STDF Reader




}

#endif
