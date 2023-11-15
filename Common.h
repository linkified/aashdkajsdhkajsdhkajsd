#pragma once

#ifndef COMMON_H
#define COMMON_H

#define _WIN32_WINNT _WIN32_WINNT_VISTA

#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <array>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <memory>
#include <optional>
#include <filesystem>
#include <sodium.h>
//#include <nlohmann\\json.hpp>
#include <boost/asio.hpp>
#include <Windows.h>
#include <msgpack.hpp>

#define SODIUM_SUCCESS 0

/*
namespace nlohmann {

	template <class T> void to_json(nlohmann::json& j, const std::optional<T>& v) {
		if (v.has_value())
			j = *v;
		else
			j = nullptr;
	}

	template <class T> void from_json(const nlohmann::json& j, std::optional<T>& v) {
		if (j.is_null())
			v = std::nullopt;
		else
			v = j.get<T>();
	}

} // namespace nlohmann

using json = nlohmann::json;*/

using std::string;
using std::string_view;
using std::wstring;
using std::wstring_view;
using std::vector;
using std::array;
using std::ifstream;
using std::istream;
using std::map;
using std::ostream;
using std::ofstream;
using std::fstream;
using std::optional;
using std::shared_ptr;
using std::unique_ptr;
using std::weak_ptr;
using std::nullopt;
using std::cout;
using std::endl;
using std::cerr;

typedef vector<uint8_t> byte_array;
typedef vector<char> char_array;
typedef map<string, msgpack::type::variant> msgpack_object;

namespace fs = std::filesystem;

typedef fs::path Path;

template <auto fn> using deleter_from_fn = std::integral_constant<decltype(fn), fn>;
template <typename T, auto fn> using win_ptr = std::unique_ptr<typename std::remove_pointer_t<T>, deleter_from_fn<fn>>;
template <typename T> using win_shared_ptr = std::shared_ptr<typename std::remove_pointer_t<T>>;

template<typename HandleType, typename Deleter> win_shared_ptr<HandleType> make_shared_handle(HandleType _handle, Deleter _dx) {
    return win_shared_ptr<HandleType>(_handle, _dx);
}

static constexpr string_view SOCKET_DELIMITER = "\r\n";

#endif