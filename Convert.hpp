#pragma once

#ifndef CONVERT_HPP
#define CONVERT_HPP

#include "Common.h"


namespace msgpack {
	template <typename UnpackT> UnpackT unpackt(const char* data, const size_t size) {
		const msgpack::object_handle oh = msgpack::unpack(data, size);
		const msgpack::object deserialized = oh.get();
		UnpackT unpacked;
		deserialized.convert(unpacked);
		return unpacked;
	}

	template <typename UnpackT> UnpackT unpackt(const string& data) {
		return unpackt<UnpackT>(data.data(), data.size());
	}

	template <typename UnpackT> UnpackT unpackt(const byte_array& data) {
		return unpackt<UnpackT>(reinterpret_cast<const char*>(data.data()), data.size());
	}
}


#endif