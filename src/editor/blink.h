// based header from blink with following license
/**
 * Copyright (C) 2016 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */
// changed for (insanely) better compile time

#pragma once

#include "core/os.h"
#include <string>
#include <unordered_map>
#include <Windows.h>
#undef min

namespace blink {

using u8 = Lumix::u8;
using u32 = Lumix::u32;

struct guid {
	u32 data1;
	u32 data2;
	u32 data3;
	u32 data4;

	bool operator==(const guid &other) { return data1 == other.data1 && data2 == other.data2 && data3 == other.data3 && data4 == other.data4; }
	bool operator!=(const guid &other) { return !operator==(other); }
};

union COFF_HEADER {
	constexpr static const u8 bigobj_classid[16] = {
		0xc7, 0xa1, 0xba, 0xd1, 0xee, 0xba, 0xa9, 0x4b,
		0xaf, 0x20, 0xfa, 0xf6, 0x6a, 0xa4, 0xdc, 0xb8,
	};

	//This is actually a 16byte UUID
	static_assert(sizeof(bigobj_classid) == sizeof(CLSID));

	bool is_extended() const {
		return bigobj.Sig1 == 0x0000 && bigobj.Sig2 == 0xFFFF && memcmp(&bigobj.ClassID, bigobj_classid, sizeof(CLSID)) == 0 ;
	}

	IMAGE_FILE_HEADER obj;
	ANON_OBJECT_HEADER_BIGOBJ bigobj;
};

bool open_coff_file(const char* path, COFF_HEADER &header, Lumix::os::InputFile& file);
bool read_symbol_table(const char* path, const guid& guid, u8 *image_base, std::unordered_map<std::string, void *> &symbols);


} // namespace blink
