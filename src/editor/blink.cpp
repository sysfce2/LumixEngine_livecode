// based on pdb_reader.cpp,
// coff_reader.cpp,
// and msf_reader.cpp from blink with following license
/**
 * Copyright (C) 2016 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */
// changed for (insanely) better compile time

#include "blink.h"

/**
 * Microsoft program debug database file
 *
 * File is a multi-stream file with various different data streams. Some streams are located at a fixed index:
 *  - Stream 1: PDB headers and list of named streams
 *  - Stream 2: Type info (TPI stream)
 *  - Stream 3: Debug info (DBI stream)
 */

namespace blink {

struct pdb_reader {
	struct content_stream {
		u32 size;
		std::vector<u32> page_indices;
	};

	explicit pdb_reader(const std::string &path);
	~pdb_reader() { _file_stream.close(); }
	
	guid guid() const { return _guid; }
	void read_symbol_table(u8 *image_base, std::unordered_map<std::string, void *> &symbols);
	std::vector<char> stream(size_t index);
	
	std::vector<char> stream(const std::string &name) {
		const auto it = _named_streams.find(name);
		if (it == _named_streams.end())
		return {};
		return stream(it->second);
	}

	std::vector<content_stream> _streams;
	
	u32 _page_size;
	Lumix::os::InputFile _file_stream;

	bool _is_valid = false;
	u32 _version = 0, _timestamp = 0;
	struct guid _guid = {};
	std::unordered_map<std::string, u32> _named_streams;
};

#pragma region PDB Headers
#pragma pack(1)

struct pdb_header
{
	uint32_t version;
	uint32_t time_date_stamp;
	uint32_t age;
	guid guid;
	uint32_t names_map_offset;
};
struct pdb_names_header
{
	uint32_t signature;
	uint32_t version;
	uint32_t names_map_offset;
};
struct pdb_link_info_header
{
	uint32_t cb;
	uint32_t version;
	uint32_t cwd_offset;
	uint32_t command_offset; // Example: link.exe -re -out:foo.exe
	uint32_t out_file_begin_in_command; // Example: 18 (index of 'foo.exe' in command)
	uint32_t libs_offset;
};

struct pdb_dbi_header
{
	uint32_t signature;
	uint32_t version;
	uint32_t age;
	uint16_t global_symbol_info_stream;
	uint16_t toolchain_major : 8;
	uint16_t toolchain_minor : 7;
	uint16_t new_version_format : 1;
	uint16_t public_symbol_info_stream;
	uint16_t pdb_dll_build_major;
	uint16_t symbol_record_stream;
	uint16_t pdb_dll_build_minor;
	uint32_t module_info_size;
	uint32_t section_contribution_size;
	uint32_t section_map_size;
	uint32_t file_info_size;
	uint32_t ts_map_size;
	uint32_t mfc_index;
	uint32_t debug_header_size;
	uint32_t ec_info_size;
	uint16_t incrementally_linked : 1;
	uint16_t private_symbols_stripped : 1;
	uint16_t has_conflicting_types : 1;
	uint16_t padding1 : 13;
	uint16_t machine;
	uint32_t padding2;
};
struct pdb_dbi_module_info
{
	uint32_t is_opened;
	struct {
		uint16_t index;
		uint16_t padding1;
		uint32_t offset;
		uint32_t size;
		uint32_t characteristics;
		uint16_t module_index;
		uint16_t padding2;
		uint32_t data_crc;
		uint32_t relocation_crc;
	} section;
	uint16_t is_dirty : 1;
	uint16_t has_ec_info : 1;
	uint16_t padding1 : 6;
	uint16_t type_server_index : 8;
	uint16_t symbol_stream;
	uint32_t symbol_byte_size;
	uint32_t old_lines_byte_size;
	uint32_t lines_byte_size;
	uint16_t num_source_files;
	uint16_t padding2;
	uint32_t offsets;
	uint32_t source_file_name_index;
	uint32_t pdb_file_name_index;
};
struct pdb_dbi_debug_header
{
	uint16_t fpo; // IMAGE_DEBUG_TYPE_FPO
	uint16_t exception; // IMAGE_DEBUG_TYPE_EXCEPTION
	uint16_t fixup; // IMAGE_DEBUG_TYPE_FIXUP
	uint16_t omap_to_src; // IMAGE_DEBUG_TYPE_OMAP_TO_SRC
	uint16_t omap_from_src; // IMAGE_DEBUG_TYPE_OMAP_FROM_SRC
	uint16_t section_header; // A dump of all section headers from the executable
	uint16_t token_rid_map;
	uint16_t xdata; // A dump of the .xdata section from the executable
	uint16_t pdata;
	uint16_t new_fpo;
	uint16_t section_header_orig;
};
struct pdb_dbi_section_header
{
	char name[8];
	uint32_t size;
	uint32_t virtual_address;
	uint32_t data_size;
	uint32_t raw_data_rva;
	uint32_t relocation_table_rva;
	uint32_t line_numbers_rva;
	uint16_t num_relocations;
	uint16_t num_line_numbers;
	uint32_t flags;
};
#pragma endregion


struct stream_reader {
	stream_reader() = default;
	stream_reader(std::vector<char> &&stream) : _stream(std::move(stream)) {}
	stream_reader(const std::vector<char> &stream) : _stream(stream) {}

	size_t size() const { return _stream.size(); }
	size_t tell() const { return _stream_offset; }

	template <typename T = char>
	T *data(size_t offset = 0) { return reinterpret_cast<T *>(_stream.data() + _stream_offset + offset); }

	void skip(size_t size) { _stream_offset += size; }
	void seek(size_t offset) { _stream_offset = offset; }

	void align(size_t align) {
		if (_stream_offset % align != 0) skip(align - _stream_offset % align);
	}

	size_t read(void *buffer, size_t size) {
		if (_stream_offset >= _stream.size()) return 0;

		size = std::min(_stream.size() - _stream_offset, size);
		std::memcpy(buffer, _stream.data() + _stream_offset, size);
		_stream_offset += size;

		return size;
	}

	template <typename T>
	T &read() {
		_stream_offset += sizeof(T);
		return *reinterpret_cast<T *>(_stream.data() + _stream_offset - sizeof(T));
	}

	std::string_view read_string() {
		std::string_view result(_stream.data() + _stream_offset);
		_stream_offset += result.size() + 1;
		return result;
	}

	size_t _stream_offset = 0;
	std::vector<char> _stream;
};

void pdb_reader::read_symbol_table(uint8_t *image_base, std::unordered_map<std::string, void *> &symbols) {
	stream_reader stream(this->stream(3));

	const pdb_dbi_header &header = stream.read<pdb_dbi_header>();
	if (header.signature != 0xFFFFFFFF) return;

	// Find debug header stream (https://llvm.org/docs/PDB/DbiStream.html#optional-debug-header-stream)
	stream.skip(header.module_info_size + header.section_contribution_size + header.section_map_size + header.file_info_size + header.ts_map_size + header.ec_info_size);
	const pdb_dbi_debug_header &debug_header = stream.read<pdb_dbi_debug_header>();

	stream_reader section_stream(this->stream(debug_header.section_header));

	const size_t num_sections = section_stream.size() / sizeof(pdb_dbi_section_header);
	const pdb_dbi_section_header *sections = section_stream.data<pdb_dbi_section_header>();

	stream = this->stream(header.symbol_record_stream);

	const size_t end = stream.tell() + stream.size();
	
	// A list of records in CodeView format
	while (stream.tell() < end) {
		const auto size = stream.read<uint16_t>();
		const auto code_view_tag = stream.read<uint16_t>();
		const auto next_record_offset = (stream.tell() - sizeof(size)) + size;

		if (code_view_tag == 0x110E) { // S_PUB32
			const struct PUBSYM32 {
				uint32_t flags;
				uint32_t offset;
				uint16_t section;
				const char name[1];
			} &sym = *stream.data<const PUBSYM32>();

			if (sym.section == 0 || sym.section > num_sections) {
				// Relative address
				symbols[sym.name] = reinterpret_cast<void *>(static_cast<uintptr_t>(sym.offset));
			}
			else {
				// Absolute address
				symbols[sym.name] = image_base + sections[sym.section - 1].virtual_address + sym.offset;
			}
		}

		stream.seek(next_record_offset);
		stream.align(4);
	}

}

bool read_symbol_table(const char* path, const guid& guid, u8 *image_base, std::unordered_map<std::string, void *> &symbols) {
	pdb_reader pdb(path);
	if (pdb.guid() != guid) return false;

	pdb.read_symbol_table(image_base, symbols);
	return true;
}

bool open_coff_file(const char* path, COFF_HEADER &header, Lumix::os::InputFile& file) {
	bool opened = file.open(path);
	if (!opened) {
		for (int i = 0; i < 10; i++) {
			Sleep(100);
			opened = file.open(path);
		}
	}

	if (!opened) return false;

	if (!file.read(header)) return false;

	// Need to adjust file position if this is not an extended COFF, since the normal header is smaller
	if (!header.is_extended()) {
		if (!file.seek(sizeof(header.obj))) return false;
	}

	return true;
}

/**
 * Microsoft C/C++ MSF 7.00 (MSF = multi-stream file / compound file)
 *
 * Raw file is subdivided into pages of fixed size.
 * Those pages are grouped into content streams of variable size.
 * The stream assignments to corresponding pages are defined in the root directory (and stream zero).
 */

struct msf_file_header
{
	char signature[32];
	uint32_t page_size;
	uint32_t free_page_map;
	uint32_t page_count;
	uint32_t directory_size;
	uint32_t reserved;
};

static inline uint32_t calc_page_count(uint32_t size, uint32_t page_size)
{
	return (size + page_size - 1u) / page_size;
}

#define READ(v, s) \
	if (!_file_stream.read(reinterpret_cast<void *>(v), (s))) { _is_valid = false; return; }
#define SEEK(...) \
	if (!_file_stream.seek(__VA_ARGS__)) { _is_valid = false; return; }

pdb_reader::pdb_reader(const std::string &path) {
	{
		_is_valid = true;
		if (!_file_stream.open(path.c_str())) return;

		msf_file_header header;
		if (!_file_stream.read(header)) return;

		static constexpr char signature[] = "Microsoft C/C++ MSF 7.00\r\n\032DS\0\0";

		if (std::memcmp(header.signature, signature, sizeof(signature)) != 0) return;

		const auto num_root_pages = calc_page_count(header.directory_size, header.page_size);
		const auto num_root_index_pages = calc_page_count(num_root_pages * 4, header.page_size);
		std::vector<uint32_t> root_pages(num_root_pages);
		std::vector<uint32_t> root_index_pages(num_root_index_pages);

		if (num_root_index_pages == 0)
			return;

		_page_size = header.page_size;


		READ(root_index_pages.data(), num_root_index_pages * 4);

		for (uint32_t i = 0, k = 0, len; i < num_root_index_pages; i++, k += len)
		{
			len = std::min(_page_size / 4, num_root_pages - k);

			SEEK(root_index_pages[i] * _page_size);
			READ(&root_pages[k], len * 4);
		}

		// Read content stream sizes
		uint32_t current_root_page = 0;

		for (uint32_t i = 0, j = 0; i < num_root_pages; i++)
		{
			SEEK(root_pages[i] * _page_size);

			if (i == 0)
			{
				READ(&j, sizeof(j));
				_streams.reserve(j);
			}

			for (uint32_t k = i == 0, size; j > 0 && k < _page_size / 4; k++, j--)
			{
				READ(&size, sizeof(size));
				if (0xFFFFFFFF == size)
					size = 0;
				_streams.push_back({ size });
			}

			if (j == 0)
			{
				current_root_page = i;
				break;
			}
		}

		// Read content stream page indices (located directly after stream sizes)
		for (content_stream &stream : _streams)
		{
			uint32_t num_pages = calc_page_count(stream.size, _page_size);
			if (num_pages == 0)
				continue;

			stream.page_indices.resize(num_pages);

			for (uint32_t num_pages_remaining = num_pages; num_pages_remaining > 0;)
			{
				const auto page_off = static_cast<uint32_t>(_file_stream.pos()) % _page_size;
				const auto page_size = std::min(num_pages_remaining * 4, _page_size - page_off);

				READ(stream.page_indices.data() + num_pages - num_pages_remaining, page_size);

				num_pages_remaining -= page_size / 4;

				// Advance to next root page
				if (page_off + page_size == _page_size)
					SEEK(root_pages[++current_root_page] * _page_size);
			}
		}
	}

	// PDB files should have 4 streams at the beginning that are always at the same index
	_is_valid &= _streams.size() > 4;

	if (!_is_valid) return;

	// Read PDB info stream
	stream_reader pdb_stream(stream(1));
	if (pdb_stream.size() == 0)
		return;

	const pdb_header &header = pdb_stream.read<pdb_header>();
	_version = header.version;
	_timestamp = header.time_date_stamp;
	_guid = header.guid;

	// Read stream names from string hash map
	pdb_stream.skip(header.names_map_offset);

	const auto count = pdb_stream.read<uint32_t>();
	const auto hash_table_size = pdb_stream.read<uint32_t>();
	_named_streams.reserve(count);

	const auto num_bitset_present = pdb_stream.read<uint32_t>();
	std::vector<uint32_t> bitset_present(num_bitset_present);
	pdb_stream.read(bitset_present.data(), num_bitset_present * sizeof(uint32_t));

	const auto num_bitset_deleted = pdb_stream.read<uint32_t>();
	pdb_stream.skip(num_bitset_deleted * sizeof(uint32_t));

	for (uint32_t i = 0; i < hash_table_size; i++)
	{
		if ((bitset_present[i / 32] & (1 << (i % 32))) == 0)
			continue;

		const auto name_offset = pdb_stream.read<uint32_t>();
		const auto stream_index = pdb_stream.read<uint32_t>();

		const auto pos = pdb_stream.tell();
		pdb_stream.seek(sizeof(header) + name_offset); // Seek into the string table that stores the name
		const std::string name(pdb_stream.read_string());
		pdb_stream.seek(pos); // Seek previous position in stream to read next name offset in the next iteration of this loop

		_named_streams.insert({ name, stream_index });
	}
}

std::vector<char> pdb_reader::stream(size_t index) {
	const content_stream &stream = _streams[index];

	size_t offset = 0;
	std::vector<char> stream_data(stream.page_indices.size() * _page_size);

	// Iterate through all pages associated with this stream and read their data
	for (uint32_t page_index : stream.page_indices) {
		if (!_file_stream.seek(page_index * _page_size)) return stream_data;
		if (!_file_stream.read(stream_data.data() + offset, _page_size)) return stream_data;

		offset += _page_size;
	}

	// Shrink result to the actual stream size
	stream_data.resize(stream.size);

	return stream_data;
}

}