#pragma once
#pragma warning(disable : 4996)
#pragma warning(disable : 4018)
#include <Windows.h>
#include <new>
#include <string>
#include <iterator>
#include <vector>
#include <sstream>
#include <intrin.h>

namespace memory
{
	enum dll_sections_t
	{
		SECTION_TEXT,  //.text
		SECTION_RDATA, //.rdata
		SECTION_DATA,  //.data
		SECTION_RSRC,  //.rsrc
		SECTION_RELOC, //.reloc
		SECTION_MAX
	};

	// c_stack
	// stack manager/ helper class	

	// msvc compiletime fix
	#define get_ebp  ( void* ) ( ( uintptr_t ) _AddressOfReturnAddress() - sizeof( uintptr_t ) )
	class c_stack
	{
	private:
		void* base = nullptr;
	public:
		c_stack( void* base )
		{
			this->base = base;
		}

		void previous( unsigned int frames = 1 )
		{
			for ( ; frames < 0; --frames )
			{
				base = *( void** ) base;
			}
		}

		template <typename t>
		t get_local( uintptr_t offset )
		{
			return ( t ) ( ( uintptr_t ) base - offset );
		}

		template <typename t>
		t get_arg( uintptr_t offset )
		{
			( t ) get_retaddr( ) + offset;
		}

		uintptr_t get_retaddr( )
		{
			return ( uintptr_t ) base + sizeof( uintptr_t );
		}
	};

    class c_vmt
    {
        bool m_is_safe_hook{};

        int                       m_vfunc_count{};
        uintptr_t* m_table{};
        uintptr_t* m_original{};
        uintptr_t* m_new{};

        uintptr_t find_safe_space(const char* module_name, size_t needed_size)
        {
            uintptr_t module_address = uintptr_t(GetModuleHandleA(module_name));

            if (!module_address)
                return 0;

            IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module_address;
            IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)(module_address + dos_header->e_lfanew);
            IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(nt_header);

            uintptr_t start = module_address + section_header[SECTION_DATA].VirtualAddress;
            uintptr_t end = start + nt_header->OptionalHeader.SizeOfInitializedData;

            uintptr_t current = start;
            while (current < end)
            {
                MEMORY_BASIC_INFORMATION mbi = { 0 };
                if (!VirtualQuery((void*)current, &mbi, sizeof(mbi)))
                    break;

                // Check if this region is suitable
                if (mbi.State == MEM_COMMIT &&
                    mbi.RegionSize >= needed_size &&
                    (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) &&
                    !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
                {
                    // Additional check for empty space
                    bool is_empty = true;
                    for (uintptr_t ptr = (uintptr_t)mbi.BaseAddress;
                        ptr < (uintptr_t)mbi.BaseAddress + needed_size && is_empty;
                        ptr += sizeof(uintptr_t))
                    {
                        if (*(uintptr_t*)ptr != 0)
                        {
                            is_empty = false;
                        }
                    }

                    if (is_empty)
                    {
                        return (uintptr_t)mbi.BaseAddress;
                    }
                }

                current = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            }

            return 0;
        }

    public:
        int count()
        {
            if (!m_original)
                return 0;

            int vfunc_count = 0;
            while (m_original[vfunc_count] && vfunc_count < 512) // Reasonable limit
            {
                vfunc_count++;
            }

            return vfunc_count;
        }

        c_vmt(void* table, bool safe_hook, const char* module_name = nullptr)
        {
            if (!table)
                return;

            m_is_safe_hook = safe_hook;
            m_table = reinterpret_cast<uintptr_t*>(table);
            m_original = *reinterpret_cast<uintptr_t**>(m_table);
            m_vfunc_count = count();

            if (m_vfunc_count == 0)
                return;

            if (safe_hook && module_name)
            {
                size_t needed_size = (m_vfunc_count + 1) * sizeof(uintptr_t);
                uintptr_t safe_space = find_safe_space(module_name, needed_size);

                if (safe_space)
                {
                    m_new = reinterpret_cast<uintptr_t*>(safe_space);
                }
                else
                {
                    printf("Could not find safe space in module %s\n", module_name);
                    m_is_safe_hook = false;
                }
            }

            if (!m_new)
            {
                m_new = new uintptr_t[m_vfunc_count + 1]();
            }

            // Copy original table (fixed indexing)
            for (int i = 0; i < m_vfunc_count; i++)
            {
                m_new[i + 1] = m_original[i]; // +1 to skip first entry
            }

            // Store original table pointer in first entry
            m_new[0] = reinterpret_cast<uintptr_t>(m_original);

            // Replace vtable pointer
            *m_table = reinterpret_cast<uintptr_t>(&m_new[1]);
        }

        ~c_vmt()
        {
            restore();
        }

        template<typename T = uintptr_t> T get_function(void* new_function, int index)
        {
            if (index < 0 || index >= m_vfunc_count || !m_new)
                return 0;

            m_new[index + 1] = (uintptr_t)new_function;
            return reinterpret_cast<T>(m_original[index]);
        }

        template<typename T = uintptr_t> T get_old_function(int index)
        {
            if (index < 0 || index >= m_vfunc_count || !m_original)
                return 0;

            return reinterpret_cast<T>(m_original[index]);
        }

        void unhook(int index)
        {
            if (index >= 0 && index < m_vfunc_count && m_new)
            {
                m_new[index + 1] = m_original[index];
            }
        }

        void restore()
        {
            if (m_table && m_original)
            {
                *m_table = reinterpret_cast<uintptr_t>(m_original);
            }

            if (m_new)
            {
                if (m_is_safe_hook)
                {
                    m_new = nullptr;
                }
                else
                {
                    delete[] m_new;
                    m_new = nullptr;
                }
            }
        }
    };

	template <typename fn>
	__forceinline fn get_vfunc(void* classbase, int index)
	{
		return (fn) (*(uintptr_t**) classbase)[index];
	}

	namespace pattern
	{
		inline bool bin_match(const uint8_t* code, const std::vector<uint8_t>& pattern)
		{
			for (size_t j = 0; j < pattern.size(); j++)
			{
				if (pattern[j] && code[j] != pattern[j])
					return false;
			}

			return true;
		}

		template <typename t = uintptr_t>
		static t first_match(uintptr_t start, std::string sig, size_t len, std::ptrdiff_t skip = 0)
		{
			// god this is
			std::istringstream iss(sig);
			std::vector<std::string> tokens{std::istream_iterator<std::string>{iss}, std::istream_iterator<std::string>{}};
			std::vector<uint8_t> pattern;

			for (const auto& hex_byte : tokens)
				pattern.push_back(static_cast<uint8_t>(std::strtoul(hex_byte.c_str(), nullptr, 16)));

			for (size_t i = 0; i < len; i++)
			{
				uint8_t* current_opcode = reinterpret_cast<uint8_t*>(start + i);

				if (current_opcode[0] != pattern.at(0))
					continue;

				if (bin_match(current_opcode, pattern))
					return ((t) (start + i + skip));
			}

			return 0;
		}

		template <typename t = uintptr_t>
		static t first_code_match(const HMODULE& start, const std::string& pattern, const std::ptrdiff_t& skip = 0)
		{
			PIMAGE_DOS_HEADER dos{reinterpret_cast<PIMAGE_DOS_HEADER>(start)};
			PIMAGE_NT_HEADERS nt;

			if (dos->e_magic != IMAGE_DOS_SIGNATURE)
				return 0;

			nt = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(dos) + dos->e_lfanew);

			return first_match<t>( reinterpret_cast<uintptr_t>( dos ) + nt->OptionalHeader.BaseOfCode, pattern, nt->OptionalHeader.SizeOfCode, skip );;
		}
	};
}
