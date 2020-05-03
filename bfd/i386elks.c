/* BFD back-end for ELKS a.out executables.
   Copyright (C) 1990-2020 Free Software Foundation, Inc.
   Modified from Bryan Ford's i386msdos.c MS-DOS MZ back-end by TK Chia.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */


#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "libaout.h"

struct elks_aout_header
{
  /* ELKS a.out header format.  The ELKS program format is derived from the
     Minix a.out format.  */
  uint8_t a_magic[2];			/* Magic number. */
  uint8_t a_flags;			/* Flags. */
  uint8_t a_cpu;			/* CPU type. */
  uint8_t a_hdrlen;			/* Length of header. */
  uint8_t a_unused;			/* Reserved. */
  uint8_t a_version[2];			/* Version stamp (unused). */
  uint8_t a_text[4];			/* Size of text section(s) in bytes. */
  uint8_t a_data[4];			/* Size of data section(s) in bytes. */
  uint8_t a_bss[4];			/* Size of BSS section(s) in bytes. */
  uint8_t a_entry[4];			/* Entry point. */
  uint8_t a_total[4];			/* Total memory allocated (if separate
					   I/D, for data and BSS). */
  uint8_t a_syms[4];			/* Symbol table size. */
};

#define A_MAGIC0	((uint8_t) 0x01)
#define A_MAGIC1	((uint8_t) 0x03)

/* CPU types for a_cpu. */
#define A_NONE		((uint8_t) 0x00) /* Unknown. */
#define A_I8086		((uint8_t) 0x04) /* Intel 8086/8088. */
#define A_M68K		((uint8_t) 0x0b) /* Motorola M68000. */
#define A_NS16K		((uint8_t) 0x0c) /* National Semiconductor 16032. */
#define A_I80386	((uint8_t) 0x10) /* Intel 80386. */
#define A_SPARC		((uint8_t) 0x17) /* Sun SPARC. */

/* Flag values for a_flags.  The first two are shared with Minix. */
#define A_EXEC		((uint8_t) 0x10) /* Executable (may be unset if A_SEP
					    is set). */
#define A_SEP		((uint8_t) 0x20) /* Separate instruction and data
					    address spaces.  */
/* These flags are reserved for ELKS use. */
#define A_EXEC_NEW	((uint8_t) 0x18) /* Executable with ELKS-specific
					    header fields.  (0x08 was old
					    Minix A_IMG flag.)  */

static bool
elks_mkobject (bfd *abfd)
{
  bfd_default_set_arch_mach (abfd, bfd_arch_i386, bfd_mach_i386_i8086);

  return aout_32_mkobject (abfd);
}

static bfd_cleanup
elks_object_p (bfd *abfd)
{
  struct elks_aout_header hdr;
  asection *section;
  uint32_t hdr_len, text_size, data_size, bss_size;

  if (bfd_seek (abfd, (file_ptr) 0, SEEK_SET) != 0
      || bfd_bread (&hdr, (bfd_size_type) sizeof (hdr), abfd) < sizeof (hdr))
    {
      if (bfd_get_error () != bfd_error_system_call)
	bfd_set_error (bfd_error_wrong_format);
      return NULL;
    }

  /* For now, only accept separate I/D executables for the 8086 with simple
     headers. */
  hdr_len = hdr.a_hdrlen;
  if (hdr.a_magic[0] != A_MAGIC0 || hdr.a_magic[1] != A_MAGIC1
      || hdr.a_unused != 0 || H_GET_16 (abfd, hdr.a_version) != 0
      || hdr.a_cpu != A_I8086 || hdr_len != sizeof (hdr))
    {
      bfd_set_error (bfd_error_wrong_format);
      return NULL;
    }

  switch (hdr.a_flags)
    {
    case A_SEP:
    case A_EXEC | A_SEP:
      break;

    default:
      bfd_set_error (bfd_error_wrong_format);
      return NULL;
    }

  if (!elks_mkobject (abfd))
    return NULL;

  abfd->flags = EXEC_P;
  abfd->start_address = H_GET_32 (abfd, hdr.a_entry);

  section = bfd_make_section (abfd, ".text");
  if (section == NULL)
    return NULL;

  section->flags = (SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_HAS_CONTENTS);
  section->filepos = hdr_len;
  text_size = H_GET_32 (abfd, hdr.a_text);

  if (bfd_seek (abfd, (file_ptr) (section->filepos + text_size), SEEK_SET)
      != 0)
    {
      if (bfd_get_error () != bfd_error_system_call)
	bfd_set_error (bfd_error_wrong_format);
      return NULL;
    }

  bfd_set_section_vma (section, 0);
  bfd_set_section_size (section, text_size);
  section->alignment_power = 0;

  section = bfd_make_section (abfd, ".data");
  if (section == NULL)
    return NULL;

  section->flags = (SEC_ALLOC | SEC_LOAD | SEC_DATA | SEC_HAS_CONTENTS);
  section->filepos = hdr_len + text_size;
  data_size = H_GET_32 (abfd, hdr.a_data);

  if (bfd_seek (abfd, (file_ptr) (section->filepos + text_size + data_size),
		SEEK_SET) != 0)
    {
      if (bfd_get_error () != bfd_error_system_call)
	bfd_set_error (bfd_error_wrong_format);
      return NULL;
    }

  bfd_set_section_vma (section, 0);
  bfd_set_section_lma (section, text_size);
  bfd_set_section_size (section, data_size);
  section->alignment_power = 0;

  section = bfd_make_section (abfd, ".bss");
  if (section == NULL)
    return NULL;

  section->flags = (SEC_ALLOC | SEC_DATA);
  bss_size = H_GET_32 (abfd, hdr.a_bss);
  bfd_set_section_vma (section, data_size);
  bfd_set_section_lma (section, text_size + data_size);
  bfd_set_section_size (section, bss_size);
  section->alignment_power = 0;

  return _bfd_no_cleanup;
}

static int
elks_sizeof_headers (bfd *abfd ATTRIBUTE_UNUSED,
		      struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  return 0;
}

static bool
elks_write_object_contents (bfd *abfd)
{
  struct elks_aout_header hdr;
  bfd_vma text_begin = (bfd_vma) 0 - 1, text_end = 0,
	  data_begin = (bfd_vma) 0 - 1, data_end = 0,
	  bss_end = 0;
  asection *sec;

  /* Find the size of the text, data, and BSS sections. */
  for (sec = abfd->sections; sec != (asection *) NULL; sec = sec->next)
    {
      flagword flags = bfd_section_flags (sec);
      bfd_vma sec_vma, sec_end_vma;

      if ((flags & SEC_ALLOC) == 0)
	continue;

      sec_vma = bfd_section_vma (sec);
      sec_end_vma = sec_vma + sec->size;

      if ((flags & SEC_CODE) != 0)
	{
	  if (sec_vma < text_begin)
	    text_begin = sec_vma;
	  if (sec_end_vma > text_end)
	    text_end = sec_end_vma;
	}
      else if ((flags & SEC_LOAD) != 0)
	{
	  if (sec_vma < data_begin)
	    data_begin = sec_vma;
	  if (sec_end_vma > data_end)
	    data_end = sec_end_vma;
	}
      else
	{
	  if (sec_end_vma > bss_end)
	    bss_end = sec_end_vma;
	}
    }

  if (text_begin > text_end)
    text_begin = text_end;

  if (data_begin > data_end)
    data_begin = data_end;

  /* Make sure the VMAs are sane. */
  if (text_begin != 0 || data_begin != 0 || bss_end < data_end)
    {
      bfd_set_error(bfd_error_nonrepresentable_section);
      return false;
    }

 if (text_end > (uint32_t) 0 - 1 || data_end > (uint32_t) 0 - 1
     || bss_end > (uint32_t) 0 - 1)
    {
      bfd_set_error(bfd_error_file_too_big);
      return false;
    }

  /* Fill in the header. */
  hdr.a_magic[0] = A_MAGIC0;
  hdr.a_magic[1] = A_MAGIC1;
  hdr.a_flags = A_EXEC | A_SEP;
  hdr.a_cpu = A_I8086;
  hdr.a_hdrlen = sizeof (hdr);
  hdr.a_unused = 0;
  H_PUT_16 (abfd, 0, hdr.a_version);
  H_PUT_32 (abfd, text_end, hdr.a_text);
  H_PUT_32 (abfd, data_end, hdr.a_data);
  H_PUT_32 (abfd, bss_end - data_end, hdr.a_bss);
  H_PUT_32 (abfd, abfd->start_address, hdr.a_entry);
  H_PUT_32 (abfd, 0, hdr.a_total);	/* XXX */
  H_PUT_32 (abfd, 0, hdr.a_syms);	/* XXX */

  if (bfd_seek (abfd, (file_ptr) 0, SEEK_SET) != 0
      || bfd_bwrite (&hdr, (bfd_size_type) sizeof(hdr), abfd) != sizeof(hdr))
    return false;

  return true;
}

static bool
elks_set_section_contents (bfd *abfd,
			    sec_ptr section,
			    const void *location,
			    file_ptr offset,
			    bfd_size_type count)
{

  if (count == 0)
    return true;

  section->filepos = sizeof (struct elks_aout_header)
		     + bfd_section_lma (section);

  if (bfd_section_flags (section) & SEC_LOAD)
    {
      if (bfd_seek (abfd, section->filepos + offset, SEEK_SET) != 0
	  || bfd_bwrite (location, count, abfd) != count)
	return false;
    }

  return true;
}



#define elks_make_empty_symbol aout_32_make_empty_symbol
#define elks_bfd_reloc_type_lookup aout_32_reloc_type_lookup
#define elks_bfd_reloc_name_lookup aout_32_reloc_name_lookup

#define	elks_close_and_cleanup _bfd_generic_close_and_cleanup
#define elks_bfd_free_cached_info _bfd_generic_bfd_free_cached_info
#define elks_new_section_hook _bfd_generic_new_section_hook
#define elks_get_section_contents _bfd_generic_get_section_contents
#define elks_get_section_contents_in_window \
  _bfd_generic_get_section_contents_in_window
#define elks_bfd_get_relocated_section_contents \
  bfd_generic_get_relocated_section_contents
#define elks_bfd_relax_section bfd_generic_relax_section
#define elks_bfd_gc_sections bfd_generic_gc_sections
#define elks_bfd_lookup_section_flags bfd_generic_lookup_section_flags
#define elks_bfd_merge_sections bfd_generic_merge_sections
#define elks_bfd_is_group_section bfd_generic_is_group_section
#define elks_bfd_discard_group bfd_generic_discard_group
#define elks_section_already_linked \
  _bfd_generic_section_already_linked
#define elks_bfd_define_common_symbol bfd_generic_define_common_symbol
#define elks_bfd_link_hide_symbol _bfd_generic_link_hide_symbol
#define elks_bfd_define_start_stop bfd_generic_define_start_stop
#define elks_bfd_link_hash_table_create _bfd_generic_link_hash_table_create
#define elks_bfd_link_add_symbols _bfd_generic_link_add_symbols
#define elks_bfd_link_just_syms _bfd_generic_link_just_syms
#define elks_bfd_copy_link_hash_symbol_type \
  _bfd_generic_copy_link_hash_symbol_type
#define elks_bfd_final_link _bfd_generic_final_link
#define elks_bfd_link_split_section _bfd_generic_link_split_section
#define elks_set_arch_mach _bfd_generic_set_arch_mach
#define elks_bfd_link_check_relocs _bfd_generic_link_check_relocs

#define elks_get_symtab_upper_bound _bfd_nosymbols_get_symtab_upper_bound
#define elks_canonicalize_symtab _bfd_nosymbols_canonicalize_symtab
#define elks_print_symbol _bfd_nosymbols_print_symbol
#define elks_get_symbol_info _bfd_nosymbols_get_symbol_info
#define elks_get_symbol_version_string \
  _bfd_nosymbols_get_symbol_version_string
#define elks_find_nearest_line _bfd_nosymbols_find_nearest_line
#define elks_find_line _bfd_nosymbols_find_line
#define elks_find_inliner_info _bfd_nosymbols_find_inliner_info
#define elks_get_lineno _bfd_nosymbols_get_lineno
#define elks_bfd_is_target_special_symbol _bfd_bool_bfd_asymbol_false
#define elks_bfd_is_local_label_name _bfd_nosymbols_bfd_is_local_label_name
#define elks_bfd_make_debug_symbol _bfd_nosymbols_bfd_make_debug_symbol
#define elks_read_minisymbols _bfd_nosymbols_read_minisymbols
#define elks_minisymbol_to_symbol _bfd_nosymbols_minisymbol_to_symbol

#define elks_canonicalize_reloc _bfd_norelocs_canonicalize_reloc
#define elks_set_reloc _bfd_norelocs_set_reloc
#define elks_get_reloc_upper_bound _bfd_norelocs_get_reloc_upper_bound
#define elks_32_bfd_link_split_section  _bfd_generic_link_split_section

const bfd_target i386_elks_vec =
  {
    "elks",			/* name */
    bfd_target_aout_flavour,
    BFD_ENDIAN_LITTLE,		/* target byte order */
    BFD_ENDIAN_LITTLE,		/* target headers byte order */
    (EXEC_P),			/* object flags */
    (SEC_CODE | SEC_DATA | SEC_HAS_CONTENTS
     | SEC_ALLOC | SEC_LOAD),	/* section flags */
    0,				/* leading underscore */
    ' ',				/* ar_pad_char */
    16,				/* ar_max_namelen */
    0,					/* match priority.  */
    TARGET_KEEP_UNUSED_SECTION_SYMBOLS, /* keep unused section symbols.  */
    bfd_getl64, bfd_getl_signed_64, bfd_putl64,
    bfd_getl32, bfd_getl_signed_32, bfd_putl32,
    bfd_getl16, bfd_getl_signed_16, bfd_putl16,	/* data */
    bfd_getl64, bfd_getl_signed_64, bfd_putl64,
    bfd_getl32, bfd_getl_signed_32, bfd_putl32,
    bfd_getl16, bfd_getl_signed_16, bfd_putl16,	/* hdrs */

    {
      _bfd_dummy_target,
      elks_object_p,		/* bfd_check_format */
      _bfd_dummy_target,
      _bfd_dummy_target,
    },
    {
      _bfd_bool_bfd_false_error,
      elks_mkobject,
      _bfd_generic_mkarchive,
      _bfd_bool_bfd_false_error,
    },
    {				/* bfd_write_contents */
      _bfd_bool_bfd_false_error,
      elks_write_object_contents,
      _bfd_write_archive_contents,
      _bfd_bool_bfd_false_error,
    },

    BFD_JUMP_TABLE_GENERIC (elks),
    BFD_JUMP_TABLE_COPY (_bfd_generic),
    BFD_JUMP_TABLE_CORE (_bfd_nocore),
    BFD_JUMP_TABLE_ARCHIVE (_bfd_noarchive),
    BFD_JUMP_TABLE_SYMBOLS (elks),
    BFD_JUMP_TABLE_RELOCS (elks),
    BFD_JUMP_TABLE_WRITE (elks),
    BFD_JUMP_TABLE_LINK (elks),
    BFD_JUMP_TABLE_DYNAMIC (_bfd_nodynamic),

    NULL,

    NULL
  };


