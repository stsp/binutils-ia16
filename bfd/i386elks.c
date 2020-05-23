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
  uint8_t a_text[4];			/* Size of text section in bytes. */
  uint8_t a_data[4];			/* Size of data section in bytes. */
  uint8_t a_bss[4];			/* Size of BSS section in bytes. */
  uint8_t a_entry[4];			/* Entry point. */
  uint8_t a_heap[2];			/* Maxmimum heap size (a_version == 1)
					   or total data segment to allocate
					   (a_version == 0). */
  uint8_t a_minstack[2];		/* Minimum initial stack size. */
  uint8_t a_syms[4];			/* Symbol table size. */
  /* The following fields are optional.  They are specified, but apparently
     unused, in Minix. */
  uint8_t a_trsize[4];			/* Length of text relocation info. */
  uint8_t a_drsize[4];			/* Length of data relocation info. */
  uint8_t a_tbase[4];			/* Text relocation base. */
  uint8_t a_dbase[4];			/* Data relocation base. */
  /* Not yet implemented in ELKS. */
  uint8_t a_ftext[2];			/* Size of far text section in
					   bytes. */
  uint8_t a_ftrsize[4];			/* Length of far text relocation
					   info. */
  uint8_t a_unused2[10];		/* Reserved; should be 0. */
};

/* Minimum ELKS a.out header size. */
#define ELKS_MIN_HDR_SIZE (offsetof (struct elks_aout_header, a_trsize))

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

/* Relocation format. */
struct elks_aout_reloc
{
  uint8_t r_vaddr[4];			/* Address of place within section. */
  uint8_t r_symndx[2];			/* Index into symbol table, or
					   (negative) segment number. */
  uint8_t r_type[2];			/* Relocation type. */
};

/* Relocation types (?).  Not yet implemented in ELKS. */
#define R_ABBS		0
#define R_RELLBYTE	2
#define R_PCRBYTE	3
#define R_RELWORD	4
#define R_PCRWORD	5
#define R_RELLONG	6
#define R_PCRLONG	7
#define R_REL3BYTE	8
#define R_KBRANCHE	9
/* New IA-16 segment relocation type. */
#define R_SEGWORD	80

/* Special symbol indices. */
#define S_ABS		((uint16_t) -1U)
#define S_TEXT		((uint16_t) -2U)
#define S_DATA		((uint16_t) -3U)
#define S_BSS		((uint16_t) -4U)
/* Not yet implemented in ELKS. */
#define S_FTEXT		((uint16_t) -5U)

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
  bfd_size_type n_read;
  uint32_t hdr_len, a_text, a_data, a_bss, a_syms, a_trsize = 0, a_drsize = 0,
	   a_tbase = 0, a_dbase = 0, a_ftext = 0, a_ftrsize = 0;
  long a_version;

  if (bfd_seek (abfd, (file_ptr) 0, SEEK_SET) != 0
      || bfd_bread (&hdr, (bfd_size_type) sizeof (hdr), abfd) < sizeof (hdr))
    {
      if (bfd_get_error () != bfd_error_system_call)
	bfd_set_error (bfd_error_wrong_format);
      return NULL;
    }

  /* For now, only accept separate I/D executables for the 8086 with simple
     headers. */
  n_read = bfd_bread (&hdr, (bfd_size_type) sizeof (hdr), abfd);
  hdr_len = hdr.a_hdrlen;
  if (n_read < ELKS_MIN_HDR_SIZE || hdr_len > n_read)
    {
      if (bfd_get_error () != bfd_error_system_call)
	bfd_set_error (bfd_error_wrong_format);
      return NULL;
    }

  /* For now, only accept separate I/D executables for the 8086, with the
     a_version field indicating a version 0 or version 1 header. */
  if (hdr.a_magic[0] != A_MAGIC0 || hdr.a_magic[1] != A_MAGIC1
      || hdr.a_unused != 0 || hdr.a_cpu != A_I8086)
    {
      bfd_set_error (bfd_error_wrong_format);
      return NULL;
    }

  a_version = H_GET_16 (abfd, hdr.a_version);
  if (a_version > 1)
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

  /* Check that the recorded header size makes sense.  Also read any extra
     fields, if available, beyond the minimum. */
  switch (hdr_len)
    {
    case sizeof (hdr):
      a_ftext = H_GET_16 (abfd, hdr.a_ftext);
      a_ftrsize = H_GET_32 (abfd, hdr.a_ftrsize);
      /* fall through */

    case offsetof (struct elks_aout_header, a_ftext):
      a_tbase = H_GET_32 (abfd, hdr.a_tbase);
      a_dbase = H_GET_32 (abfd, hdr.a_tbase);
      a_trsize = H_GET_32 (abfd, hdr.a_trsize);
      a_drsize = H_GET_32 (abfd, hdr.a_drsize);
      /* fall through */

    case ELKS_MIN_HDR_SIZE:
      break;

    default:
      bfd_set_error (bfd_error_wrong_format);
      return NULL;
    }

  if (a_trsize % sizeof (struct elks_aout_reloc) != 0
      || a_drsize % sizeof (struct elks_aout_reloc) != 0
      || a_ftrsize % sizeof (struct elks_aout_reloc) != 0)
    {
      bfd_set_error (bfd_error_wrong_format);
      return NULL;
    }

  a_text = H_GET_32 (abfd, hdr.a_text);
  a_data = H_GET_32 (abfd, hdr.a_data);
  a_bss = H_GET_32 (abfd, hdr.a_bss);
  a_syms = H_GET_32 (abfd, hdr.a_syms);

  if (!elks_mkobject (abfd))
    return NULL;

  abfd->flags = EXEC_P;
  if (a_trsize || a_drsize || a_ftrsize)
    abfd->flags |= HAS_RELOC;

  adata (abfd).exec_bytes_size = hdr_len;
  exec_hdr (abfd)->a_info = a_version;
  exec_hdr (abfd)->a_text = a_text;
  exec_hdr (abfd)->ov_siz[0] = a_ftext;
  exec_hdr (abfd)->ov_siz[1] = a_ftrsize;
  exec_hdr (abfd)->a_data = a_data;
  exec_hdr (abfd)->a_bss = a_bss;
  exec_hdr (abfd)->a_heap = H_GET_16 (abfd, hdr.a_heap);
  exec_hdr (abfd)->a_minstack = H_GET_16 (abfd, hdr.a_minstack);
  exec_hdr (abfd)->a_syms = a_syms;
  exec_hdr (abfd)->a_entry = abfd->start_address
			   = H_GET_32 (abfd, hdr.a_entry);
  exec_hdr (abfd)->a_trsize = a_trsize;
  exec_hdr (abfd)->a_drsize = a_drsize;
  exec_hdr (abfd)->a_tload = a_tbase;
  exec_hdr (abfd)->a_dload = a_dbase;

  if (a_text)
    {
      section = bfd_make_section (abfd, ".text");
      if (section == NULL)
	return NULL;

      section->flags = (SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_HAS_CONTENTS);
      if (a_trsize)
	section->flags |= SEC_RELOC;
      section->filepos = hdr_len;

      if (bfd_seek (abfd, (file_ptr) (section->filepos + a_text), SEEK_SET)
	  != 0)
	{
	  if (bfd_get_error () != bfd_error_system_call)
	    bfd_set_error (bfd_error_wrong_format);
	  return NULL;
	}

      bfd_set_section_vma (section, a_tbase);
      bfd_set_section_size (section, a_text);
      section->alignment_power = 0;
    }

  if (a_ftext)
    {
      section = bfd_make_section (abfd, ".fartext");
      if (section == NULL)
	return NULL;

      section->flags = (SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_HAS_CONTENTS);
      if (a_ftrsize)
	section->flags |= SEC_RELOC;
      section->filepos = hdr_len + a_text;

      if (bfd_seek (abfd, (file_ptr) (section->filepos + a_text + a_ftext),
		    SEEK_SET) != 0)
	{
	  if (bfd_get_error () != bfd_error_system_call)
	    bfd_set_error (bfd_error_wrong_format);
	  return NULL;
	}

      bfd_set_section_vma (section, 0);
      bfd_set_section_lma (section, a_text);
      bfd_set_section_size (section, a_ftext);
      section->alignment_power = 0;
    }

  if (a_data)
    {
      section = bfd_make_section (abfd, ".data");
      if (section == NULL)
	return NULL;

      section->flags = (SEC_ALLOC | SEC_LOAD | SEC_DATA | SEC_HAS_CONTENTS);
      if (a_drsize)
	section->flags |= SEC_RELOC;
      section->filepos = hdr_len + a_text + a_ftext;

      if (bfd_seek (abfd, (file_ptr) (section->filepos + a_text + a_ftext
				      + a_data), SEEK_SET) != 0)
	{
	  if (bfd_get_error () != bfd_error_system_call)
	    bfd_set_error (bfd_error_wrong_format);
	  return NULL;
	}

      bfd_set_section_vma (section, a_dbase);
      bfd_set_section_lma (section, a_text);
      bfd_set_section_size (section, a_data);
      section->alignment_power = 0;
    }

  if (a_bss)
    {
      section = bfd_make_section (abfd, ".bss");
      if (section == NULL)
	return NULL;

      section->flags = (SEC_ALLOC | SEC_DATA);
      bfd_set_section_vma (section, a_dbase + a_data);
      bfd_set_section_lma (section, a_text + a_data);
      bfd_set_section_size (section, a_bss);
      section->alignment_power = 0;
    }

  return _bfd_no_cleanup;
}

static int
elks_sizeof_headers (bfd *abfd, struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  return adata (abfd).exec_bytes_size;
}

static bool
elks_new_section_hook (bfd *abfd, asection *newsect)
{
  if (bfd_get_format (abfd) == bfd_object)
    {
      /* Accept .fartext and .fartext.* as far text section names. */
      if (obj_ovsec (abfd, 0) == NULL
	  && strncmp (newsect->name, ".fartext", 8) == 0
	  && (newsect->name[8] == 0 || newsect->name[8] == '.'))
	obj_ovsec (abfd, 0) = newsect;
    }

  return aout_32_new_section_hook (abfd, newsect);
}

static void
elks_prime_header (bfd *abfd)
{
  asection *sec;
  bfd_vma a_text = 0, a_data = 0, a_bss = 0, a_ftext = 0,
	  a_trsize = 0, a_drsize = 0, a_ftrsize = 0, a_tbase = 0, a_dbase = 0;
  bfd_size_type hdr_len;

  sec = obj_textsec (abfd);
  if (sec)
    {
      bfd_vma vma = bfd_section_vma (sec),
	      lma = bfd_section_lma (sec);
      a_text = bfd_section_size (sec);
      a_trsize = sec->reloc_count * sizeof (struct elks_aout_reloc);
      /* XXX */
      if ((lma & (bfd_vma) 0xffff) == vma)
	a_tbase = vma;
      else
	a_tbase = lma;
    }

  sec = obj_datasec (abfd);
  if (sec)
    {
      bfd_vma vma = bfd_section_vma (sec),
	      lma = bfd_section_lma (sec);
      a_data = bfd_section_size (sec);
      a_drsize = sec->reloc_count * sizeof (struct elks_aout_reloc);
      /* XXX */
      if ((lma & (bfd_vma) 0xffff) == vma)
	a_dbase = vma;
      else
	a_dbase = lma;
    }

  sec = obj_bsssec (abfd);
  if (sec)
    {
      a_bss = bfd_section_size (sec);
      /* There may be some padding after the initialized data segment.  Take
	 this into account. */
      a_bss += bfd_section_vma (sec);
      a_bss -= a_dbase + a_data;
    }

  sec = obj_ovsec (abfd, 0);
  if (sec)
    {
      a_ftext = bfd_section_size (sec);
      a_ftrsize = sec->reloc_count * sizeof (struct elks_aout_reloc);
    }

  if (a_ftext || a_ftrsize)
    hdr_len = sizeof (struct elks_aout_header);
  else if (a_trsize || a_drsize || a_tbase || a_dbase)
    hdr_len = offsetof (struct elks_aout_header, a_ftext);
  else
    hdr_len = ELKS_MIN_HDR_SIZE;

  adata (abfd).exec_bytes_size = hdr_len;
  exec_hdr (abfd)->a_text = a_text;
  exec_hdr (abfd)->ov_siz[0] = a_ftext;
  exec_hdr (abfd)->ov_siz[1] = a_ftrsize;
  exec_hdr (abfd)->a_data = a_data;
  exec_hdr (abfd)->a_bss = a_bss;
  exec_hdr (abfd)->a_syms = 0;		/* XXX */
  exec_hdr (abfd)->a_entry = abfd->start_address;
  exec_hdr (abfd)->a_trsize = a_trsize;
  exec_hdr (abfd)->a_drsize = a_drsize;
  exec_hdr (abfd)->a_tload = a_tbase;
  exec_hdr (abfd)->a_dload = a_dbase;
}

static bool
elks_bfd_final_link (bfd *abfd, struct bfd_link_info *info)
{
  elks_prime_header (abfd);
  if (! _bfd_generic_final_link (abfd, info))
    return false;

  elks_prime_header (abfd);
  return true;
}

static bool
elks_squirt_out_relocs (bfd *abfd, asection *sec, file_ptr pos)
{
  arelent **orelocation;
  unsigned i, reloc_count;
  struct elks_aout_reloc aout_rel;

  if (! sec)
    return true;

  reloc_count = sec->reloc_count;
  if (! reloc_count)
    return true;

  if (bfd_seek (abfd, pos, SEEK_SET) != 0)
    return false;

  orelocation = sec->orelocation;
  for (i = 0; i < reloc_count; ++i)
    {
      arelent *rel = orelocation[i];
      asymbol *sym;
      asection *sym_sec;
      reloc_howto_type *howto = rel->howto;
      uint16_t sym_ndx;

      /* XXX this should probably be checked earlier and in a different way. */
      if (strstr (howto->name, "SEG") == 0
	  || strstr (howto->name, "RELSEG") != 0)
	{
	  _bfd_error_handler
	     /* xgettext:c_format */
	    (_("%pB: unsupported `%s' relocation for section `%pA'"),
	     abfd, howto->name, sec);
	  bfd_set_error (bfd_error_nonrepresentable_section);
	  return false;
	}

      sym = *rel->sym_ptr_ptr;
      sym_sec = sym->section->output_section;

      if (sym_sec == obj_textsec (abfd))
	sym_ndx = S_TEXT;
      else if (sym_sec == obj_datasec (abfd) || sym_sec == obj_bsssec (abfd))
	sym_ndx = S_DATA;
      else if (sym_sec == obj_ovsec (abfd, 0))
	sym_ndx = S_FTEXT;
      else
	{
	  _bfd_error_handler
	     /* xgettext:c_format */
	    (_("%pB: cannot emit IA-16 segment relocation to section `%pA'"),
	     abfd, sym_sec);
	  bfd_set_error (bfd_error_nonrepresentable_section);
	  return false;
	}

      H_PUT_32 (abfd, rel->address, aout_rel.r_vaddr);
      H_PUT_16 (abfd, sym_ndx, aout_rel.r_symndx);
      H_PUT_16 (abfd, R_SEGWORD, aout_rel.r_type);

      if (bfd_bwrite (&aout_rel, sizeof (aout_rel), abfd) != sizeof (aout_rel))
	return false;
    }

  return true;
}

static bool
elks_write_object_contents (bfd *abfd)
{
  struct elks_aout_header hdr;
  bfd_size_type hdr_len;
  long a_version;
  bfd_vma a_text, a_ftext = 0, a_data, a_bss,
	  a_trsize = 0, a_drsize = 0, a_ftrsize = 0, a_heap, a_minstack;

  /* Get the size of the header we actually need to write.  This should have
     been set by elks_bfd_final_link (, ) above. */
  hdr_len = adata (abfd).exec_bytes_size;

  /* Get some other parameters. */
  a_version = exec_hdr (abfd)->a_info;
  a_text = exec_hdr (abfd)->a_text;
  a_data = exec_hdr (abfd)->a_data;
  a_bss = exec_hdr (abfd)->a_bss;
  a_heap = exec_hdr (abfd)->a_heap;
  a_minstack = exec_hdr (abfd)->a_minstack;

  /* Do some sanity checking.  But not too much.  Most checking can be
     deferred to the linker scripts, which are easier to modify. */
  switch (a_version)
    {
    case 0:
      /* Backward compatibility.  a_heap actually holds the desired total
	 data segment size. */
      if (a_heap > 0xffff)
	{
	  _bfd_error_handler
	       /* xgettext:c_format */
	    (_("%pB: total data segment size (%#lx) is too large"),
	     abfd, (unsigned long) a_heap);
	  bfd_set_error (bfd_error_bad_value);
	  return false;
	}
      break;

    case 1:
      if (a_minstack > 0xffff)
	{
	  _bfd_error_handler
	       /* xgettext:c_format */
	    (_("%pB: initial stack size (%#lx) is too large"),
	     abfd, (unsigned long) a_minstack);
	  bfd_set_error (bfd_error_bad_value);
	  return false;
	}

      if (a_heap > 0xffff)
	{
	  _bfd_error_handler
	       /* xgettext:c_format */
	    (_("%pB: maximum heap size (%#lx) is too large"),
	     abfd, (unsigned long) a_heap);
	  bfd_set_error (bfd_error_bad_value);
	  return false;
	}
      break;

    default:
      abort ();
    }

  /* Fill in the header. */
  memset (&hdr, 0, hdr_len);
  hdr.a_magic[0] = A_MAGIC0;
  hdr.a_magic[1] = A_MAGIC1;
  hdr.a_flags = A_EXEC | A_SEP;
  hdr.a_cpu = A_I8086;
  hdr.a_hdrlen = hdr_len;
  hdr.a_unused = 0;
  H_PUT_16 (abfd, a_version, hdr.a_version);
  H_PUT_32 (abfd, a_text, hdr.a_text);
  H_PUT_32 (abfd, a_data, hdr.a_data);
  H_PUT_32 (abfd, a_bss, hdr.a_bss);
  H_PUT_32 (abfd, exec_hdr (abfd)->a_entry, hdr.a_entry);
  H_PUT_16 (abfd, exec_hdr (abfd)->a_heap, hdr.a_heap);
  H_PUT_16 (abfd, exec_hdr (abfd)->a_minstack, hdr.a_minstack);
  H_PUT_32 (abfd, exec_hdr (abfd)->a_syms, hdr.a_syms);

  if (hdr_len > ELKS_MIN_HDR_SIZE)
    {
      a_trsize = exec_hdr (abfd)->a_trsize;
      a_drsize = exec_hdr (abfd)->a_drsize;
      H_PUT_32 (abfd, a_trsize, hdr.a_trsize);
      H_PUT_32 (abfd, a_drsize, hdr.a_drsize);
      H_PUT_32 (abfd, exec_hdr (abfd)->a_tload, hdr.a_tbase);
      H_PUT_32 (abfd, exec_hdr (abfd)->a_dload, hdr.a_dbase);
      if (hdr_len > offsetof (struct elks_aout_header, a_ftext))
	{
	  a_ftext = exec_hdr (abfd)->ov_siz[0];
	  a_ftrsize = exec_hdr (abfd)->ov_siz[1];
	  H_PUT_16 (abfd, a_ftext, hdr.a_ftext);
	  H_PUT_32 (abfd, a_ftrsize, hdr.a_ftrsize);
	}
    }

  /* Write out the header. */
  if (bfd_seek (abfd, (file_ptr) 0, SEEK_SET) != 0
      || bfd_bwrite (&hdr, hdr_len, abfd) != hdr_len)
    return false;

  /* Also write out relocations (!). */
  if (! elks_squirt_out_relocs (abfd, obj_textsec (abfd),
				(file_ptr) hdr_len + a_text + a_ftext
				+ a_data)
      || ! elks_squirt_out_relocs (abfd, obj_ovsec (abfd, 0),
				   (file_ptr) hdr_len + a_text + a_ftext
				   + a_data + a_trsize)
      || ! elks_squirt_out_relocs (abfd, obj_datasec (abfd),
				   (file_ptr) hdr_len + a_text + a_ftext
				   + a_data + a_trsize + a_ftrsize))
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
  bfd_size_type hdr_len;

  if (! abfd->output_has_begun)
    elks_prime_header (abfd);

  hdr_len = adata (abfd).exec_bytes_size;

  if (section == obj_textsec (abfd))
    section->filepos = hdr_len;
  else if (section == obj_ovsec (abfd, 0))
    section->filepos = hdr_len + exec_hdr (abfd)->a_text;
  else if (section == obj_datasec (abfd))
    section->filepos = hdr_len + exec_hdr (abfd)->a_text
		       + exec_hdr (abfd)->ov_siz[0];
  else if (section == obj_bsssec (abfd))
    {
      bfd_set_error (bfd_error_no_contents);
      return false;
    }
  else
    {
      _bfd_error_handler
	   /* xgettext:c_format */
	(_("%pB: can not represent section `%pA' in ELKS object file format"),
	 abfd, section);
      bfd_set_error (bfd_error_nonrepresentable_section);
      return false;
    }

  if (count != 0)
    if (bfd_seek (abfd, section->filepos + offset, SEEK_SET) != 0
	|| bfd_bwrite (location, count, abfd) != count)
      return false;

  return true;
}

static bfd_reloc_status_type
bfd_elks_segword_reloc (bfd *abfd ATTRIBUTE_UNUSED,
			arelent *reloc_entry ATTRIBUTE_UNUSED,
			asymbol *symbol ATTRIBUTE_UNUSED,
			void *data ATTRIBUTE_UNUSED,
			asection *input_section ATTRIBUTE_UNUSED,
			bfd *output_bfd ATTRIBUTE_UNUSED,
			char **error_message ATTRIBUTE_UNUSED)
{
  /* XXX */
  abort ();
  return bfd_reloc_other;
}

static reloc_howto_type howto_segword =
  HOWTO (R_SEGWORD, 0, 1, 16, false, 0, complain_overflow_signed,
	 bfd_elks_segword_reloc, "R_SEGWORD", true, 0xffff, 0xffff, false);

static bool
elks_slurp_reloc_table (bfd *abfd, asection *sec)
{
  file_ptr reloc_areas_start, pos;
  bfd_vma a_trsize, rsize;
  unsigned count, i;
  struct elks_aout_reloc aout_rel;
  arelent *reloc_cache;

  if (sec->relocation)
    return true;

  reloc_areas_start = (file_ptr) adata (abfd).exec_bytes_size
		      + exec_hdr (abfd)->a_text + exec_hdr (abfd)->ov_siz[0]
		      + exec_hdr (abfd)->a_data;
  a_trsize = exec_hdr (abfd)->a_trsize;

  if (sec == obj_textsec (abfd))
    {
      pos = reloc_areas_start;
      rsize = a_trsize;
    }
  else if (sec == obj_ovsec (abfd, 0))
    {
      pos = reloc_areas_start + a_trsize;
      rsize = exec_hdr (abfd)->ov_siz[1];
    }
  else if (sec == obj_datasec (abfd))
    {
      pos = reloc_areas_start + a_trsize + exec_hdr (abfd)->ov_siz[1];
      rsize = exec_hdr (abfd)->a_drsize;
    }
  else
    {
      bfd_set_error (bfd_error_invalid_operation);
      return false;
    }

  if (bfd_seek (abfd, pos, SEEK_SET) != 0)
    return false;

  count = rsize / sizeof (struct elks_aout_reloc);
  if (! count)
    {
      sec->relocation = NULL;
      sec->reloc_count = 0;
      return true;
    }

  size_t amt;
  if (_bfd_mul_overflow (count, sizeof (arelent), &amt))
    return false;
  reloc_cache = bfd_zmalloc (amt);
  if (! reloc_cache)
    return false;

  for (i = 0; i < count; ++i)
    {
      unsigned rtype, sym_ndx;
      asymbol **sym_ptr_ptr;
      reloc_howto_type *howto;

      if (bfd_bread (&aout_rel, sizeof (aout_rel), abfd) != sizeof (aout_rel))
	{
	  free (reloc_cache);
	  return false;
	}

      rtype = H_GET_16 (abfd, aout_rel.r_type);
      switch (rtype)
	{
	case R_SEGWORD:
	  howto = &howto_segword;
	  break;

	default:
	  _bfd_error_handler
	     /* xgettext:c_format */
	    (_("%pB: unsupported relocation type %#x in section `%pA'"),
	     abfd, (unsigned) rtype, sec);
	  bfd_set_error (bfd_error_invalid_operation);
	  free (reloc_cache);
	  return false;
	}

      sym_ndx = H_GET_16 (abfd, aout_rel.r_symndx);
      switch (sym_ndx)
	{
	case S_TEXT:
	  sym_ptr_ptr = obj_textsec (abfd)->symbol_ptr_ptr;
	  break;

	case S_FTEXT:
	  sym_ptr_ptr = obj_ovsec (abfd, 0)->symbol_ptr_ptr;
	  break;

	case S_DATA:
	  sym_ptr_ptr = obj_datasec (abfd)->symbol_ptr_ptr;
	  break;

	case S_BSS:
	  sym_ptr_ptr = obj_bsssec (abfd)->symbol_ptr_ptr;
	  break;

	default:
	  _bfd_error_handler
	     /* xgettext:c_format */
	    (_("%pB: unsupported symbol index %#x in section `%pA'"),
	     abfd, (unsigned) sym_ndx, sec);
	  bfd_set_error (bfd_error_invalid_operation);
	  free (reloc_cache);
	  return false;
	}

      reloc_cache[i].sym_ptr_ptr = sym_ptr_ptr;
      reloc_cache[i].address = H_GET_32 (abfd, aout_rel.r_vaddr);
      reloc_cache[i].addend = 0;
      reloc_cache[i].howto = howto;
    }

  sec->relocation = reloc_cache;
  sec->reloc_count = count;
  return true;
}

static long
elks_get_reloc_upper_bound (bfd *abfd, asection *sec)
{
  if (! elks_slurp_reloc_table (abfd, sec))
    return -1L;

  return (sec->reloc_count + 1) * sizeof (arelent *);
}

static long
elks_canonicalize_reloc (bfd *abfd, asection *sec, arelent **loc,
			 asymbol **syms ATTRIBUTE_UNUSED)
{
  unsigned count, i;

  if (! elks_slurp_reloc_table (abfd, sec))
    return -1L;

  count = sec->reloc_count;
  for (i = 0; i < count; ++i)
    loc[i] = &sec->relocation[i];
  loc[count] = NULL;

  return count;
}

/* Called from the i386elks.em linker emulation code. */
void
elks_set_heap_and_minstack (bfd *, bfd_vma, bfd_vma, bfd_vma, bfd_vma);

void
elks_set_heap_and_minstack (bfd *abfd, bfd_vma stack_size, bfd_vma heap_size,
			    bfd_vma chmem, bfd_vma total_data_size)
{
  if (stack_size || heap_size)
    {
      /* New-style header. */
      exec_hdr (abfd)->a_info = 1;
      exec_hdr (abfd)->a_heap = heap_size;
      exec_hdr (abfd)->a_minstack = stack_size;
      return;
    }

  /* Old-style header. */
  if (chmem && ! total_data_size)
    {
      bfd_vma a_data, a_bss;
      elks_prime_header (abfd);
      a_data = exec_hdr (abfd)->a_data;
      a_bss = exec_hdr (abfd)->a_bss;
      total_data_size = a_data + a_bss + chmem;
    }

  exec_hdr (abfd)->a_info = 0;
  exec_hdr (abfd)->a_heap = total_data_size;
  exec_hdr (abfd)->a_minstack = 0;
}

#define elks_make_empty_symbol aout_32_make_empty_symbol
#define elks_bfd_reloc_type_lookup aout_32_reloc_type_lookup
#define elks_bfd_reloc_name_lookup aout_32_reloc_name_lookup

#define	elks_close_and_cleanup _bfd_generic_close_and_cleanup
#define elks_bfd_free_cached_info _bfd_generic_bfd_free_cached_info
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
#define elks_bfd_link_split_section _bfd_generic_link_split_section
#define elks_set_arch_mach _bfd_generic_set_arch_mach
#define elks_bfd_link_check_relocs _bfd_generic_link_check_relocs
#define elks_bfd_group_name bfd_generic_group_name

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

#define elks_set_reloc _bfd_generic_set_reloc
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
