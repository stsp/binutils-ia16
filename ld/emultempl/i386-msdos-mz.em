# This shell script emits a C file. -*- C -*-
#   Copyright (C) 1991-2019 Free Software Foundation, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
# MA 02110-1301, USA.
#

# This file is sourced from elf32.em, and defines routines for
# handling special "i386" segment relocations when creating an
# MS-DOS MZ executable as output.  It is based on armelf.em,
# elf32-arm.c, and ppc64elf.em.  -- tkchia
#
fragment <<EOF

#line 28 "i386-msdos-mz.em"  /* to aid debugging */

#include "ldctor.h"
#include "ldlex.h"
#include "elf/i386.h"
#include "bfd.h"
#include "libiberty.h"

static asection **mz_reloc_sections = NULL;
static bfd_vma num_mz_reloc_sections = 0;

static void
i386_mz_after_open (void)
{
  /* For each input file, check if it uses any R_386_OZSEG16 relocations.
     If it does, add a .msdos_mz_reloc.* section to it, with the right size.

     Try not to waste memory on sections with no R_386_OZSEG16
     relocations.  -- tkchia  */
  size_t num_new_secs = 0, new_secs_top = 0;
  asection **new_secs = NULL;

  if (! bfd_link_relocatable (&link_info))
    {
      LANG_FOR_EACH_INPUT_STATEMENT (is)
	{
	  bfd *abfd = is->the_bfd;
	  asection *sec = NULL, *mz_section = NULL;
	  Elf_Internal_Rela *irels = NULL, *irel, *irelend;
	  bfd_vma num_mz = 0;
	  char *mz_section_name = NULL;
	  int count = 0;
	  bfd_byte *contents = NULL;

	  for (sec = abfd->sections; sec; sec = sec->next)
	    {
	      if (sec->reloc_count == 0
		  || (sec->flags & SEC_EXCLUDE)
		  || ! (sec->flags & SEC_ALLOC)
		  || ! (sec->flags & SEC_RELOC))
		continue;

	      irels = _bfd_elf_link_read_relocs (abfd, sec, NULL, NULL,
						 link_info.keep_memory);
	      if (! irels)
		{
		  /* xgettext:c-format */
		  einfo (_("%P: errors encountered processing file %s\n"),
			 is->filename);
		  bfd_set_error (bfd_error_bad_value);
		  goto cont;
		}

	      irelend = irels + sec->reloc_count;
	      for (irel = irels; irel != irelend; ++irel)
		{
		  switch (ELF32_R_TYPE (irel->r_info))
		    {
		    case R_386_OZSEG16:
		      if (num_mz >= 0xffffu)
			{
			  /* xgettext:c-format */
			  einfo (_("%P: too many MZ relocations needed\n"));
			  bfd_set_error (bfd_error_bad_value);
			  if (elf_section_data (sec)->relocs != irels)
			    free (irels);
			  goto cont;
			}
		      ++num_mz;
		      break;
		    }
		}

	      if (elf_section_data (sec)->relocs != irels)
		free (irels);
	    }

	  if (! num_mz)
	    continue;

	  mz_section_name
	    = bfd_get_unique_section_name (abfd, ".msdos_mz_reloc", &count);
	  if (mz_section_name)
	    mz_section
	      = bfd_make_section_anyway_with_flags (abfd, mz_section_name,
						    SEC_ALLOC | SEC_LOAD
						    | SEC_DATA
						    | SEC_HAS_CONTENTS
						    | SEC_KEEP);
	  if (! mz_section_name || ! mz_section
	      || ! bfd_set_section_size (mz_section,
					 4 * num_mz * sizeof (bfd_byte)))
	    {
	      /* xgettext:c-format */
	      einfo (_("%P: cannot make MZ relocation section for file %s\n"),
		     is->filename);
	      bfd_set_error (bfd_error_no_memory);
	      goto cont;
	    }

	  contents = bfd_alloc (abfd, 4 * num_mz * sizeof (bfd_byte));
	  if (! contents)
	    {
	      /* xgettext:c-format */
	      einfo (_("%P: no memory for MZ relocations for file %s\n"),
		     is->filename);
	      bfd_set_error (bfd_error_no_memory);
	      goto cont;
	    }

	  mz_section->contents = contents;
	  mz_section->flags |= SEC_IN_MEMORY;

	  if (num_new_secs > SIZE_MAX / sizeof (asection *) - 1)
	    {
	      /* xgettext:c-format */
	      einfo (_("%P: too many MZ relocation sections needed\n"));
	      bfd_set_error (bfd_error_file_too_big);
	      goto cont;
	    }

	  if (++num_new_secs > new_secs_top)
	    {
	      while (new_secs_top < num_new_secs)
		{
		  if (new_secs_top < (SIZE_MAX / sizeof (asection *) - 1) / 2)
		    new_secs_top = 2 * new_secs_top + 1;
		  else
		    new_secs_top = num_new_secs;
		}
	      new_secs = XRESIZEVEC (asection *, new_secs, new_secs_top);
	    }
	  new_secs[num_new_secs - 1] = mz_section;
	}
    }

  if (new_secs_top > num_new_secs)
    new_secs = XRESIZEVEC (asection *, new_secs, num_new_secs);
  mz_reloc_sections = new_secs;
  num_mz_reloc_sections = num_new_secs;

cont:
  gld${EMULATION_NAME}_after_open ();
}

static void
gld${EMULATION_NAME}_finish (void)
{
  /* Fill the .msdos_mz_reloc.* sections we just created with the actual
     relocations.  */
  if (num_mz_reloc_sections)
    {
      asection **mz_secs = mz_reloc_sections,
	       **mz_secs_end = mz_reloc_sections + num_mz_reloc_sections,
	       **pmzs;

      for (pmzs = mz_secs; pmzs != mz_secs_end; ++pmzs)
	{
	  asection *mz_section = *pmzs, *sec, *osec;
	  bfd *ibfd = mz_section->owner;
	  bfd *obfd = link_info.output_bfd;
	  asection *hdr_sec = bfd_get_section_by_name (obfd, ".msdos_mz_hdr");
	  bfd_vma subtrahend = 0;
	  bfd_size_type reloc_idx = 0;
	  Elf_Internal_Rela *irels = NULL, *irel, *irelend;

	  if (hdr_sec)
	    {
	      if (hdr_sec->lma % 16 != 0 || hdr_sec->size % 16 != 0)
		{
		  /* xgettext:c-format */
		  einfo (_("%P: R_386_OZSEG16 with unaligned \
MZ header\n"));
		  bfd_set_error (bfd_error_bad_value);
		  break;
		}

	      subtrahend = hdr_sec->lma / 16 + hdr_sec->size / 16;
	    }

	  for (sec = ibfd->sections; sec; sec = sec->next)
	    {
	      if (sec == mz_section
		  || sec->reloc_count == 0
		  || (sec->flags & SEC_EXCLUDE)
		  || ! (sec->flags & SEC_ALLOC)
		  || ! (sec->flags & SEC_RELOC))
		continue;

	      osec = sec->output_section;

	      irels = _bfd_elf_link_read_relocs (ibfd, sec, NULL, NULL,
						 link_info.keep_memory);
	      if (! irels)
		{
		  /* xgettext:c-format */
		  einfo (_("%P: errors encountered processing file %s\n"),
			 ibfd->filename);
		  bfd_set_error (bfd_error_bad_value);
		  goto cont;
		}

	      irelend = irels + sec->reloc_count;
	      for (irel = irels; irel != irelend; ++irel)
		{
		  long r_info = irel->r_info;
		  long r_type = ELF32_R_TYPE (r_info);
		  if (r_type == R_386_OZSEG16)
		    {
		      bfd_vma olma = osec->lma, ovma = osec->vma;
		      if (olma % 16 != ovma % 16)
			{
			  /* xgettext:c-format */
			  einfo (_("%P: R_386_OZSEG16 with \
unaligned output section\n"));
			  bfd_set_error (bfd_error_bad_value);
			  break;
			}
		      bfd_put_16 (ibfd,
				  ovma + sec->output_offset + irel->r_offset,
				  mz_section->contents + 4 * reloc_idx);
		      bfd_put_16 (ibfd, (olma - ovma) / 16 - subtrahend,
				  mz_section->contents + 4 * reloc_idx + 2);
		      ++reloc_idx;
		    }
		}

	      if (elf_section_data (sec)->relocs != irels)
		free (irels);
	    }
	}

      XDELETEVEC (mz_secs);
      mz_reloc_sections = NULL;
    }

cont:
  finish_default ();
}

EOF

LDEMUL_AFTER_OPEN=i386_mz_after_open
LDEMUL_FINISH=gld${EMULATION_NAME}_finish
