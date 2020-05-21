# This shell script emits a C file. -*- C -*-
#   Copyright (C) 2010-2020 Free Software Foundation, Inc.
#
# This file is part of the GNU Binutils.
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

# This file is sourced from generic.em.

fragment <<EOF
#include "getopt.h"

#define OPTION_STACK		301
#define OPTION_HEAP		(OPTION_STACK + 1)
#define OPTION_CHMEM		(OPTION_HEAP + 1)
#define OPTION_TOTAL_DATA	(OPTION_CHMEM + 1)

static bfd_vma stack_size = 0, heap_size = 0, chmem = 0, total_data_size = 0;

static void
gld${EMULATION_NAME}_add_options (int ns ATTRIBUTE_UNUSED,
				  char **shortopts ATTRIBUTE_UNUSED,
 				  int nl, struct option **longopts,
				  int nrl ATTRIBUTE_UNUSED,
				  struct option **really_longopts
						  ATTRIBUTE_UNUSED)
{
  static const struct option xtra_long[] =
  {
    { "stack", required_argument, NULL, OPTION_STACK },
    { "heap", required_argument, NULL, OPTION_HEAP },
    { "chmem", required_argument, NULL, OPTION_CHMEM },
    { "total-data", required_argument, NULL, OPTION_TOTAL_DATA },
    { NULL, no_argument, NULL, 0 }
  };
  *longopts = (struct option *)
    xrealloc (*longopts, nl * sizeof (struct option) + sizeof (xtra_long));
  memcpy (*longopts + nl, xtra_long, sizeof (xtra_long));
}

static bool
gld${EMULATION_NAME}_handle_option (int optc)
{
  char *end;
  bfd_vma value;

  switch (optc)
    {
    default:
      return false;

    case OPTION_STACK:
      value = strtoul (optarg, &end, 0);
      if (*end)
	einfo (_("%F%P: invalid stack size \`%s'\n"), optarg);
      else
	stack_size = value;
      break;

    case OPTION_HEAP:
      value = strtoul (optarg, &end, 0);
      if (*end)
	einfo (_("%F%P: invalid heap size \`%s'\n"), optarg);
      else
	heap_size = value;
      break;

    case OPTION_CHMEM:
      value = strtoul (optarg, &end, 0);
      if (*end)
	einfo (_("%F%P: invalid stack + heap size \`%s'\n"), optarg);
      else
	chmem = value;
      break;

    case OPTION_TOTAL_DATA:
      value = strtoul (optarg, &end, 0);
      if (*end)
	einfo (_("%F%P: invalid data segment size \`%s'\n"), optarg);
      else
	total_data_size = value;
      break;
    }

  return true;
}

static void
gld${EMULATION_NAME}_list_options (FILE *file)
{
  fprintf (file, _("  --stack <size>              "
		   "Set size of the initial stack\n"));
  fprintf (file, _("  --heap <size>               "
		   "Set maximum heap size\n"));
  fprintf (file, _("  --chmem <size>              "
		   "Set maximum stack + heap + env size\n"));
  fprintf (file, _("  --total-data <size>         "
		   "Set maximum data segment size\n"));
}

extern void elks_set_total_and_minstack (bfd *, bfd_vma, bfd_vma, bfd_vma,
						bfd_vma);

static void
gld${EMULATION_NAME}_after_allocation (void)
{
  bfd *abfd = link_info.output_bfd;

  elks_set_total_and_minstack (abfd, stack_size, heap_size, chmem,
				     total_data_size);
}
EOF

LDEMUL_ADD_OPTIONS=gld"$EMULATION_NAME"_add_options
LDEMUL_HANDLE_OPTION=gld"$EMULATION_NAME"_handle_option
LDEMUL_LIST_OPTIONS=gld"$EMULATION_NAME"_list_options
LDEMUL_AFTER_ALLOCATION=gld"$EMULATION_NAME"_after_allocation
