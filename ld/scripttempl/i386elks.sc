# Copyright (C) 2014-2020 Free Software Foundation, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.

test -z "$ENTRY" && ENTRY=_start
cat <<EOF
/* Copyright (C) 2014-2020 Free Software Foundation, Inc.

   Copying and distribution of this script, with or without modification,
   are permitted in any medium without royalty provided the copyright
   notice and this notice are preserved.  */

OUTPUT_FORMAT("${OUTPUT_FORMAT}")
OUTPUT_ARCH(${ARCH})

ENTRY(${ENTRY})

${RELOCATING+${LIB_SEARCH_DIRS}}
${STACKZERO+${RELOCATING+${STACKZERO}}}
SECTIONS
{
  ${RELOCATING+. = ${TEXT_START_ADDR};}
  .text :
  {
    CREATE_OBJECT_SYMBOLS
    *(.text .text.*)
    ${RELOCATING+etext = .;}
    ${RELOCATING+_etext = .;}
    ${RELOCATING+__etext = .;}
  }
  .fartext ${RELOCATING+0} : ${RELOCATING+AT(0x10000)}
  {
    *(.fartext .fartext.*)
  }
  .data ${RELOCATING+0} : ${RELOCATING+AT(0x20000)}
  {
    *(.rodata .rodata.*)
    *(.data .data.*)
    ${CONSTRUCTING+CONSTRUCTORS}
    ${RELOCATING+edata  =  .;}
    ${RELOCATING+_edata  =  .;}
    ${RELOCATING+__edata  =  .;}
  }
  .bss :
  {
   ${RELOCATING+ _bss_start = .};
   ${RELOCATING+ __bss_start = .};
   *(.bss .bss.*)
   *(COMMON)
   ${RELOCATING+end = ALIGN(4) };
   ${RELOCATING+_end = ALIGN(4) };
   ${RELOCATING+__end = ALIGN(4) };
  }
}
EOF
