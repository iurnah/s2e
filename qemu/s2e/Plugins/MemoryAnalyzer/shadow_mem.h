/**********************************************************************************************
*      This file is part of REWARDS, A Data Structure Reverse Engineering System.             *
*                                                                                             *
*      REWARDS is owned and copyright (C) by Lab FRIENDS at Purdue University, 2009-2010.     *
*      All rights reserved.                                                                   *
*      Do not copy, disclose, or distribute without explicit written                          *
*      permission.                                                                            *
*                                                                                             *
*      Author: Zhiqiang Lin <zlin@cs.purdue.edu>                                              *
**********************************************************************************************/
#ifndef __UTILITY_H
#define __UTILITY_H

#define VGM_BYTE_INVALID   0xFF
#include <inttypes.h>

typedef struct _mem_tag_t {
	uint32_t pc;
	uint32_t time_stamp;
} mem_tag_t;

extern void init_shadow_memory(void);

#ifdef CPLUSPLUS
extern "C" {
#endif
	extern void set_mem_shadow_tag(uint32_t a, mem_tag_t *t);
	extern void get_mem_shadow_tag(uint32_t a, mem_tag_t *t);

#ifdef CPLUSPLUS
}
#endif
#endif
