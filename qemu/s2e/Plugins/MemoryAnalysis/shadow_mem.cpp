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

#include "shadow_mem.h"
#include <stdlib.h>
/*---------------------shadow memory----------------------*/
#define PAGE_SIZE 65536
#define PAGE_NUM 262144

#define IS_DISTINGUISHED_SM(smap) \
   ((smap) == &distinguished_secondary_map)

#define ENSURE_MAPPABLE(map, addr)                              \
   do {                                                           \
      if (IS_DISTINGUISHED_SM(map[(addr) >> 16])) {       \
         map[(addr) >> 16] = alloc_secondary_map; \
      }                                                           \
   } while(0)

#define ENSURE_MAPPABLE_BYTE_GRANUITY(map,addr)         \
   do {                                                           \
      if (IS_DISTINGUISHED_SM(map[(addr)&0x03][(addr) >> 16])) {    \
          map[(addr)&0x03][(addr) >> 16] = alloc_secondary_map(); \
      }                                                           \
   } while(0)

typedef struct {
	uint8_t byte[PAGE_SIZE];
} SecMap;

static SecMap distinguished_secondary_map;

static SecMap *ii_inst_addr_map[4][PAGE_NUM];
static SecMap *ii_time_stamp_map[4][PAGE_NUM];

unsigned int shadow_bytes;

void init_shadow_memory(void)
{
	int32_t i, j;

	for (i = 0; i < PAGE_SIZE; i++)
		distinguished_secondary_map.byte[i] = VGM_BYTE_INVALID;	//0xff

	for (j = 0; j < 4; j++)
		for (i = 0; i < PAGE_NUM; i++) {
			ii_inst_addr_map[j][i] = &distinguished_secondary_map;
			ii_time_stamp_map[j][i] = &distinguished_secondary_map;
		}
}

static SecMap *alloc_secondary_map()
{
	SecMap *map;
	uint32_t i;

	/* Mark all bytes as invalid access and invalid value. */
	map = (SecMap *) malloc(sizeof(SecMap));
	shadow_bytes += sizeof(SecMap);
	for (i = 0; i < 65536; i++)
		map->byte[i] = VGM_BYTE_INVALID;	/* Invalid Value */

	return map;
}

static uint32_t get_mem_ins_addr(uint32_t a)
{
	SecMap *sm;
	sm = ii_inst_addr_map[a & 0x3][a >> 16];

	uint32_t sm_off = a & 0xFFFF;
	return ((uint32_t *) (sm->byte))[sm_off >> 2];
}

static void set_mem_ins_addr(uint32_t a, uint32_t bytes)
{
	SecMap *sm;
	uint32_t sm_off;
	ENSURE_MAPPABLE_BYTE_GRANUITY(ii_inst_addr_map, a);
	sm = ii_inst_addr_map[a & 0x03][a >> 16];

	sm_off = a & 0xFFFF;
	((uint32_t *) (sm->byte))[sm_off >> 2] = bytes;
}

static uint32_t get_mem_time_stamp(uint32_t a)
{
	SecMap *sm;
	sm = ii_time_stamp_map[a & 0x3][a >> 16];

	uint32_t sm_off = a & 0xFFFF;
	return ((uint32_t *) (sm->byte))[sm_off >> 2];
}

static void set_mem_time_stamp(uint32_t a, uint32_t bytes)
{
	SecMap *sm;
	uint32_t sm_off;
	ENSURE_MAPPABLE_BYTE_GRANUITY(ii_time_stamp_map, a);
	sm = ii_time_stamp_map[a & 0x3][a >> 16];

	sm_off = a & 0xFFFF;
	((uint32_t *) (sm->byte))[sm_off >> 2] = bytes;
}

////////////////////////////////////////////////////////////
// Export function
///////////////////////////////////////////////////////////

void set_mem_shadow_tag(uint32_t a, mem_tag_t *t)
{
	set_mem_ins_addr(a, t->pc);
	set_mem_time_stamp(a, t->time_stamp);
}

void get_mem_shadow_tag(uint32_t a, mem_tag_t * t)
{
	(*t).pc= get_mem_ins_addr(a);
	(*t).time_stamp = get_mem_time_stamp(a);
}
