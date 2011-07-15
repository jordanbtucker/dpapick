/*

    File: file_blobdpapi.c

    Copyright (C) 2010, 2011 Ivan Fontarensky <ivan.fontarensky@cassidian.com>

    This software is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
  
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
  
    You should have received a copy of the GNU General Public License along
    with this program; if not, write the Free Software Foundation, Inc., 51
    Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


   
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "common.h"
#include "filegen.h"


static void register_header_check_blob_dpapi(file_stat_t *file_stat);
static int header_check_blob_dpapi(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);

const file_hint_t file_hint_blob_dpapi= {
  .extension="blobdpapi",
  .description="Windows Blob DPAPI",
  .min_header_distance=0,
  .max_filesize=1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_blob_dpapi
};

static const unsigned char blob_dpapi_header[20] = {0x01,0x00,0x00,0x00,0xd0,0x8c,0x9d,0xdf,0X01,0x15,0xd1,0x11,0x8c,0x7a,0x00,0xc0,0x4f,0xc2,0x97,0xeb};


static void register_header_check_blob_dpapi(file_stat_t *file_stat)
{





  register_header_check(0, blob_dpapi_header,sizeof(blob_dpapi_header), &header_check_blob_dpapi, file_stat);


}



static int header_check_blob_dpapi(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{



  if(memcmp(buffer,blob_dpapi_header,sizeof(blob_dpapi_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->min_filesize=0x1000,
    file_recovery_new->extension=file_hint_blob_dpapi.extension;
    return 1;
  }
  return 0;
}



