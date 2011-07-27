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
static int check_guid_utf16(char* guid,int length);

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

typedef struct {
    unsigned int     Data1;
    unsigned short   Data2;
    unsigned short   Data3;
    unsigned char    Data4[8];
} DGUID; //<16 bytes>

typedef struct {
    unsigned int   dwRevision;
    DGUID    	   gProvider;
    unsigned int   cbMkeys;
    DGUID          *gMkeys;
    unsigned int   dwFlags;
    unsigned int   cbDescr;
    unsigned char  *wszDescr;
    unsigned int   idCipher;
    unsigned int   dwKey;
    unsigned int   cbData;
    DGUID    	   *pbData;
    unsigned int   cbStrong;
    DGUID    	   *pbStrong;
    unsigned int   idHash;
    unsigned int   cbHash;
    unsigned int   cbSalt;
    DGUID    	   *pbSalt;
    unsigned int   cbCiphertext;
    DGUID    	   *pbCiphertext;
    unsigned int   cbHmac;
    DGUID    	   *pbHmac;
} DPAPIBlob; //<size=sizeOfBlob>;


static void register_header_check_blob_dpapi(file_stat_t *file_stat)
{


  register_header_check(0, blob_dpapi_header,sizeof(blob_dpapi_header), &header_check_blob_dpapi, file_stat);


}



static int header_check_blob_dpapi(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  
    DPAPIBlob db;
    int size = 0;
  
    if(memcmp(buffer,blob_dpapi_header,sizeof(blob_dpapi_header))==0)
    {
	memcpy(&db.dwRevision,buffer+size,sizeof(unsigned int));
	size += sizeof(unsigned int);
	memcpy(&db.gProvider,buffer+size,sizeof(DGUID));
	size += sizeof(DGUID);    
	
	memcpy(&db.cbMkeys,buffer+size,sizeof(unsigned int));
	size += sizeof(unsigned int);
	//memcpy(db.gMkeys,buffer+size,sizeof(DGUID)*db.cbMkeys);
	size += sizeof(DGUID)*db.cbMkeys;

	memcpy(&db.dwFlags,buffer+size,sizeof(unsigned int));
	size += sizeof(unsigned int);
	memcpy(&db.cbDescr,buffer+size,sizeof(unsigned int));
	size += sizeof(unsigned int);
	
	memcpy(&db.wszDescr,buffer+size,sizeof(unsigned char)* (db.cbDescr >> 1) * 2);
	size += sizeof(unsigned char)* (db.cbDescr >> 1) * 2;
	
	// Verification que nous avons bien de l'UTF-16
	if (!check_guid_utf16(&db.wszDescr,sizeof(unsigned char)* (db.cbDescr >> 1) * 2))
	{
	  return 0;
	}

	
	memcpy(&db.idCipher,buffer+size,sizeof(unsigned int));
	size += sizeof(unsigned int);
	//memcpy(db.dwKey,buffer+size,sizeof(unsigned int));
	size += sizeof(unsigned int);


	memcpy(&db.cbData,buffer+size,sizeof(unsigned int));
	size += sizeof(unsigned int);
//	memcpy(&db.pbData,buffer+size,sizeof(DGUID)*db.cbData);
	size += sizeof(DGUID)*db.cbData;
		

	memcpy(&db.cbStrong,buffer+size,sizeof(unsigned int));
	size += sizeof(unsigned int);
//	memcpy(&db.pbStrong,buffer+size,sizeof(DGUID)*db.cbStrong);
	size += sizeof(DGUID)*db.cbData;
		
	memcpy(&db.idHash,buffer+size,sizeof(unsigned int));
	size += sizeof(unsigned int);	

	memcpy(&db.cbHash,buffer+size,sizeof(unsigned int));
	size += sizeof(unsigned int);		

	memcpy(&db.cbSalt,buffer+size,sizeof(unsigned int));
	size += sizeof(unsigned int);			
//	memcpy(&db.pbSalt,buffer+size,sizeof(DGUID)*db.cbSalt);
	size += sizeof(DGUID)*db.cbSalt;

	memcpy(&db.cbCiphertext,buffer+size,sizeof(unsigned int));
	size += sizeof(unsigned int);				
//	memcpy(&db.pbCiphertext,buffer+size,sizeof(DGUID)*db.cbCiphertext);
	size += sizeof(DGUID)*db.cbCiphertext;
	

	memcpy(&db.cbHmac,buffer+size,sizeof(unsigned int));
	size += sizeof(unsigned int);				
//	memcpy(&db.pbHmac,buffer+size,sizeof(DGUID)*db.cbHmac);
	size += sizeof(DGUID)*db.cbHmac;
	
	
	reset_file_recovery(file_recovery_new);
	file_recovery_new->min_filesize=16;
	file_recovery_new->calculated_file_size=size;
	file_recovery_new->extension=file_hint_blob_dpapi.extension;
	return 1;
    }
    return 0;
}


//
// Code rapide, verifie seulement si c'est une chaine en 
// utf-16
//
static int check_guid_utf16(char* candidate,int size)
{
  int i=0;
  for (i=0;i<size-2;i=i+2)
//   fprintf(pFile,"%c ",candidate[i]);    
    if (!((candidate[i]!=0x00) && (candidate[i+1]==0x00)))
      return 0;
//    fprintf(pFile,"\n");


  return 1;
}


