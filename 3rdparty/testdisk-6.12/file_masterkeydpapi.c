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


static void register_header_check_mk_dpapi(file_stat_t *file_stat);
static int header_check_mk_dpapi(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new);
static int check_guid_utf16(char* guid,int length);

const file_hint_t file_hint_mk_dpapi= {
  .extension="mkdpapi",
  .description="Windows Master Key DPAPI",
  .min_header_distance=0,
  .max_filesize=1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_mk_dpapi
};

static const unsigned char mk_dpapi_header[12] = {0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0X00,0x00,0x00,0x00};

typedef struct {
    unsigned int   dwRevision;
    unsigned int   dwUnk[2];
    unsigned char  wszGUID[72];
    unsigned int   dwUnk2[2];
    unsigned int   dwFlags;
    unsigned long int   cbMasterKey;
    unsigned long int   cbBackupKey;
    unsigned long int   cbCredhist;
    unsigned long int   cbDomainKey;
} MasterkeyHeader;// <size=128>;

typedef struct {
    unsigned int  dwRevision;
    unsigned char pbIV[16];
    unsigned int  dwRounds;
    unsigned int  idHash;
    unsigned int  idCipher;
} MkeyHeader;// <size=32>;



FILE* pFile;

static void register_header_check_mk_dpapi(file_stat_t *file_stat)
{


   register_header_check(0, mk_dpapi_header,sizeof(mk_dpapi_header), &header_check_mk_dpapi, file_stat);



}



static int header_check_mk_dpapi(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{

/*
 pFile = fopen ("___debug___mkk2.txt","a");



  fprintf(pFile,"+header_check_mk_dpapi\n");
*/


  if(memcmp(buffer,mk_dpapi_header,sizeof(mk_dpapi_header))==0)
  {
    reset_file_recovery(file_recovery_new);
    file_recovery_new->min_filesize=0x1000,
    file_recovery_new->extension=file_hint_mk_dpapi.extension;
    
    MasterkeyHeader mkh;
    MkeyHeader mkeyHead;

    int size = 0;

    memcpy(&mkh,buffer,sizeof(MasterkeyHeader));
    size = sizeof(MasterkeyHeader);


 
    // Verification que nous avons bien un guid
    if (!check_guid_utf16(&mkh.wszGUID,72))
    {
      return 0;
    }

/*

    if (mkh.cbMasterKey > 0) 
    {
	memcpy(&mkeyHead,buffer+size,sizeof(MkeyHeader));    
	size += sizeof(MkeyHeader);
	size += mkh.cbMasterKey - sizeof (MkeyHeader);
    }
    if (mkh.cbBackupKey > 0) 
    {
        memcpy(&mkeyHead,buffer+size,sizeof(MkeyHeader));                   
	size += sizeof(MkeyHeader);
	size += mkh.cbBackupKey - sizeof (MkeyHeader);
    }

*/
         
/*
    fprintf(pFile,"dwRevision=%X\n",mkh.dwRevision);
    fprintf(pFile,"dwFlags=%X\n",mkh.dwFlags);
    fprintf(pFile,"GUID=%c%c%c\n",mkh.wszGUID[0],mkh.wszGUID[2],mkh.wszGUID[4]);
    fprintf(pFile,"idHash=%X\n",mkeyHead.idHash);
*/





//    fclose(pFile);    
    return 1;
  }

//  pclose(pFile);
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
    fprintf(pFile,"%c ",candidate[i]);    
    if (!((candidate[i]!=0x00) && (candidate[i+1]==0x00)))
      return 0;
    fprintf(pFile,"\n");


  return 1;
}
