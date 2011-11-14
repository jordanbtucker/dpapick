import plistlib
from struct import unpack, pack, calcsize
import os, binascii

import CFPListErrors as errors
from CFTypes import *

CFPropertyListFormatBinary = 1
CFPropertyListFormatXML = 2
CFPropertyListFormatAuto = 0

class CFPropertyList(object):
    def __init__(self, fileName=None, format=CFPropertyListFormatAuto):
        self.file = fileName
        self.format = format
        self.value = None
    
    def load(self, fileName=None, format=None):
        fileName = fileName if fileName else self.file
        format = format if format else self.format
        
        if format == CFPropertyListFormatBinary:
            self.read_binary(fileName)
        if format == CFPropertyListFormatAuto:
            opened = False
            try:
                fp = open(fileName, 'rb')
                opened = True
            except TypeError:
                fp = fileName
            magic_number = fp.read(8)
            if magic_number == False:
                raise IOError('Could not read %s' % fileName)
            if opened: fp.close()
            
            filetype = magic_number[:6]
            version = magic_number[-2:]
            
            if filetype == 'bplist':
                if not version == '00':
                    raise errors.PListError('Wrong file format version for ' +
                        '%s. Expected 00, got %s' % (fileName, version))
                self.value = self.read_binary(fileName)
            else:
                format = CFPropertyListFormatXML
        if format == CFPropertyListFormatXML:
            pass
            # self.value = plistlib.readPlist(fileName)
    
    def read_binary(self, filename):
        opened = False
        try:
            fp = open(filename, 'rb')
            opened = True
        except TypeError:
            fp = filename

        # first, we read the trailer: 32 bytes from the end
        fp.seek(-32, os.SEEK_END)
        buff = fp.read(32)
            
        (offset_size, object_ref_size, number_of_objects, top_object, table_offset) = unpack('>6xBB4xL4xL4xL', buff)
    
        # after that, get the offset table
        fp.seek(table_offset, os.SEEK_SET)
        coded_offset_table = fp.read(number_of_objects * offset_size)
        if not len(coded_offset_table) == number_of_objects * offset_size:
            raise CFFormatError('%s: Format error!' % filename)
        
        
        # decode offset table
        format_unpackers = [
            lambda d: '',
            lambda d: star_unpack('>B', d),
            lambda d: star_unpack('>H', d),
            lambda d: None,
            lambda d: star_unpack('>L', d)
        ]
        self.offsets = format_unpackers[offset_size](coded_offset_table)
        
        self.unique_table = []
        self.object_ref_size = object_ref_size
        
        top = self.read_binary_object_at(filename, fp, top_object)
        if opened: fp.close()
        return top
    
    def read_binary_object_at(self, filename, fp, pos):
        '''
        Read an object type byte at position pos, decode it and delegate to
        the correct reader function
        '''
        position = self.offsets[pos]
        fp.seek(position, os.SEEK_SET)
        return self.read_binary_object(filename, fp)
    
    def read_binary_object(self, fname, fp):
        '''
        Read an object type byte, decode it and delegate to the correct reader
        function
        '''
        # first: read the marker byte
        buff = fp.read(1)
        
        object_length = star_unpack('>B', buff)
        object_length = object_length[0] & 0xF
        
        buff = buff.encode('hex')
        object_type = buff[0]
        
        if not object_type == '0' and object_length == 15:
            object_length = self.read_binary_object(fname, fp)
            object_length = object_length.value
        
        retval = None
        if object_type == '0': # null, false, true, fillbyte
            retval = self.read_binary_null_type(object_length)
        if object_type == '1': # integer
            retval = self.read_binary_int(fname,fp,object_length)
        if object_type == '2': # real
            retval = self.read_binary_real(fname,fp,object_length)
        if object_type == '3': # date
            retval = self.read_binary_date(fname,fp,object_length)
        if object_type == '4': # data
            retval = self.read_binary_data(fname,fp,object_length)
        if object_type == '5': # byte string, usually utf8 encoded
            retval = self.read_binary_string(fname,fp,object_length)
        if object_type == '6': # unicode string (utf16be)
            retval = self.read_binary_unicode_string(fname,fp,object_length)
        if object_type == 'a': # array
            retval = self.read_binary_array(fname,fp,object_length)
        if object_type == 'd': # dictionary
            retval = self.read_binary_dict(fname,fp,object_length)
        
        return retval

    def read_binary_null_type(self, length):
        '''
        read a "null" type (i.e. null byte, marker byte, bool value)
        '''
        if length == 0: return 0 # null byte
        elif length == 8: return CFBoolean(False)
        elif length == 9: return CFBoolean(True)
        elif length == 15: return 15 # fill type
        raise CFFormatError("unknown null type: #{length}")

    def read_binary_int(self, fname,fp,length):
        '''
        read a binary int value
        '''
        if length > 3:
            raise CFFormatError('Integer greater than 8 bytes: %s' % length)
    
        nbytes = 1 << length
        val = None
        buff = fp.read(nbytes)
    
        if length == 0:
            val = unpack('>B', buff)
            val = val[0]
        elif length == 1:
            val = unpack('>H', buff)
            val = val[0]
        elif length == 2:
            val = unpack('>L', buff)
            val = val[0]
        elif length == 3:
            (hiword,loword) = unpack('>LL', buff)
            if not (hiword & 0x80000000) == 0:
                # 8 byte integers are always signed, and are negative when bit
                # 63 is set. Decoding into either a Fixnum or Bignum is tricky,
                # however, because the size of a Fixnum varies among systems,
                # and Ruby doesn't consider the number to be negative, and
                # won't sign extend.
                val = -(2**63 - ((hiword & 0x7fffffff) << 32 | loword))
            else:
                val = hiword << 32 | loword
        
        return CFInteger(val)

    def read_binary_real(self, fname, fp, length):
        '''
        read a binary real value
        '''
        if length > 3:
            raise CFFormatError('Real greater than 8 bytes: %s' % length)
        
        nbytes = 1 << length
        val = None
        buff = fp.read(nbytes)
        
        if length == 0 or length == 1: # 1 or 2 byte float? must be an error
            raise CFFormatError('got %s byte float, must be an error!' % length+1)
        if length == 2:
            val = unpack('f',buff[::-1])
            val = val[0]
        if length == 3:
            val = unpack('d',buff[::-1])
            val = val[0]
        
        return CFReal(val)

    def read_binary_date(self, fname, fp, length):
        '''
        read a binary date value
        '''
        if length > 3:
            raise CFFormatError('Date greater than 8 bytes: %s' % length)
        
        nbytes = 1 << length
        val = None
        buff = fp.read(nbytes)
        
        if length == 0 or length == 1: # 1 or 2 byte float? must be an error
            raise CFFormatError('got %s byte CFDate, must be an error!' % length+1)
        if length == 2:
            val = unpack('f',buff[::-1])
            val = val[0]
        if length == 3:
            val = unpack('d',buff[::-1])
            val = val[0]
        
        return CFDate(val, CFDate.TIMESTAMP_APPLE)


    def read_binary_data(self, fname,fp,length):
        '''
        read a binary data value
        '''
        buff = ''
        if length > 0:
            buff = fp.read(length)
        return CFData(buff, CFData.DATA_RAW)

    def read_binary_string(self, fname,fp,length):
        '''
        read a binary string value
        '''
        buff = ''
        if length > 0:
            buff = fp.read(length)
    
        return CFString(buff)

    def read_binary_unicode_string(self, fname,fp,length):
        '''
        Read a unicode string value, coded as UTF-16BE
        '''
        # The problem is: we get the length of the string IN CHARACTERS;
        # since a char in UTF-16 can be 16 or 32 bit long, we don't really know
        # how long the string is in bytes
        
        buff = fp.read(2*length)
        buff = unicode(buff, 'utf-16be')
        buff = buff.encode('utf-8')
            
        return CFString(buff)

    def read_binary_array(self, fname,fp,length):
        '''
        read a binary array value, including contained objects
        '''
        array = []
        
        # first: read object refs
        if not length == 0:
            buff = fp.read(length * self.object_ref_size)
            if self.object_ref_size == 1:
                objects = star_unpack('>B', buff)
            else:
                objects = star_unpack('>H', buff)
            
            # and now read the objets
            for i in range(length):
                obj = self.read_binary_object_at(fname, fp, objects[i])
                array.append(obj)
    
        return CFArray(array)

    def read_binary_dict(self, fname,fp,length):
        '''
        read a dictionary value, including contained objects
        '''
        dic = {}
        
        if not length == 0:
            # first read the key refs
            buff = fp.read(length * self.object_ref_size)
            if self.object_ref_size == 1:
                keys = star_unpack('>B', buff)
            else:
                keys = star_unpack('>H', buff)
            
            # then the object refs
            buff = fp.read(length * self.object_ref_size)
            if self.object_ref_size == 1:
                objects = star_unpack('>B', buff)
            else:
                objects = star_unpack('>H', buff)
            
            # and finally the keys and objects
            for i in range(length):
                key = self.read_binary_object_at(fname, fp, keys[i])
                obj = self.read_binary_object_at(fname, fp, objects[i])
                dic[key] = obj
                
        return CFDictionary(dic)


def native_types(obj):
    if obj == None: return None
    
    if isinstance(obj, CFDate) or isinstance(obj, CFString) or isinstance(obj, CFInteger) or isinstance(obj, CFReal) or isinstance(obj, CFBoolean):
        return obj.value
    elif isinstance(obj, CFData):
        return obj.decoded_value
    elif isinstance(obj, CFArray):
        return [native_types(v) for v in obj.value]
    elif isinstance(obj, CFDictionary):
        hsh = {}
        for (k, v) in obj.value.items():
            hsh[k.value] = native_types(v)
        return hsh
        

def unpack_helper(fmt, data):
    size = calcsize(fmt)
    return unpack(fmt, data[:size]), data[size:]

def star_unpack(fmt, data):
    out = []
    while data:
        (b,), data = unpack_helper(fmt, data)
        out.append(b)
    return out
