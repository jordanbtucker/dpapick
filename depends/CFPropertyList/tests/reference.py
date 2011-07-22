import sys
sys.path.append('..')
import CFPropertyList

def parsed_binary(filename):
    plist = CFPropertyList.CFPropertyList('reference/%s.plist' % filename)
    plist.load()
    return CFPropertyList.native_types(plist.value)