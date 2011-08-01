# CFPropertyList Python implementation

Contains classes to read binary property list files as [defined by
Apple][man(5) plist]. It's a (at this point partial) port of Christian Kruse's
[CFPropertyList for Ruby][ruby] with a few peeks at Rodney Rehm's
[CFPropertyList for PHP][php].

## Future

The ability to read XML plists will be added as well as the ability to write to
both binary and XML plists. Soon.

## Example

    import CFPropertyList
    
    # read a binary plist in as native types
    plist = CFPropertyList.CFPropertyList('example.plist')
    plist.load()
    data = CFPropertyList.native_types(plist.value)

[man(5) plist]:http://developer.apple.com/documentation/Darwin/Reference/ManPages/man5/plist.5.html
[ruby]:http://github.com/ckruse/CFPropertyList
[php]:http://github.com/rodneyrehm/CFPropertyList

## License

CFPropertyList is made available under the terms of the MIT License.

Copyright (c) 2010 Ben Cochran (http://bencochran.com)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

