import r2pipe

class GoLangHelper:

    def __init__(self,r2):
        self.r2 = r2
        self.PTR_SIZE = self.r2.cmdj('ij')['bin']['bits'] // 8
        self.gop = None


    def is_gopclntab_defined(self, sections):
        for section in sections:
            if section['name'] == '.gopclntab':
                return section
        return False


    def get_gopclntab(self):
        sections = self.r2.cmdj('iSj')
        has_gop = self.is_gopclntab_defined(sections)
        if has_gop:
            print("gopclntab is defined")
            self.gop = has_gop['vaddr']
            return self.gop
        else:
            print("gopclntab not defined, searching...")
            self.gop = self.find_gopclntab()
            return self.gop


    def find_gopclntab(self):
        magic = 'fbffffff'
        results = self.r2.cmdj('/xj {}'.format(magic))
        for r in results:
            is_gop = self.is_gopclntab(r['offset'])
            if is_gop:
                print('found gopclntab')
                return r['offset']
        print('gopclntab not found')
        return None


    def get_pointer(self, addr, size=None):
        if size:
            return int(self.r2.cmd('pv{} @ {}'.format(size, addr)),16)
        else:
            return int(self.r2.cmd('pv @ {}'.format(addr)),16)


    def is_gopclntab(self, offset):
       entry = self.get_pointer(offset+8+self.PTR_SIZE)
       entry_offset = self.get_pointer(offset+8+self.PTR_SIZE*2)
       entry_loc = self.get_pointer(offset+entry_offset)
       if entry == entry_loc:
           return True
       return False


    def rename_functions(self):
        base = self.gop
        size_addr = base + 8
        size = self.get_pointer(size_addr)
        start = size_addr + self.PTR_SIZE
        end = base + (size * self.PTR_SIZE * 2)

        for addr in range(start, end, (2*self.PTR_SIZE)):
            func_addr = self.get_pointer(addr)
            offset = self.get_pointer(addr + self.PTR_SIZE)
            name_str_off = self.get_pointer(base + offset + self.PTR_SIZE)
            name_addr = base + name_str_off
            name = self.r2.cmd('psz @ {}'.format(name_addr))
            name = self.format_name(name)
            if name and len(name) > 2:
                print('Found name {} at 0x{:x}'.format(name, func_addr))
                funcinfo = self.r2.cmdj('afij {}'.format(func_addr))
                self.r2.cmd('af{} {} {}'.format('n' if funcinfo else '',
                                                name, func_addr))


    def format_name(self, name):
        name = name.replace('(', '')
        name = name.replace(')', '')
        name = name.replace('*', '')
        name = name.replace('/', '.')
        name = name.replace(' ', '.')
        name = name.replace(';', '.')
        name = name.replace(',', '.')
        return name.strip()


if __name__ == '__main__':
    r2 = r2pipe.open()
    helper = GoLangHelper(r2)
    gopclntab = helper.get_gopclntab()
    print(gopclntab)
    helper.rename_functions()
