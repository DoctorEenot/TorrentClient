
class bytesOutput:
    def __init__(self,data):
        self.already_read = 0
        self.data = data
    def read(self,size):
        if self.already_read >= len(self.data):
            return False
        #self.already_read += size
        if self.already_read + size > len(self.data):
            size = len(self.data) - self.already_read
        buf = self.data[self.already_read:self.already_read+size]
        self.already_read += size
        return buf
    def close(self):
        del self

class BencodeParser:
    def __init__(self,data,filename=True):
        '''
        if filename == True -> data is filename
        if filename == False -> data is bytes object of bencode to be parsed
        '''
        if filename:
            self.file = open(data,'rb')
        else:
            self.file = bytesOutput(data)

    def parse_Bencode(self):
        to_return = []
        data = self.file.read(1)
        while data:
            if data == b'i':
                to_return.append(self.parse_DInt())
            elif data == b'd':
                to_return.append(self.parse_BDict())
            elif data == b'l':
                to_return.append(self.parse_BList())
            else:
                to_return.append(self.parse_BString(data))
            data = self.file.read(1)
        self.file.close()
        return to_return
       

    def parse_BString(self,string_start):
        size = string_start
        data = self.file.read(1)
        while data != b':':
            size += data
            data = self.file.read(1)
            if not data:
                raise Exception('Problem with string')
        return self.file.read(int(size))

    def parse_DInt(self)->int:
        buf = b''
        data = self.file.read(1)
        while data != b'e' and data:
            buf += data
            data = self.file.read(1)
        return int(buf)
         
    def parse_BList(self):
        to_return = []
        data = self.file.read(1)
        while data != b'e':
            if data == b'i':
                to_return.append(self.parse_DInt())
            elif data == b'd':
                to_return.append(self.parse_BDict())
            elif data == b'l':
                to_return.append(self.parse_BList())
            else:
                to_return.append(self.parse_BString(data))
            data = self.file.read(1)
            if not data:
                raise Exception('Malformed list')
        return to_return

    def parse_BDict(self):
        to_return = {}
        data = self.file.read(1)
        while data != b'e':
            key = self.parse_BString(data)
            data = self.file.read(1)
            item = b''
            if data == b'i':
                item = self.parse_DInt()
            elif data == b'd':
                item = self.parse_BDict()
            elif data == b'l':
                item = self.parse_BList()
            else:
                item = self.parse_BString(data)
            
            to_return[str(key,encoding='utf-8')] = item
            data = self.file.read(1)

        return to_return



def str_bstr(data:str):
    buf = bytes(str(len(data)),'utf-8')+b':'+bytes(data,'utf-8')
    return buf

def bytes_bstr(data:bytes):
    return bytes(str(len(data)),'ascii')+b':'+data

def int_bint(data:int):
    return b'i'+bytes(str(data),'ascii')+b'e'



def list_blist(data:list):
    to_return = b'l'
    for element in data:
        if type(element) == int:
            to_return += int_bint(element)
        elif type(element) == str:
            to_return += str_bstr(element)
        elif type(element) == bytes:
            to_return += bytes_bstr(element)
        elif type(element) == list:
            to_return += list_blist(element)
        elif type(element) == dict:
            to_return += dict_bdict(element)
    return to_return+b'e'


def dict_bdict(data:dict):
    to_return = b'd'
    for key in sorted(data.keys()):
        to_return += str_bstr(key)
        if type(data[key]) == int:
            to_return += int_bint(data[key])
        elif type(data[key]) == str:
            to_return += str_bstr(data[key])
        elif type(data[key]) == bytes:
            to_return += bytes_bstr(data[key])
        elif type(data[key]) == list:
            to_return += list_blist(data[key])
        elif type(data[key]) == dict:
            to_return += dict_bdict(data[key])
    return to_return+b'e'

def encode(data):
    to_return = b''
    if type(data) == int:
        to_return += int_bint(data)
    elif type(data) == str:
        to_return += str_bstr(data)
    elif type(data) == bytes:
        to_return += bytes_bstr(data)
    elif type(data) == list:
        to_return += list_blist(data)
    elif type(data) == dict:
        to_return += dict_bdict(data)
    return to_return


if __name__ == '__main__':
    
    data = b'd1:ad2:id20:\xe7i\xac\x16\x85\xc8\\\x06\xdc\x9c\x14\x05;\xd2\xecCu?~\x9c9:info_hash20:\xd5\x000\x1e\x9d\xd39\x1f\x12\x1b7\x04\xf9\xbe\xb5\x91\x87\x8f\xd7\xf6e1:q9:get_peers1:t2:\x0b\xc61:v4:LT\x01\x021:y1:qe'
    #data = b'd1:d5:abcdte'
    pars = BencodeParser(data,False)
    enc = pars.parse_Bencode()
    print()

