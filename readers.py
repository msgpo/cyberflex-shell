try:
    import smartcard, smartcard.CardRequest
except ImportError:
    print >>sys.stderr, """Could not import smartcard module. Please install pyscard 
from http://pyscard.sourceforge.net/
If you can't install pyscard and want to continue using 
pycsc you'll need to downgrade to SVN revision 246.
"""
    raise
class Smartcard_Reader(object):
    def list_readers(cls):
        "Return a list of tuples: (reader name, implementing object)"
        return []
    list_readers = classmethod(list_readers)
    
    def connect(self):
        "Create a connection to this reader"
        raise NotImplementedError, "Please implement in a sub-class"
    
    def get_ATR(self):
        "Get the ATR of the inserted card as a binary string"
        raise NotImplementedError, "Please implement in a sub-class"

    def transceive(self, data):
        "Send a binary blob, receive a binary blob"
        raise NotImplementedError, "Please implement in a sub-class"

    def disconnect(self):
        "Disconnect from the card and release all resources"
        raise NotImplementedError, "Please implement in a sub-class"

class PCSC_Reader(Smartcard_Reader):
    def __init__(self, reader):
        self._reader = reader
        self._name = str(reader)
        self._cardservice = None
    
    name = property(lambda self: self._name, None, None, "The human readable name of the reader")
    
    def list_readers(cls):
        return [ (str(r), cls(r)) for r in smartcard.System.readers() ]
    list_readers = classmethod(list_readers)
    
    def connect(self):
        unpatched = False
        printed = False
        while True:
            try:
                if not unpatched:
                    cardrequest = smartcard.CardRequest.CardRequest( readers=[self._reader], timeout=0.1 )
                else:
                    cardrequest = smartcard.CardRequest.CardRequest( readers=[self._reader], timeout=1 )
                
                self._cardservice = cardrequest.waitforcard()
                self._cardservice.connection.connect()
                break
            except TypeError:
                unpatched = True
            except (KeyboardInterrupt, SystemExit):
                raise
            except smartcard.Exceptions.CardRequestException:
                if sys.exc_info()[1].message.endswith("Command timeout."):
                    if not printed:
                        print "Please insert card ..."
                        printed = True
                else:
                    raise
            except smartcard.Exceptions.CardRequestTimeoutException:
                if not printed:
                    print "Please insert card ..."
                    printed = True
            except smartcard.Exceptions.NoCardException:
                print "Card is mute or absent. Please retry."
    
    def get_ATR(self):
        return smartcard.util.toASCIIString(self._cardservice.connection.getATR())
    
    def get_protocol(self):
        hresult, reader, state, protocol, atr = smartcard.scard.SCardStatus( self._cardservice.connection.component.hcard )
        return ((protocol == smartcard.scard.SCARD_PROTOCOL_T0) and (0,) or (1,))[0]

    PROTOMAP = {
        0: smartcard.scard.SCARD_PCI_T0,
        1: smartcard.scard.SCARD_PCI_T1,
    }
    
    def transceive(self, data):
        data_bytes = map(lambda x: ord(x), data)
        data, sw1, sw2 = self._cardservice.connection.transmit(data_bytes, protocol=self.PROTOMAP[self.get_protocol()])
        result_binary = map(lambda x: chr(x), data + [sw1,sw2])
        return result_binary
    
    def disconnect(self):
        self._cardservice.connection.disconnect()
        del self._cardservice
        self._cardservice = None
    
class ACR122_Reader(Smartcard_Reader):
    """This class implements ISO 14443-4 access through the
    PN532 in an ACR122 reader with firmware version 1.x"""
    def list_readers(cls):
        pcsc_readers = PCSC_Reader.list_readers()
        readers = []
        for name, obj in pcsc_readers:
            if name.startswith("ACS ACR 38U-CCID"):
                reader = cls(obj)
                readers.append( (reader.name, reader) )
        return readers
    list_readers = classmethod(list_readers)
    
    name = property(lambda self: self._name, None, None, "The human readable name of the reader")
    
    def __init__(self, parent):
        self._parent = parent
        self._name = self._parent.name+"-RFID"
    
    def pn532_transceive_raw(self, command):
        c_apdu = "\xff\x00\x00\x00" + chr(len(command)) + command
        r_apdu = self._parent.transceive(c_apdu)
        
        if len(r_apdu) == 2 and r_apdu[0] == "\x61":
            c_apdu = "\xff\xc0\x00\x00" + r_apdu[1]
            r_apdu = self._parent.transceive(c_apdu)
        
        return r_apdu
    
    def pn532_transceive(self, command):
        response = self.pn532_transceive_raw(command)
        
        if len(response) < 2 or response[-2:] != ["\x90", "\x00"]:
            raise IOError, "Couldn't communicate with PN532"
        
        if not (response[0] == "\xd5" and ord(response[1]) == ord(command[1])+1 ): 
            raise IOError, "Wrong response from PN532"
        
        return "".join(response[:-2])
    
    def pn532_acquire_card(self):
        response = self.pn532_transceive("\xd4\x04")
        if ord(response[4]) > 0:
            return True
        else:
            response = self.pn532_transceive("\xd4\x4a\x01\x00")
            if ord(response[2]) > 0:
                return True
            else:
                response = self.pn532_transceive("\xd4\x4a\x01\x03")
                if ord(response[2]) > 0:
                    return True
    
    def connect(self):
        # FIXME Add loop or something similar to PCSC_Reader.connect
        self._parent.connect()
        self.pn532_acquire_card()
    
    def get_ATR(self):
        # FIXME Properly implement for PC/SC version 2
        return "\x3b\x80\x80\x01\x01"

    def transceive(self, data):
        # FIXME Properly determine target number
        response = self.pn532_transceive("\xd4\x40\x01" + data)
        if response[2] != "\x00":
            # FIXME Proper error processing
            raise IOError, "Error while transceiving"
        return response[3:]

    def disconnect(self):
        self._parent.disconnect()

def list_readers():
    "Collect readers from all known drivers"
    readers = PCSC_Reader.list_readers()
    readers.extend( ACR122_Reader.list_readers() )
    return readers

def connect_to(reader):
    "Open the connection to a reader"
    
    readerObject = None
    readers = list_readers()
    
    if isinstance(reader, int) or reader.isdigit():
        reader = int(reader)
        readerObject = readers[reader][1]
    else:
        for i, name, obj in readers:
            if str(name).startswith(reader):
                readerObject = obj
    
    if readerObject is None:
        readerObject = readers[0][1]
    
    print "Using reader: %s" % readerObject.name
    
    readerObject.connect()
    
    from utils import hexdump

    print "ATR:          %s" % hexdump(readerObject.get_ATR(), short = True)
    return readerObject

if __name__ == "__main__":
    list_readers()
    
