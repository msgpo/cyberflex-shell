import utils
from gsm_card import *
import building_blocks

class GRCard_Card(GSM_Card):
    DRIVER_NAME = ["GRCard"]
    ATRS = [ 
        ("3b991800118822334455667760", None),
    ]

    DF_ALGO = "\x27\x00"
    EF_ALGO = "\x6f\x70"

    APDU_ERASE_CARD = C_APDU(CLA=0x80, INS=0xFE, data="123456\x00\x00\x13\x01\xFF\x00\x00\x00\x00\x00\x00\x00\x00\xEA")
    APDU_SET_KI = C_APDU(CLA=0x80, INS=0xD4, P1=0x02)
    APDU_SET_PINPUK = C_APDU(CLA=0x80, INS=0xD4)

    def cmd_set_algo(self, algo):
	"""Set the COMP128 version to be used as A3/A8 algorithm in the card."""
	self.select_file(0, 0, self.DF_ALGO)
	self.select_file(0, 0, self.EF_ALGO)
	self.cmd_upd_binary(algo)

    def cmd_erase_card(self):
	"""Erase the entire card including all DF and EF."""
	self.send_apdu(self.APDU_ERASE_CARD)

    def cmd_set_ki(self, ki):
	"""Set the Ki to be used by the A3/A8 algorithm."""
        ki_bin = binascii.a2b_hex("".join(ki.split()))
	apdu = C_APDU(self.APDU_SET_KI, data = ki_bin)
	self.send_apdu(apdu)

    def set_pin_puk(self, pin_num, pin, puk):
	data_bin = self.pad(pin, 8) + self.pad(puk, 8)
	apdu = C_APDU(self.APDU_SET_PINPUK, P2 = pin_num, data = data_bin)
	self.send_apdu(apdu)

    def cmd_set_pin_puk(self, pin_num, pin, puk):
	"""Set the PIN + PUK (1 or 2)."""
	self.set_pin_puk(int(pin_num, 0), pin, puk)
	
    def pad(self, data, padded_len):
        topad = padded_len - len(data)
	if topad <= 0:
	    return data
        return data + ("\xFF" * topad)
 
    COMMANDS = {}
    COMMANDS.update(GSM_Card.COMMANDS)
    COMMANDS.update({
	"grcard_set_algo" : cmd_set_algo,
	"grcard_erase_card" : cmd_erase_card,
	"grcard_set_ki" : cmd_set_ki,
        "grcard_set_pin_puk" : cmd_set_pin_puk,
    })
