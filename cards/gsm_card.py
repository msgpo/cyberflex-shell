import utils
from iso_card import *
import building_blocks

class GSM_Card(building_blocks.Card_with_read_binary,ISO_Card):
    DRIVER_NAME = ["GSM"]
    COMMAND_GET_RESPONSE = C_APDU("\xa0\xC0\x00\x00")
    CLA = 0xA0
    APDU_GET_RESPONSE = C_APDU(cla=CLA,ins=0xC0)
    APDU_RUN_GSM_ALGO = C_APDU(cla=CLA,ins=0x88)
    APDU_VERIFY_PIN = C_APDU(cla=CLA,ins=0x20)

    APDU_SELECT_FILE = C_APDU(cla=CLA,ins=0xA4)
    APDU_READ_BINARY = C_APDU(cla=CLA,ins=0xB0)
    APDU_STATUS = C_APDU(cla=CLA,ins=0xF2)
    APDU_UPD_BINARY = C_APDU(cla=CLA,ins=0xD6)
    APDU_UPD_RECORD = C_APDU(cla=CLA,ins=0xDC)

    # TS 11.14 / STK related
    APDU_TERMINAL_PROFILE = C_APDU(cla=CLA,ins=0x10)
    APDU_ENVELOPE = C_APDU(cla=CLA,ins=0xC2)
    APDU_FETCH = C_APDU(cla=CLA,ins=0x12)
    APDU_TERMINAL_RESPONSE = C_APDU(cla=CLA,ins=0x14)

    STATUS_MAP = {
        Card.PURPOSE_GET_RESPONSE: ("9F??", )
    }

    INTERESTING_DFS = [
        ("DF.GSM", "\x7f\x20"),
        ("DF.TELECOM", "\x7f\x10"),
    ]

    # Files at the GSM application level
    GSM_DFS = [
        ("LP", "\x6f\x05", "Language Preference"),
        ("IMSI", "\x6f\x07", "IMSI"),
        ("Kc","\x6f\x20", "Ciphering Key Kc"),
        ("PLMNsel", "\x6f\x30", "PLMN selector"),
        ("HPPLMN", "\x6f\x31", "Higher Priority PLMN search period"),
        ("ACMmax", "\x6f\x37", "ACM maximum value"),
        ("SST", "\x6f\x38", "SIM service table"),
        ("ACM", "\x6f\x39", "Accumulated call meter"),
        ("GID1", "\x6f\x3e", "Group Identifier Level 1"),
        ("GID2", "\x6f\x3f", "Group Identifier Level 2"),
        ("SPN", "\x6f\x46", "Service Provider Name"),
        ("PUCT", "\x6f\x41", "Price per unit and currency table"),
        ("CBMI", "\x6f\x45", "Cell broadcast message identifier selection"),
        ("BCCH", "\x6f\x74", "Broadcast control channels"),
        ("ACC", "\x6f\x78", "Access control class"),
        ("FPLMN", "\x6f\x7b", "Forbidden PLMNs"),
        ("LOCI", "\x6f\x7e", "Location Information"),
        ("AD", "\x6f\xAD", "Administrative Data"),
        ("Phase", "\x6f\xAE", "Phase identification"),
        ("VGCS", "\x6f\xB1", "Voice Group Call Service"),
        ("VGCSS", "\x6f\xB2", "Voice Group Call Service Status"),
        ("VBS", "\x6f\xB3", "Voice Broadcast Service"),
        ("VBSS", "\x6f\xB4", "Voice Broadcast Service Status"),
        ("eMLPP", "\x6f\xB5", "enhanced Multi Level Pre-emptyion and Priority"),
        ("AAeM", "\x6f\xB5", "Authomatic Answer for eEMLPP Service"),
        ("CBMID", "\x6f\x48", "Cell Broadcast Message Identifier for Data Download"),
        ("ECC", "\x6f\xB7", "Emergency Call Codes"),
        ("CBMIR", "\x6f\x50", "Cell broadcast message identifier range selection"),
        ("DCK", "\x6f\x2C", "De-personalization Control Keys"),
        ("CNL", "\x6f\x32", "Co-operative Network List"),
        ("NIA", "\x6f\x51", "Network's Indication of Alerting"),
        ("KcGPRS", "\x6f\x52", "GPRS Ciphering Key KcGPRS"),
        ("LOCIGPRS", "\x6f\x53", "GPRS Location Information"),
        ("SUME", "\x6f\x54", "SetUpMenu Elements"),
        ("PLMNwAcT", "\x6f\x60", "User controlled PLMN Selector with Access Technology"),
        ("OPLMNwAcT", "\x6f\x51", "Operator controlled PLMN Selector with Access Technology"),
        ("HPLMNwAcT", "\x6f\x62", "HPLMN Selector with Access Technology"),
        ("CPBCCH", "\x6f\x63", "CPBCCH Information"),
        ("InvScan", "\x6f\x64", "Investigation Scan"),
    ]

    # According to TS 11.11 Chapter 9.3
    type_of_file_names = { 0: 'RFU', 1: 'MF', 2: 'DF', 4: 'EF' }
    struct_of_file_names = { 0: 'transparent',
                             1: 'linear fixed',
                             2: 'transparent',
                             3: 'cyclic' }
    acc_cond_names = {   0: 'ALWAYS',
                             1: 'CHV1',
                         2: 'CHV2',
                         3: 'RFU',
                         4: 'ADM1',
                         5: 'ADM2',
                         6: 'ADM3',
                         7: 'ADM4',
                         8: 'ADM5',
                         9: 'ADM6',
                        10: 'ADM7',
                        11: 'ADM8',
                        12: 'ADM9',
                        13: 'ADM10',
                        14: 'ADM11',
                        15: 'NEW' }
    ATRS = [ 
        ("3bff9500ffc00a1f438031e073f62113574a334861324147d6", None),
        ("3b9a940092027593110001020200", None),
        ("3b989400939114010c020102", None),
        #("3b991800118822334455667760", None),
        #("3bdf96ff80b1fe451fc78031e073fe21136791150103040404ef", None),
    ]

    def before_send(self, apdu):
        if apdu.cla == 0x00:
            apdu.CLA = self.CLA

        return apdu

    def cmd_run_gsm_algo(self, rand):
        """Perform the GSM A3/A8 algorithm.
        RAND is the random challenge to be sent to the card."""
        if len(rand) != 16:
            rand2 = binascii.a2b_hex("".join(rand.split()))
        else:
            rand2 = rand

        if len(rand2) != 16:
            raise TypeError, "Need either exactly 16 binary bytes or 16 hexedecimal bytes for the RAND argument."

        apdu = C_APDU(self.APDU_RUN_GSM_ALGO,
            p1 = 0, p2 = 0, data = rand2)

        result = self.send_apdu(apdu)

        return result

    def cmd_cd_gsm(self):
        """Change into DF.GSM."""
        apdu = C_APDU(self.APDU_SELECT_FILE, data = "\x7f\x20")
        result = self.send_apdu(apdu)
        return result

#    def cmd_cd(self, dir = None):
#        fid = None
#        for n, f in self.INTERESTING_FILES:
#            if n == dir:
#                fid = f
#                break
#       if fid is None:
#            return ISO_7816_4_Card.cmd_cd(self, dir)
#       else:
#            return ISO_7816_4_Card.change_dir(self, fid)

    def change_dir(self, fid = None):
        "Change to a child DF. Alternatively, change to MF if fid is None."
	if fid is None:
	    return self.select_file(0, 0, "\x3f\x00")
	else:
	    return self.select_file(0, 0, fid)

    def cmd_status(self):
        """STATUS Command."""
        apdu = C_APDU(self.APDU_STATUS, data="\xff")
        result = self.send_apdu(apdu)
        if len(result.data) > 0:
            print utils.hexdump(result.data)
            print self.sel_ret_decode(result.data)

    def cmd_term_prof(self, data):
        """TERMINAL PROFILE Command."""
        apdu = C_APDU(self.APDU_TERMINAL_PROFILE, data = data)
        return self.send_apdu(apdu)

    def cmd_envelope(self, data):
        """ENVELOPE Command."""
        apdu = C_APDU(self.APDU_ENVELOPE, data = data)
        return self.send_apdu(apdu)

    def cmd_fetch(self, data):
        """FETCH Command."""
        apdu = C_APDU(self.APDU_FETCH, data = data)
        return self.send_apdu(apdu)

    def cmd_term_resp(self, data):
        """TERMINAL RESPONSE Command."""
        apdu = C_APDU(self.APDU_TERMINAL_RESPONSE, data = data)
        return self.send_apdu(apdu)

    def cmd_upd_binary(self, data):
        """Write to a transparent binary file."""
        data_bin = binascii.a2b_hex("".join(data.split()))
        apdu = C_APDU(self.APDU_UPD_BINARY, data = data_bin)
	return self.send_apdu(apdu)

    def cmd_selectfile(self, fid):
        """Select a file on the card."""

        fid = binascii.a2b_hex("".join(fid.split()))

        result = self.select_file(0, 0, fid)
        if len(result.data) > 0:
            print utils.hexdump(result.data)
            print self.sel_ret_decode(result.data)

    def sel_ret_decode(self, data):
        #print "File: %s" % (data[
        type_of_file = ord(data[6])
        print "Type of File: %s" % (self.type_of_file_names[type_of_file])
        if type_of_file == 4:
            structure = ord(data[12])
            print "Structure of File: %s" % (self.struct_of_file_names[structure])
            if structure == 3:
                if ord(data[7]) & 0x80:
                        print "INCREASE allowed"
                else:
                        print "INCREASE not allowed"
            if structure == 1 or structure == 3:
                print "Record size: %u bytes" % ord(data[14])
            #print "File Size: %u bytes" %
            acc_cond = data[8:11]
            self.acc_cond_decode(acc_cond)
            status = ord(data[11])
            if not status & 0x1:
                print "Status: invalidated, "
                if not status & 0x4:
                    print "not "
                print "readable and updatable\n"
        elif type_of_file == 2:
            #print "Total unallocated memory in DF: %u bytes"
            gsm_spec_data = data[13:]
            print "Number of DFs : %u" % (ord(gsm_spec_data[1]))
            print "Number of EFs : %u" % (ord(gsm_spec_data[2]))
            print "Number of CHV : %u" % (ord(gsm_spec_data[3]))
            print "CHV1 status         : %s" % (self.chv_status_decode(gsm_spec_data[5]))
            print "UNBLOCK CHV1 status : %s" % (self.chv_status_decode(gsm_spec_data[6]))
            print "CHV2 status         : %s" % (self.chv_status_decode(gsm_spec_data[7]))
            print "UNBLOCK CHV2 status : %s" % (self.chv_status_decode(gsm_spec_data[8]))

    def chv_status_decode(self, s):
        status = ord(s)
        if status & 0x80:
            initialized = 1
        else:
            initialized = 0
        return "Initialized: %u, Retries remaining: %u" % (initialized, status & 0xf)

    def acc_cond_decode(self, acc_cond):
        print "Access cond. READ/SEEK   : %s" % (self.acc_cond_names[ord(acc_cond[0]) >> 4])
        print "Access cond. UPDATE      : %s" % (self.acc_cond_names[ord(acc_cond[0]) & 0xf])
        print "Access cond. INCREASE    : %s" % (self.acc_cond_names[ord(acc_cond[1]) >> 4])
        print "Access cond. REHABILITATE: %s" % (self.acc_cond_names[ord(acc_cond[2]) >> 4])
        print "Access cond. INVALIDATE  : %s" % (self.acc_cond_names[ord(acc_cond[2]) & 0xf])


    COMMANDS = dict(Card.COMMANDS)
    COMMANDS.update(building_blocks.Card_with_read_binary.COMMANDS)
    COMMANDS.update({
        "gsm_run_algo" : cmd_run_gsm_algo,
        #"cd" : cmd_cd,
        "cd_df_gsm" : cmd_cd_gsm,
        "gsm_status" : cmd_status,
        # STK
        "gsm_terminal_profile" : cmd_term_prof,
        "gsm_envelope" : cmd_envelope,
        "gsm_fetch" : cmd_fetch,
        "gsm_terminal_response" : cmd_term_resp,
        "gsm_select_file" : cmd_selectfile,
	"update_binary" : cmd_upd_binary,
    })
    
    STATUS_WORDS = {
        # TS 11.11 Chapter 9.4.1
        #'9000': "Normal ending of the command"
        #'91??': "Normal ending of the command, with extra information from proactive SIM"
        '9E??': "Length '$(SW2)i (0x$(SW2)02x)' of the response data in case of SIM data dl error",
        '9F??': "Length '%(SW2)i (0x%(SW2)02x)' of the response data",
        # TS 11.11 Chapter 9.4.2
        '9300': "SIM Application Toolkit busy",
        # TS 11.11 Chapter 9.4.3
        '920?': lambda sw1, sw2: "Update successful but after using an internal retry routine '%i' times" % (sw2 % 16),
        '9240': "Memory problem",
        # TS 11.11 Chapter 9.4.4
        '9400': "No EF selected",
        '9402': "Out of range (invalid address)",
        '9404': "- File ID not found\n- Pattern not found",
        '9408': "File is inconsistent with the command",
        # TS 11.11 Chapter 9.4.5
        '9802': "No CHV initialized",
        '9804': "- Access condition not fulfilled\n- Unsuccessful CHV verification, at least one attempt left\n- unsuccesful UNBLOCK CHV verification, at least one attempt left\n- authentication failed",
        '9808': "In contradiction with CHV status",
        '9810': "In contradiction with invalidation status",
        '9840': "- Unsuccessful CHV verification, no attempt left\n- unsuccesful UNBLOCK CHV verification, no attempt left\n- CHV blocked\n- UNBLOCK CHV blocked",
        '9850': "Increase cannot be performed, Max value reached",
        # TS 11.11 Chapter 9.4.6
        "67??": "Incorrect parameter P3",
        "\x67\x00": "Incorrect parameter P3 (ISO:Wrong length)",
        "6B??": "Incorrect parameter P1 or P2",
        "\x6B\x00": "Incorrect parameter P1 or P2 (ISO:Wrong parameter(s) P1-P2)",
        "6D??": "Unknown instruction code given in the command",
        "\x6D\x00": "Unknown instruction code given in the command (ISO: Instruction code not supported or invalid)",
        "6E??": "Wrong instruction class given in the command",
        "\x6E\x00": "Wrong instruction class given in the command (ISO: Class not supported)",
        "6F??": "Technical problem with no diagnostic given",
        "\x6F\x00": "Technical problem with no diagnostic given (ISO: No precise diagnosis)",
        
    }
