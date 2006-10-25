import utils, TLV_utils
from iso_7816_4_card import *
import building_blocks

class TCOS_Card(ISO_7816_4_Card,building_blocks.Card_with_80_aa):
    DRIVER_NAME = "TCOS"
    
    ATRS = [
            ("3bba96008131865d0064........31809000..", None),
        ]
    
    COMMANDS = {
        "list_dirs": building_blocks.Card_with_80_aa.cmd_listdirs,
        "list_files": building_blocks.Card_with_80_aa.cmd_listfiles,
        "ls": building_blocks.Card_with_80_aa.cmd_list,
        }
    
    file_status_descriptions = (
        (0xF9, 0x01, None, "Not invalidated"),
        (0xF9, 0x00, None, "Invalidated"),
        (0xFC, 0x04, None, "Not permanent"),
        (0xFC, 0x00, None, "Permanent"),
        (0xF2, 0x00, "RFU", None),
    )
    iftd_byte_1_descriptions = (
        (0x80, 0x00, None, "Data file"),
        (0xFC, 0x00, None, "RFU"),
        (0x83, 0x00, None, " - general data file"),
        (0x83, 0x01, None, " - system file EF_ATR"),
        (0x83, 0x02, None, " - system file EF_GDO"),
        (0x83, 0x03, None, " - system file EF_SIGLimit"),
        (0x80, 0x80, None, "Secret file"),
        (0xC0, 0x80, None, " - Password file"),
        (0xFF, 0x80, None, "RFU"),
        (0xC0, 0xC0, None, " - Key file"),
        (0xC8, 0xC8, None, "    - signature"),
        (0xC4, 0xC4, None, "    - encryption"),
        (0xC2, 0xC2, None, "    - mac"),
        (0xC1, 0xC1, None, "    - authenticate"),
        (0xCF, 0xC0, None, "RFU"),
    )
    iftd_byte_3_descriptions = (
        (0x10, 0x00, None, "Symmetric algorithm"),
        (0x1C, 0x00, None, " - RFU"),
        (0x1C, 0x04, None, " - IDEA"),
        (0x1C, 0x08, None, " - DES"),
        (0x1C, 0x0C, None, " - DES3"),
        (0x10, 0x10, None, "Asymmetric algorithm"),
        (0x9C, 0x10, None, " - RSA, Public Key"),
        (0x9C, 0x90, None, " - RSA, Private Key"),
        (0x63, 0x00, "RFU", None),
    )
    def decode_file_descriptor_extension(value):
        result = [" "+utils.hexdump(value, short=True)]
        if len(value) >= 1:
            result.append("File status: %s" % utils.hexdump(value[0], short=True))
            result.append("\t" + "\n\t".join(
                utils.parse_binary( 
                    ord(value[0]), TCOS_Card.file_status_descriptions, True 
                ) )
            )
        
        if len(value) >= 2:
            is_secret = (ord(value[1]) & 0x80 == 0x80)
            is_key = (ord(value[1]) & 0xC0 == 0xC0)
            
            if is_key:
                iftd = value[1:4]
            elif is_secret:
                iftd = value[1:3]
            else:
                iftd = value[1:2]
            
            result.append("Internal File Type Descriptor: %s" % utils.hexdump(iftd, short=True))
            if len(iftd) >= 1:
                result.append("\tFile Type: %s" % utils.hexdump(iftd[0], short=True))
                result.append("\t\t" + "\n\t\t".join(
                    utils.parse_binary( 
                        ord(iftd[0]), TCOS_Card.iftd_byte_1_descriptions, True 
                    ) )
                )
            
            if len(iftd) >= 2:
                result.append("\tNumber of secret: %i (0x%x)" % ((ord(iftd[1])&0x1F,)*2) )
            
            if len(iftd) >= 3:
                result.append("\tCryptographic algorithm: %s" % utils.hexdump(iftd[2], short=True))
                result.append("\t\t" + "\n\t\t".join(
                    utils.parse_binary( 
                        ord(iftd[2]), TCOS_Card.iftd_byte_3_descriptions, True 
                    ) )
                )
            
            fbz = value[1+len(iftd):]
            if len(fbz) == 2:
                result.append("\tVerification failure counter (FBZ): %s" % utils.hexdump(fbz, short=True))
                if fbz == "\x00\x00":
                    result.append("\t\tFBZ unused")
                else:
                    result.append("\t\tCurrent value: %i (0x%x)%s" % (
                        ord(fbz[0]), ord(fbz[0]),
                        ord(fbz[0]) == 0 and (ord(fbz[1]) != 0 and " (Secret locked)" or " (FBZ unused)") or "")
                    )
                    resetmode = ord(fbz[1])
                    result.append("\t\tReset value: %i (0x%x)%s" % (
                        resetmode & 0x7F, resetmode & 0x7F,
                        resetmode == 0 and " (FBZ unused)" or (
                            resetmode & 0x80 == 0x00 and " (reset with unblock password and successful verification)"
                            or " (reset only with unblock password)")
                        )
                    )
                
        
        return "\n".join(result)

    # This is similar to MTCOS_Card.decode_security_attributes but not identical
    def decode_security_attributes(value):
        results = []
        if len(value) == 6:
            results.append( " " + utils.hexdump(value, short=True) )
        else:
            results.append("")
        
        for i in range(len(value)/6):
            part = value[i*6:i*6+6]
            partresponse = []
            if len(value) != 6:
                partresponse.append("Rule: %s\n" % utils.hexdump(part, short=True))
            
            if ord(part[0])&0xFE == 0x60:
                partresponse.append("Admin commands")
            else:
                partresponse.append("Command 0x%02X" % (ord(part[0])&0xFE) )
            all = not (ord(part[0])&0x01)
            
            secrets = []
            b2 = ord(part[1])
            for k in range(4):
                if b2 & (0x10<<k):
                    secrets.append("global password with number %s" % hex(k) )
            for k in range(4):
                if b2 & (0x01<<k):
                    secrets.append("local password with number %s" % hex(k) )
            
            b3 = ord(part[2])
            for k in range(8):
                if b3 & (0x01<<k):
                    secrets.append("global key with number %s" % k)
            
            b4 = ord(part[3])
            for k in range(8):
                if b4 & (0x01<<k):
                    secrets.append("local key with number %s" % k)
            
            if len(secrets) > 1:
                partresponse.append(
                    " needs\n\t    " + (all and "\n\tAND " or "\n\t OR ").join(secrets)
                )
            elif len(secrets) == 1:
                partresponse.append(" needs " + secrets[0])
            elif len(secrets) == 0:
                partresponse.append(" always allowed")
            
            def decode_key(value):
                partresponse.append( (value&0x80) and "local" or "global" )
                partresponse.append(" key, ")
                partresponse.append( (value&0x40) and "random" or "any" )
                partresponse.append(" IV")
                if not (value & 0x20):
                    partresponse.append(", key with number: ")
                    if (value & 0x1F) != 0x1F:
                        partresponse.append("0x%02x" % (value & 0x1F) )
                    else:
                        partresponse.append("RFU")
            
            b5 = ord(part[4])
            b6 = ord(part[5])
            if b5 == 0xff and b6 == 0xff and len(secrets) <= 1:
                partresponse.append(", No secure messaging required")
            else:
                if b5 == 0xff:
                    partresponse.append("\nSecure messaging: no MAC required")
                else:
                    partresponse.append("\nCryptographic MAC with ")
                    decode_key(b5)
                
                if b6 == 0xff:
                    partresponse.append("\nSecure messaging: no encryption required")
                elif not (b6 & 0x20):
                    partresponse.append("\nEncryption with ")
                    decode_key(b6)
                else:
                    partresponse.append("\nEncryption: RFU")
            
            if len(value) != 6:
                results.append("\n\t".join("".join(partresponse).splitlines()))
            else:
                results.append("".join(partresponse))
        
        return "\n".join(results)

    TLV_OBJECTS = {
        TLV_utils.context_FCP: {
            0x86: (decode_security_attributes, "Security attributes"),
            0x85: (decode_file_descriptor_extension, "File descriptor extension"),
        },
    }
    TLV_OBJECTS[TLV_utils.context_FCI] = TLV_OBJECTS[TLV_utils.context_FCP]
