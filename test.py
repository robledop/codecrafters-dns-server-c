from scapy.all import DNS, DNSQR, IP, UDP, sr1

query = (
        IP(dst="127.0.0.1")
        / UDP(dport=2053)
        / DNS(rd=1, qd=[DNSQR(qname="abc.longassdomainname.com"), DNSQR(qname="def.longassdomainname.com")])
)

response = sr1(query)
print(response[DNS].an)