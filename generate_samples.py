"""Generate sample DNS log files in all 8 supported formats."""
import json, datetime

random_seed = 99
DOMAINS = ['google.com', 'a8f3kq2.tunnel.example.com', 'github.com',
           'exfildata.evil.io', 'docs.python.org', 'c2server.dnscat.net']
QTYPES  = ['A', 'TXT', 'AAAA', 'NULL', 'CNAME', 'A']
MONTHS  = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
base = datetime.datetime(2024, 1, 15, 8, 0, 0)
N = 100

def ts_row(i):
    return base + datetime.timedelta(seconds=i * 10)

# ── Zeek dns.log ─────────────────────────────────────────────────────────────
lines = [
    '#separator \\x09',
    '#set_separator\t,',
    '#empty_field\t(empty)',
    '#unset_field\t-',
    '#path\tdns',
    '#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name\trcode\trcode_name\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\trejected',
    '#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\tinterval\tstring\tcount\tstring\tcount\tstring\tcount\tstring\tbool\tbool\tbool\tbool\tcount\tvector[string]\tvector[interval]\tbool',
]
for i in range(N):
    d = DOMAINS[i % 6]; q = QTYPES[i % 6]
    t = ts_row(i)
    lines.append('\t'.join([
        str(t.timestamp()), f'uid{i:04d}',
        f'192.168.1.{i % 255}', str(50000 + i),
        '8.8.8.8', '53', 'udp', str(i),
        '0.001', d, '1', 'C_INTERNET',
        str(i % 5 + 1), q, '0', 'NOERROR',
        'F', 'F', 'T', 'T', '0', '1.2.3.4', '30.0', 'F',
    ]))
with open(r'e:\DTDS\sample_zeek_dns.log', 'w') as f:
    f.write('\n'.join(lines))
print('Written sample_zeek_dns.log')

# ── Suricata eve.json ─────────────────────────────────────────────────────────
with open(r'e:\DTDS\sample_suricata_eve.json', 'w') as f:
    for i in range(N):
        d = DOMAINS[i % 6]; q = QTYPES[i % 6]
        t = ts_row(i)
        obj = {
            'timestamp': t.isoformat() + '+0000',
            'event_type': 'dns',
            'src_ip': f'192.168.1.{i % 255}',
            'src_port': 50000 + i,
            'dest_ip': '8.8.8.8', 'dest_port': 53,
            'dns': {
                'type': 'query', 'id': i,
                'rrname': d, 'rrtype': q, 'tx_id': 0,
                'answers': [{'rrname': d, 'rrtype': q, 'rdata': '1.2.3.4'}],
            },
        }
        f.write(json.dumps(obj) + '\n')
        # Non-DNS event to verify filtering works
        f.write(json.dumps({'timestamp': t.isoformat(), 'event_type': 'alert'}) + '\n')
print('Written sample_suricata_eve.json')

# ── AWS Route53 ───────────────────────────────────────────────────────────────
with open(r'e:\DTDS\sample_route53.csv', 'w') as f:
    f.write('version,date,time,hosted-zone-id,name,type,responseCode,layer4Protocol,edgeLocation,resolverIpAddress,clientIpAddress\n')
    for i in range(N):
        d = DOMAINS[i % 6]; q = QTYPES[i % 6]
        t = ts_row(i)
        hms = t.strftime('%H:%M:%S')
        f.write(f'1.1,{t.date()},{hms},Z1EXAMPLE123,{d}.,{q},NOERROR,UDP,IAD12,8.8.8.8,192.168.1.{i % 255}\n')
print('Written sample_route53.csv')

# ── dnsmasq log ───────────────────────────────────────────────────────────────
with open(r'e:\DTDS\sample_dnsmasq.log', 'w') as f:
    for i in range(N):
        d = DOMAINS[i % 6]; q = QTYPES[i % 6]
        t = ts_row(i)
        mon = MONTHS[t.month - 1]
        hms = t.strftime('%H:%M:%S')
        f.write(f'{mon} {t.day:2d} {hms} router dnsmasq[1234]: query[{q}] {d} from 192.168.1.{i % 255}\n')
print('Written sample_dnsmasq.log')

# ── BIND named log ────────────────────────────────────────────────────────────
with open(r'e:\DTDS\sample_bind_named.log', 'w') as f:
    for i in range(N):
        d = DOMAINS[i % 6]; q = QTYPES[i % 6]
        t = ts_row(i)
        mon = MONTHS[t.month - 1]
        hms = t.strftime('%H:%M:%S')
        f.write(f'{mon} {t.day:2d} {hms} ns1 named[5678]: client 192.168.1.{i % 255}#5432 ({d}): query: {d} IN {q} + (8.8.8.8)\n')
print('Written sample_bind_named.log')

# ── Generic TSV (non-standard column names) ───────────────────────────────────
with open(r'e:\DTDS\sample_generic.tsv', 'w') as f:
    f.write('event_time\tfqdn\trrtype\tpayload_len\tnum_labels\tresp_len\n')
    for i in range(N):
        d = DOMAINS[i % 6]; q = QTYPES[i % 6]
        t = ts_row(i)
        f.write(f'{t.isoformat()}\t{d}\t{q}\t{20 + i % 80}\t{max(0, d.count(".") - 1)}\t{100 + i % 300}\n')
print('Written sample_generic.tsv')

print('\nAll sample files generated in e:\\DTDS\\')
