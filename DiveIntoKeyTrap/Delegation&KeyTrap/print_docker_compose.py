for depth in range(1, 32):
    print(f"""redo{depth}:
    build: redo/redo{depth}
    volumes:
      - ./redo/redo{depth}/conf/named:/etc/default/named
      - ./redo/redo{depth}/conf/named.conf:/var/named/chroot/etc/named.conf
      - ./redo/redo{depth}/datafile/{'redo.' * depth}delegation.keytrap.test.zone.signed:/var/named/chroot/var/named/{'redo.' * depth}delegation.keytrap.test.zone.signed
    networks:
      app_net:
        ipv4_address: 10.10.0.{depth + 5 - 1}
    """)