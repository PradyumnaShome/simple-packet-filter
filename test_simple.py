import firewall


def test_simple():
    # inbound,tcp,80,192.168.1.2
    f = firewall.Firewall("inputs/test_simple.csv")
    assert f.accept_packet("inbound", "tcp", "80", "192.168.1.2")
    assert not f.accept_packet("inbound", "tcp", "81", "192.168.1.2")

    # inbound,udp,53,192.168.1.1-192.168.2.5
    assert f.accept_packet('inbound', 'udp', '53', '192.168.1.1')
    assert f.accept_packet('inbound', 'udp', '53', '192.168.1.3')

    # Edge case test
    assert f.accept_packet('inbound', 'udp', '53', '192.168.2.5')
    assert not f.accept_packet('outbound', 'udp', '53', '192.168.2.5')
    assert not f.accept_packet('outbound', 'tcp', '53', '192.168.2.5')

    # outbound,tcp,10000-20000,192.168.10.11
    # Testing port range
    assert f.accept_packet('outbound', 'tcp', '10000', '192.168.10.11')
    assert f.accept_packet('outbound', 'tcp', '20000', '192.168.10.11')
    assert not f.accept_packet('outbound', 'tcp', '90000', '192.168.10.11')