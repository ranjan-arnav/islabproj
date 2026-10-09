from pathlib import Path

import pytest

from bitchat_web.mesh import MeshNode


def make_node(root: Path, name: str) -> MeshNode:
    node = MeshNode(root / name, start_transport=False)
    node.configure(name, "shared room secret")
    return node


def test_encrypted_packet_relays_across_three_nodes(tmp_path: Path):
    alice = make_node(tmp_path, "alice")
    bob = make_node(tmp_path, "bob")
    carol = make_node(tmp_path, "carol")
    first_hop = []
    second_hop = []
    alice.transport.broadcast = lambda packet, exclude=None: first_hop.append(packet.copy()) or 1
    bob.transport.broadcast = lambda packet, exclude=None: second_hop.append(packet.copy()) or 1

    alice.send_message("hello through the mesh")
    assert first_hop[0]["ttl"] == 7
    assert "hello through the mesh" not in str(first_hop[0])

    bob.receive_packet(first_hop[0], "alice-link")
    assert bob.status()["messages"][0]["verified"] is True
    assert bob.status()["messages"][0]["hops"] == 1
    assert second_hop[0]["ttl"] == 6

    carol.receive_packet(second_hop[0], "bob-link")
    assert carol.status()["messages"][0]["text"] == "hello through the mesh"
    assert carol.status()["messages"][0]["hops"] == 2


def test_tampered_ciphertext_is_rejected(tmp_path: Path):
    alice = make_node(tmp_path, "alice")
    bob = make_node(tmp_path, "bob")
    packets = []
    alice.transport.broadcast = lambda packet, exclude=None: packets.append(packet.copy()) or 1
    alice.send_message("authentic")
    packets[0]["ciphertext"] = packets[0]["ciphertext"][:-2] + "AA"

    bob.receive_packet(packets[0], "attacker")
    status = bob.status()
    assert status["messages"] == []
    assert any("Rejected packet" in event["text"] for event in status["events"])


def test_private_message_is_opaque_to_intermediate_node(tmp_path: Path):
    alice = make_node(tmp_path, "alice")
    bob = make_node(tmp_path, "bob")
    carol = make_node(tmp_path, "carol")

    carol_packets = []
    carol.transport.broadcast = lambda packet, exclude=None: carol_packets.append(packet.copy()) or 1
    carol.announce()

    bob_relays = []
    bob.transport.broadcast = lambda packet, exclude=None: bob_relays.append(packet.copy()) or 1
    bob.receive_packet(carol_packets[-1], "carol-link")
    alice.receive_packet(bob_relays[-1], "bob-link")
    assert alice.status()["participants"][0]["id"] == carol.identity.fingerprint
    assert alice.status()["participants"][0]["hops"] == 2

    outbound = []
    alice.transport.broadcast = lambda packet, exclude=None: outbound.append(packet.copy()) or 1
    alice.send_message("only carol may read this", carol.identity.fingerprint)
    private_packet = outbound[-1]
    assert private_packet["type"] == "private"
    assert "only carol may read this" not in str(private_packet)
    with pytest.raises(ValueError):
        bob.identity.unwrap_key(private_packet["wrapped_key"])

    bob_messages_before = list(bob.status()["messages"])
    bob_events_before = list(bob.status()["events"])
    bob_relays.clear()
    bob.receive_packet(private_packet, "alice-link")
    assert bob.status()["messages"] == bob_messages_before
    assert bob.status()["events"] == bob_events_before
    assert bob_relays[-1]["ttl"] == 6

    carol.receive_packet(bob_relays[-1], "bob-link")
    received = carol.status()["messages"][-1]
    assert received["text"] == "only carol may read this"
    assert received["private"] is True
    assert received["hops"] == 2
