import json

import pytest

from agents.common.ledger import InMemoryLedgerStore, Ledger, MinioLedgerStore, ledger_from_env


def test_ledger_sequences_are_per_incident_and_keys_are_stable():
    store = InMemoryLedgerStore()
    ledger = Ledger(store)

    first = ledger.append("incident-a", "detected", {"source": "health"})
    second = ledger.append("incident-a", "decision", {"action": "HUMAN"})
    other = ledger.append("incident-b", "detected", {})

    assert (first.sequence, second.sequence, other.sequence) == (1, 2, 1)
    assert first.key == "incidents/incident-a/000001-detected.json"
    assert second.key == "incidents/incident-a/000002-decision.json"
    assert other.key == "incidents/incident-b/000001-detected.json"
    stored = json.loads(store.objects[first.key])
    assert stored["payload"] == {"source": "health"}
    assert stored["sequence"] == 1


def test_ledger_continues_sequence_from_existing_store_keys():
    store = InMemoryLedgerStore()
    store.put_if_absent("incidents/i/000007-old.json", b"{}")

    entry = Ledger(store).append("i", "new", {})

    assert entry.sequence == 8
    assert entry.key == "incidents/i/000008-new.json"


def test_memory_store_refuses_overwrite():
    store = InMemoryLedgerStore()
    store.put_if_absent("incidents/i/000001-step.json", b"first")

    with pytest.raises(FileExistsError):
        store.put_if_absent("incidents/i/000001-step.json", b"replacement")

    assert store.objects["incidents/i/000001-step.json"] == b"first"


@pytest.mark.parametrize("incident_id,step", [("", "step"), ("../bad", "step"), ("i", "")])
def test_ledger_rejects_invalid_key_segments(incident_id, step):
    with pytest.raises(ValueError):
        Ledger().append(incident_id, step, {})


class _MissingObject(Exception):
    code = "NoSuchKey"


class _FakeMinio:
    def __init__(self):
        self.objects = {}

    def list_objects(self, bucket_name, prefix, recursive):
        return [type("Object", (), {"object_name": key}) for key in self.objects if key.startswith(prefix)]

    def stat_object(self, bucket_name, object_name):
        key = object_name
        if key not in self.objects:
            raise _MissingObject()

    def put_object(self, bucket_name, object_name, data, length, content_type):
        self.objects[object_name] = data.read(length)


def test_minio_store_writes_json_and_checks_existing_key():
    client = _FakeMinio()
    ledger = Ledger(MinioLedgerStore(client, "audit"))

    entry = ledger.append("i", "decision", {"result": "observe"})
    assert json.loads(client.objects[entry.key])["payload"] == {"result": "observe"}

    with pytest.raises(FileExistsError):
        MinioLedgerStore(client, "audit").put_if_absent(entry.key, b"overwrite")


def test_ledger_factory_defaults_to_memory_and_rejects_missing_minio_credentials():
    assert isinstance(ledger_from_env({}).store, InMemoryLedgerStore)
    with pytest.raises(ValueError, match="MINIO_ACCESS_KEY"):
        ledger_from_env({"LEDGER_BACKEND": "minio"})

