"""Tests for key_handoff.py: gateway -> patient -> doctor key flow with per-patient ML-KEM keys.
Skipped without liboqs; with REQUIRE_PQC=1 (CI) a missing liboqs fails the build."""
import os

import pytest

try:
    import pqc_real as P
    import key_handoff as K
except (ImportError, RuntimeError, OSError):
    if os.environ.get("REQUIRE_PQC") == "1":
        raise
    pytest.skip("liboqs / liboqs-python not installed (pip install -r requirements-pqc.txt)", allow_module_level=True)

RECORDS = [b'{"pid":7,"step":%d,"hr":72.3}' % i for i in range(5)]


@pytest.fixture(scope="module")
def world():
    patient, doctor, other_doctor = P.MLKEMKeyPair(768), P.MLKEMKeyPair(768), P.MLKEMKeyPair(768)
    key, wrapped = K.new_epoch_key("p7", patient.public_key, epoch=1)
    blobs = [K.encrypt_record(key, "p7", 1, i, m) for i, m in enumerate(RECORDS)]
    return dict(patient=patient, doctor=doctor, other=other_doctor, key=key, wrapped=wrapped, blobs=blobs)


def test_full_flow_doctor_reads_the_records(world):
    grant = K.grant_access(world["patient"], "p7", 1, world["wrapped"], world["doctor"].public_key)
    key = K.receive_grant(world["doctor"], "p7", 1, grant)
    assert key == world["key"]
    assert [K.decrypt_record(key, "p7", 1, i, b) for i, b in enumerate(world["blobs"])] == RECORDS


def test_per_record_overhead_is_only_nonce_and_tag(world):
    assert all(len(b) == len(m) + 28 for b, m in zip(world["blobs"], RECORDS))
    assert K.RECORD_OVERHEAD == 28


def test_stored_material_does_not_contain_the_key_or_plaintext(world):
    assert world["key"] not in world["wrapped"]
    assert all(m not in b for m, b in zip(RECORDS, world["blobs"]))


def test_only_the_patient_can_open_the_wrapped_key(world):
    with pytest.raises(ValueError):
        K.grant_access(world["doctor"], "p7", 1, world["wrapped"], world["other"].public_key)


def test_grant_is_only_usable_by_the_intended_doctor(world):
    grant = K.grant_access(world["patient"], "p7", 1, world["wrapped"], world["doctor"].public_key)
    with pytest.raises(ValueError):
        K.receive_grant(world["other"], "p7", 1, grant)


@pytest.mark.parametrize("patient_id, epoch", [("p8", 1), ("p7", 2)])
def test_grant_cannot_be_replayed_for_another_patient_or_epoch(world, patient_id, epoch):
    grant = K.grant_access(world["patient"], "p7", 1, world["wrapped"], world["doctor"].public_key)
    with pytest.raises(ValueError):
        K.receive_grant(world["doctor"], patient_id, epoch, grant)


def test_wrapped_key_is_bound_to_patient_and_epoch(world):
    for patient_id, epoch in (("p8", 1), ("p7", 2)):
        with pytest.raises(ValueError):
            K.grant_access(world["patient"], patient_id, epoch, world["wrapped"], world["doctor"].public_key)


@pytest.mark.parametrize("patient_id, epoch, step", [("p8", 1, 0), ("p7", 2, 0), ("p7", 1, 1)])
def test_a_record_cannot_be_moved_to_another_patient_epoch_or_step(world, patient_id, epoch, step):
    with pytest.raises(ValueError):
        K.decrypt_record(world["key"], patient_id, epoch, step, world["blobs"][0])


def test_tampered_or_short_record_rejected(world):
    bad = bytearray(world["blobs"][0])
    bad[-1] ^= 1
    with pytest.raises(ValueError):
        K.decrypt_record(world["key"], "p7", 1, 0, bytes(bad))
    with pytest.raises(ValueError):
        K.decrypt_record(world["key"], "p7", 1, 0, b"short")


def test_revocation_by_rotation_protects_new_epochs_but_cannot_recall_old_ones(world):
    old_grant = K.grant_access(world["patient"], "p7", 1, world["wrapped"], world["doctor"].public_key)
    old_key = K.receive_grant(world["doctor"], "p7", 1, old_grant)
    new_key, _ = K.new_epoch_key("p7", world["patient"].public_key, epoch=2)
    new_blob = K.encrypt_record(new_key, "p7", 2, 0, RECORDS[0])
    assert new_key != old_key
    with pytest.raises(ValueError):
        K.decrypt_record(old_key, "p7", 2, 0, new_blob)                              # the new epoch is closed to the revoked doctor
    assert K.decrypt_record(old_key, "p7", 1, 0, world["blobs"][0]) == RECORDS[0]    # the old epoch stays readable: a handed-over key is not recallable


def test_audit_hash_identifies_a_blob_without_revealing_it(world):
    h = K.blob_hash(world["wrapped"])
    assert len(h) == 64 and h != K.blob_hash(world["wrapped"] + b"x")


@pytest.mark.parametrize("level", [512, 1024])
def test_flow_works_at_other_security_levels(level):
    patient, doctor = P.MLKEMKeyPair(level), P.MLKEMKeyPair(level)
    key, wrapped = K.new_epoch_key("p1", patient.public_key, 0, level=level)
    grant = K.grant_access(patient, "p1", 0, wrapped, doctor.public_key)
    assert K.receive_grant(doctor, "p1", 0, grant) == key
