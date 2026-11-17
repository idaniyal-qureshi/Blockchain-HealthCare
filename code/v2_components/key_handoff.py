"""
Per-patient key handoff: how a doctor gets the key to a patient's data (design decision of 2026-11-17).

THE IDEA
  Every patient has their own ML-KEM key pair (the secret key stays on the patient's device). The patient-side gateway encrypts records
  under a random data key K, one per patient per epoch (e.g. a day), and stores K only in a "wrapped" form that the patient can open:

    gateway  : K = random 32 bytes;  wrapped = seal(patient_pk, K)                      -> stored with the epoch (off-chain)
               every record: AES-256-GCM(K, nonce, record, aad = patient|epoch|step)    -> only 28 bytes overhead, no KEM per record
    patient  : when the consent flow approves a doctor:
               K = unseal(patient_sk, wrapped);  grant = seal(doctor_pk, K)              -> handed to / stored for that doctor
    doctor   : K = unseal(doctor_sk, grant);  decrypt the epoch's records

  seal / unseal are the real ML-KEM + AES-GCM envelope of pqc_real.py. Each wrap is bound (as AES-GCM associated data) to the patient, the
  epoch and, for a grant, the doctor's key fingerprint, so a grant cannot be replayed for another patient, epoch or doctor.

REVOCATION
  Stop making grants and start a new epoch with a fresh K. A doctor who already received a grant keeps access to the epochs they were
  given: a key that has been handed over cannot be recalled. That limit is inherent and is tested explicitly in test_key_handoff.py.

WHERE IT PLUGS INTO ACCESS CONTROL (access_control.py, owned by the zero-knowledge teammate)
  grant_access() is the step to call when PatientDevice.issue_token(...) / PolicyStore.define(...) approves a requester. The paper leaves
  "how s reaches the hospital" open (GAP in access_control.py), so this module does not depend on it. blob_hash() gives the value to put in
  the on-chain audit event; the grant itself stays off-chain.

LIMITS  Python cannot wipe keys from memory. AES-GCM with random 96-bit nonces is safe far beyond the ~1,440 records per patient-day used here.
"""
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

import pqc_real

KEY_SIZE = 32
RECORD_OVERHEAD = pqc_real.NONCE_SIZE + pqc_real.TAG_SIZE


def fingerprint(public_key):
    """Short identifier of a doctor's (or patient's) public key."""
    return SHA256.new(bytes(public_key)).hexdigest()[:16]


def blob_hash(blob):
    """SHA-256 of a wrapped key or grant: what the on-chain audit trail records instead of the blob."""
    return SHA256.new(blob).hexdigest()


def _ctx(*parts):
    return "|".join(map(str, parts)).encode()


# ---------- gateway (patient side, public key only) ----------
def new_epoch_key(patient_id, patient_public_key, epoch, level=768):
    """Returns (K, wrapped): K encrypts this epoch's records; `wrapped` is K sealed to the patient and is what gets stored."""
    key = get_random_bytes(KEY_SIZE)
    return key, pqc_real.seal(level, patient_public_key, key, aad=_ctx("epoch-key", patient_id, epoch))


def encrypt_record(key, patient_id, epoch, step, message):
    nonce = get_random_bytes(pqc_real.NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(_ctx("record", patient_id, epoch, step))
    data, tag = cipher.encrypt_and_digest(message)
    return nonce + tag + data


def decrypt_record(key, patient_id, epoch, step, blob):
    """Raises ValueError for a wrong key or any change to the blob, or a record moved to another patient / epoch / step."""
    n, t = pqc_real.NONCE_SIZE, pqc_real.NONCE_SIZE + pqc_real.TAG_SIZE
    if len(blob) < t:
        raise ValueError("record too short")
    cipher = AES.new(key, AES.MODE_GCM, nonce=blob[:n])
    cipher.update(_ctx("record", patient_id, epoch, step))
    return cipher.decrypt_and_verify(blob[t:], blob[n:t])


# ---------- patient device (holds the secret key) ----------
def grant_access(patient_keypair, patient_id, epoch, wrapped_key, doctor_public_key):
    """Re-wrap the epoch key to a doctor. Called when the consent flow approves that doctor. Returns the grant blob."""
    key = patient_keypair.unseal(wrapped_key, aad=_ctx("epoch-key", patient_id, epoch))
    return pqc_real.seal(patient_keypair.level, doctor_public_key, key,
                         aad=_ctx("grant", patient_id, epoch, fingerprint(doctor_public_key)))


# ---------- doctor ----------
def receive_grant(doctor_keypair, patient_id, epoch, grant):
    """Open a grant with the doctor's secret key. Returns K. Raises ValueError if it was not made for this doctor, patient and epoch."""
    return doctor_keypair.unseal(grant, aad=_ctx("grant", patient_id, epoch, fingerprint(doctor_keypair.public_key)))
