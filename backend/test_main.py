import os
import pytest
from fastapi.testclient import TestClient
from main import app
from database import initialize_database, get_connection

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    initialize_database()
    yield


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert "Q-Legacy" in response.text


def test_asset_lifecycle():
    # 1. Register Asset
    payload = {
        "filename": "test_rsa_key.pem",
        "asset_type": "RSA Key",
        "algorithms": ["RSA", "SHA256"],
    }
    create_res = client.post("/api/assets", json=payload)
    assert create_res.status_code == 201
    created_data = create_res.json()
    asset_id = created_data["id"]
    assert created_data["filename"] == "test_rsa_key.pem"
    assert created_data["risk_level"] == "HIGH"
    assert created_data["priority"] == "HIGH"

    # 2. List Assets
    list_res = client.get("/api/assets")
    assert list_res.status_code == 200
    assets = list_res.json()
    assert any(a["id"] == asset_id for a in assets)

    # 3. Get Single Asset
    get_res = client.get(f"/api/assets/{asset_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == asset_id

    # 4. Get Dashboard Metrics
    dash_res = client.get("/api/dashboard")
    assert dash_res.status_code == 200
    dash_data = dash_res.json()
    assert dash_data["total_assets"] >= 1
    assert "risk_distribution" in dash_data

    # 5. Delete Asset
    del_res = client.delete(f"/api/assets/{asset_id}")
    assert del_res.status_code == 200

    # 6. Verify 404 after deletion
    get_404 = client.get(f"/api/assets/{asset_id}")
    assert get_404.status_code == 404


def test_analyze_file_upload():
    # Test safe text scan
    text_content = b"Config file specifying ML-KEM-768 key exchange and RSA-2048 fallback."
    res = client.post(
        "/api/analyze",
        files={"file": ("config.txt", text_content, "text/plain")},
    )
    assert res.status_code == 200
    json_data = res.json()
    assert json_data["filename"] == "config.txt"
    assert "ML-KEM" in json_data["algorithms_detected"]
    assert "RSA" in json_data["algorithms_detected"]
    assert json_data["overall_risk_level"] == "HIGH"
    assert json_data["overall_confidence"] == "MEDIUM"  # Text heuristic match


def test_analyze_empty_file():
    res = client.post(
        "/api/analyze",
        files={"file": ("empty.txt", b"", "text/plain")},
    )
    assert res.status_code == 400


def test_aes256_gcm_crypto_flow():
    # 1. Test Demo endpoint
    demo_res = client.get("/api/crypto/aes/demo")
    assert demo_res.status_code == 200
    demo_data = demo_res.json()
    assert demo_data["decryption_verified"] is True
    assert demo_data["tamper_test"]["tamper_rejected"] is True

    # 2. Test Encrypt endpoint
    enc_payload = {"plaintext": "Confidential Payload 123"}
    enc_res = client.post("/api/crypto/aes/encrypt", json=enc_payload)
    assert enc_res.status_code == 200
    enc_data = enc_res.json()
    key_hex = enc_data["key_hex"]
    nonce_hex = enc_data["nonce_hex"]
    ciphertext_hex = enc_data["ciphertext_hex"]

    # 3. Test Decrypt endpoint (Valid)
    dec_payload = {
        "key_hex": key_hex,
        "nonce_hex": nonce_hex,
        "ciphertext_hex": ciphertext_hex,
    }
    dec_res = client.post("/api/crypto/aes/decrypt", json=dec_payload)
    assert dec_res.status_code == 200
    assert dec_res.json()["plaintext"] == "Confidential Payload 123"

    # 4. Test Decrypt endpoint (Tampered Ciphertext)
    tampered_bytes = bytearray(bytes.fromhex(ciphertext_hex))
    tampered_bytes[0] ^= 0xFF
    bad_dec_payload = {
        "key_hex": key_hex,
        "nonce_hex": nonce_hex,
        "ciphertext_hex": tampered_bytes.hex(),
    }
    bad_dec_res = client.post("/api/crypto/aes/decrypt", json=bad_dec_payload)
    assert bad_dec_res.status_code == 400
    assert "tampered" in bad_dec_res.json()["detail"].lower() or "decryption failed" in bad_dec_res.json()["detail"].lower()


def test_mlkem_crypto_flow():
    # 1. Test Demo endpoint
    demo_res = client.get("/api/crypto/mlkem/demo")
    assert demo_res.status_code == 200
    demo_data = demo_res.json()
    assert demo_data["simulation"]["shared_secrets_identical"] is True

    # 2. Keygen
    kg_res = client.post("/api/crypto/mlkem/keygen")
    assert kg_res.status_code == 200
    kg_data = kg_res.json()
    pk_hex = kg_data["public_key_hex"]
    sk_hex = kg_data["secret_key_hex"]

    # 3. Encapsulate
    encaps_res = client.post("/api/crypto/mlkem/encapsulate", json={"public_key_hex": pk_hex})
    assert encaps_res.status_code == 200
    encaps_data = encaps_res.json()
    ct_hex = encaps_data["ciphertext_hex"]
    ss_sender_hex = encaps_data["shared_secret_hex"]

    # 4. Decapsulate
    decaps_res = client.post(
        "/api/crypto/mlkem/decapsulate",
        json={"secret_key_hex": sk_hex, "ciphertext_hex": ct_hex},
    )
    assert decaps_res.status_code == 200
    ss_recipient_hex = decaps_res.json()["shared_secret_hex"]

    # 5. Shared secret match assertion
    assert ss_sender_hex == ss_recipient_hex
