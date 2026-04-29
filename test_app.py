import os

os.environ["NOT_MY_KEY"] = "my-secret-key"

import app as jwks_app


def setup_module(module):
    if os.path.exists(jwks_app.DB_NAME):
        os.remove(jwks_app.DB_NAME)

    jwks_app.init_db()
    jwks_app.ensure_keys()


def test_register_endpoint():
    jwks_app.app.config["TESTING"] = True

    with jwks_app.app.test_client() as client:
        response = client.post(
            "/register",
            json={
                "username": "testuser",
                "email": "test@example.com"
            }
        )

        assert response.status_code in [200, 201]
        data = response.get_json()
        assert "password" in data


def test_jwks_endpoint():
    with jwks_app.app.test_client() as client:
        response = client.get("/.well-known/jwks.json")

        assert response.status_code == 200
        data = response.get_json()
        assert "keys" in data
        assert len(data["keys"]) >= 1


def test_auth_endpoint():
    with jwks_app.app.test_client() as client:
        response = client.post("/auth")

        assert response.status_code == 200
        assert response.data is not None


def test_auth_expired_endpoint():
    with jwks_app.app.test_client() as client:
        response = client.post("/auth?expired=true")

        assert response.status_code == 200
        assert response.data is not None


def test_rate_limit():
    with jwks_app.app.test_client() as client:
        for _ in range(10):
            client.post("/auth")

        response = client.post("/auth")
        assert response.status_code == 429