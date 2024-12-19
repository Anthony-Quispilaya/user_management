import pytest
from httpx import AsyncClient
from uuid import uuid4
from datetime import timedelta
from app.models.user_model import User, UserRole
from app.schemas.user_schemas import UserUpdate
from app.services.jwt_service import create_access_token


# Helper function to generate a JWT token for a user
def generate_test_token(user_id, role):
    return create_access_token(
        data={"sub": str(user_id), "role": role},
        expires_delta=timedelta(minutes=15)
    )


@pytest.mark.asyncio
async def test_upgrade_user_to_professional_as_admin(
    db_session,
    async_client: AsyncClient,
    admin_user: User,
    user: User,
):
    """
    Test successful upgrade of a user to professional status by an Admin.
    """
    token = generate_test_token(admin_user.id, admin_user.role.name)

    url = f"/users/{user.id}/upgrade"

    response = await async_client.put(
        url, headers={"Authorization": f"Bearer {token}"}
    )

    await db_session.refresh(user)

    assert response.status_code == 200
    assert response.json()["is_professional"] is True
    assert user.is_professional is True
    assert user.professional_status_updated_at is not None


@pytest.mark.asyncio
async def test_upgrade_user_to_professional_as_manager(
    db_session,
    async_client: AsyncClient,
    manager_user: User,
    user: User,
):
    """
    Test successful upgrade of a user to professional status by a Manager.
    """
    token = generate_test_token(manager_user.id, manager_user.role.name)

    url = f"/users/{user.id}/upgrade"

    response = await async_client.put(
        url, headers={"Authorization": f"Bearer {token}"}
    )

    await db_session.refresh(user)

    assert response.status_code == 200
    assert response.json()["is_professional"] is True
    assert user.is_professional is True


@pytest.mark.asyncio
async def test_upgrade_user_to_professional_as_manager_fails_for_admin(
    db_session,
    async_client: AsyncClient,
    manager_user: User,
    admin_user: User,
):
    """
    Test failure when a Manager attempts to upgrade an Admin.
    """
    # Generate a token for the manager
    token = generate_test_token(manager_user.id, manager_user.role.name)

    # URL for upgrading the admin user
    url = f"/users/{admin_user.id}/upgrade"

    # Perform the request
    response = await async_client.put(
        url, headers={"Authorization": f"Bearer {token}"}
    )

    # Debugging logs
    print("Response Status:", response.status_code)
    print("Response Body:", response.json())

    # Assertions
    assert response.status_code == 403, "Expected 403 Forbidden when a Manager tries to upgrade an Admin"
    assert "detail" in response.json(), "Response must contain a 'detail' key"
    assert response.json()["detail"] == "You cannot update this user."



@pytest.mark.asyncio
async def test_upgrade_user_to_professional_user_not_found(
    db_session, async_client: AsyncClient, admin_user: User
):
    """
    Test attempting to upgrade a non-existent user (404 error).
    """
    token = generate_test_token(admin_user.id, admin_user.role.name)

    invalid_user_id = uuid4()
    url = f"/users/{invalid_user_id}/upgrade"

    response = await async_client.put(
        url, headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"


@pytest.mark.asyncio
async def test_upgrade_user_to_professional_unauthorized(async_client: AsyncClient, user: User):
    """
    Test unauthorized request to upgrade user without a token.
    """
    url = f"/users/{user.id}/upgrade"

    response = await async_client.put(url)

    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

@pytest.mark.asyncio
async def test_update_own_profile_success(async_client: AsyncClient, test_user: User):
    """
    Test successful user profile update.
    """
    headers = {"Authorization": f"Bearer {test_user.get_token()}"}
    update_payload = {"first_name": "UpdatedName", "bio": "Updated bio"}

    # Debug: Print token and request
    print("Authorization Token:", headers["Authorization"])
    print("Payload:", update_payload)

    response = await async_client.put("/users/profile", json=update_payload, headers=headers)

    # Debug: Print response details
    print("Response Status Code:", response.status_code)
    print("Response Body:", response.json())

    assert response.status_code == 200, "Profile update should return a 200 status code"
    assert response.json()["first_name"] == "UpdatedName", "First name should be updated"
    assert response.json()["bio"] == "Updated bio", "Bio should be updated"

@pytest.mark.asyncio
async def test_update_own_profile_user_not_found(async_client: AsyncClient, test_user: User, db_session):
    """
    Test updating profile for a non-existing user.
    """
    # Delete the test user to simulate user not found
    await db_session.delete(test_user)
    await db_session.commit()

    headers = {"Authorization": f"Bearer {test_user.get_token()}"}
    update_payload = {"first_name": "Name"}

    response = await async_client.put("/users/profile", json=update_payload, headers=headers)
    
    # Debug: Print response details
    print("Response Status Code:", response.status_code)
    print("Response Body:", response.json())

    assert response.status_code == 404, "Should return 404 if user is not found"
    assert response.json()["detail"] == "User not found", "Error message should indicate user not found"

@pytest.mark.asyncio
async def test_update_own_profile_unauthorized(async_client: AsyncClient):
    """
    Test updating profile without a valid token.
    """
    update_payload = {"first_name": "UnauthorizedUpdate"}

    response = await async_client.put("/users/profile", json=update_payload)

    # Debug: Print response details
    print("Response Status Code:", response.status_code)
    print("Response Body:", response.json())

    assert response.status_code == 401, "Should return 401 for unauthorized request"
    assert "detail" in response.json(), "Error message should indicate unauthorized access"

async def test_update_own_profile_invalid_payload(async_client: AsyncClient, test_user: User):
    """
    Test updating profile with invalid payload.
    """
    headers = {"Authorization": f"Bearer {test_user.get_token()}"}
    invalid_payload = {"first_name": 12345}  # Invalid: first_name should be a string

    response = await async_client.put("/users/profile", json=invalid_payload, headers=headers)

    # Debug: Print response details
    print("Response Status Code:", response.status_code)
    print("Response Body:", response.json())

    assert response.status_code == 422, "Should return 422 for invalid payload"
    assert "detail" in response.json(), "Response should contain validation error details"

@pytest.fixture
async def test_user(db_session):
    """
    Create a test user fixture for authentication.
    """
    user = User(
        id=uuid4(),
        nickname="testuser",
        email="testuser@example.com",
        hashed_password="testpassword",
        role=UserRole.AUTHENTICATED,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    # Mock a method to generate JWT token
    user.get_token = lambda: "mocked_token_for_test_user"
    return user
