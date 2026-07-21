from motor.motor_asyncio import AsyncIOMotorClient
from app.config import get_settings

settings = get_settings()

_client: AsyncIOMotorClient | None = None


def get_client() -> AsyncIOMotorClient:
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(settings.mongo_uri)
    return _client


def get_db():
    client = get_client()
    return client.get_default_database()


async def close_db():
    global _client
    if _client:
        _client.close()
        _client = None
