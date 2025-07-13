import sys
import os
import traceback
import logging
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]  # /.../market_data
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Setup detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_component(name, test_func):
    """Test a component and report results"""
    print(f"\n🧪 Testing: {name}")
    print("-" * 40)
    
    try:
        result = test_func()
        print(f"✅ SUCCESS: {result}")
        return True
    except Exception as e:
        print(f"❌ FAILED: {str(e)}")
        print(f"📋 Traceback:\n{traceback.format_exc()}")
        return False

def test_imports():
    """Test all required imports"""
    try:
        from app.utils.config import get_settings
        from app.utils.database import get_db_manager
        from app.services.redis_optimizer import get_redis_service
        from app.services.data_storage import ProductionDataStorageService, DataStorageService
        from app.dependency import get_database, get_redis_client
        return "All imports successful"
    except Exception as e:
        raise Exception(f"Import failed: {e}")

def test_configuration():
    """Test configuration loading"""
    from app.utils.config import get_settings
    settings = get_settings()
    return f"Config loaded: {settings.APP_NAME}, DB: {settings.DATABASE_URL[:20]}..."

def test_database_manager():
    """Test database manager initialization"""
    from app.utils.database import get_db_manager
    from app.utils.config import get_settings
    
    settings = get_settings()
    db_manager = get_db_manager()
    
    # Test sync session creation
    session = db_manager.get_sync_session()
    session.close()
    
    return f"Database manager working, session created and closed"

def test_redis_service():
    """Test Redis service"""
    from app.services.redis_optimizer import get_redis_service
    import asyncio
    
    async def async_test():
        redis_service = await get_redis_service()
        return f"Redis service: {type(redis_service).__name__}"
    
    return asyncio.run(async_test())

def test_dependency_injection():
    """Test dependency injection"""
    from app.dependency import get_database, get_redis_client
    
    # Test database dependency
    db_gen = get_database()
    db_session = next(db_gen)
    db_session.close()
    
    # Test Redis dependency (might fail, that's ok)
    try:
        redis_client = get_redis_client()
        redis_status = "Redis dependency working"
    except Exception as e:
        redis_status = f"Redis dependency failed: {e}"
    
    return f"DB dependency working, {redis_status}"

def test_storage_service_basic():
    """Test basic storage service creation"""
    from app.services.data_storage import DataStorageService
    from app.dependency import get_database, get_redis_client
    
    # Get dependencies
    db_gen = get_database()
    db_session = next(db_gen)
    
    try:
        redis_client = get_redis_client()
    except:
        import redis
        redis_client = redis.Redis()  # Dummy Redis
    
    # Create basic storage service
    storage_service = DataStorageService(db_session, redis_client)
    
    db_session.close()
    
    return f"Basic storage service created: {type(storage_service).__name__}"

def test_storage_service_enhanced():
    """Test enhanced storage service creation"""
    from app.dependency import get_database, get_redis_client
    from app.services.data_storage import ProductionDataStorageService
    from app.utils.config import get_settings
    
    # Get dependencies
    db_gen = get_database()
    db_session = next(db_gen)
    
    try:
        redis_client = get_redis_client()
    except:
        import redis
        redis_client = redis.Redis()  # Dummy Redis
    
    config = get_settings()
    
    # Create enhanced storage service
    storage_service = ProductionDataStorageService(
        db=db_session,
        redis_client=redis_client,
        enhanced_redis_service=None,  # Set to None to avoid issues
        config=config
    )
    
    db_session.close()
    
    return f"Enhanced storage service created: {type(storage_service).__name__}"

def test_actual_endpoint_dependency():
    """Test the actual dependency as used in the endpoint"""
    try:
        # Import the function from the actual router
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        from app.routers.v1.ohlcv import get_enhanced_storage_service
        
        # Test the dependency
        storage_service = get_enhanced_storage_service()
        
        return f"Endpoint dependency working: {type(storage_service).__name__}"
        
    except Exception as e:
        raise Exception(f"Endpoint dependency failed: {e}")

def main():
    """Run all diagnostic tests"""
    print("🔍 TradeSage Storage Service Diagnostic")
    print("=" * 60)
    
    tests = [
        ("Component Imports", test_imports),
        ("Configuration Loading", test_configuration),
        ("Database Manager", test_database_manager),
        ("Redis Service", test_redis_service),
        ("Dependency Injection", test_dependency_injection),
        ("Basic Storage Service", test_storage_service_basic),
        ("Enhanced Storage Service", test_storage_service_enhanced),
        ("Actual Endpoint Dependency", test_actual_endpoint_dependency),
    ]
    
    results = []
    for test_name, test_func in tests:
        success = test_component(test_name, test_func)
        results.append((test_name, success))
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 DIAGNOSTIC SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    print(f"Passed: {passed}/{total}")
    print(f"Failed: {total - passed}/{total}")
    
    if passed == total:
        print("\n🎉 All diagnostics passed! The issue might be elsewhere.")
    else:
        print(f"\n💥 Found {total - passed} issues to fix:")
        for test_name, success in results:
            if not success:
                print(f"   ❌ {test_name}")
    
    print("\n📋 NEXT STEPS:")
    if passed < total:
        print("   1. Fix the failed components above")
        print("   2. Restart the application")
        print("   3. Test the endpoint again")
    else:
        print("   1. Apply the storage service fix I provided")
        print("   2. Check application logs for more details")
        print("   3. Verify database tables exist")

if __name__ == "__main__":
    main()