#!/usr/bin/env python3
"""
Debug script to identify and fix data ingestion issues
"""

import sys
import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# Add project path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.config import settings
from models.market_data import Symbol, Base
from schemas.market_data import SymbolCreate

def test_direct_database_access():
    """Test direct database access without ORM"""
    try:
        engine = create_engine(settings.POSTGRES_URL)
        
        with engine.connect() as conn:
            # Test if table is accessible
            result = conn.execute(text("SELECT COUNT(*) FROM symbols"))
            count = result.scalar()
            print(f"✅ Direct access: symbols table has {count} rows")
            
            # Test inserting directly with SQL
            conn.execute(text("""
                INSERT INTO symbols (symbol, dataset, description, sector, industry, currency, exchange, is_active, created_at, updated_at)
                VALUES ('TEST_DIRECT', 'TEST.DATASET', 'Direct test', 'Tech', 'Software', 'USD', 'TEST', true, NOW(), NOW())
            """))
            conn.commit()
            print("✅ Direct SQL insert successful")
            
            # Clean up
            conn.execute(text("DELETE FROM symbols WHERE symbol = 'TEST_DIRECT'"))
            conn.commit()
            print("✅ Direct SQL cleanup successful")
            
            return True
    except Exception as e:
        print(f"❌ Direct database access failed: {e}")
        return False

def test_sqlalchemy_orm():
    """Test SQLAlchemy ORM access"""
    try:
        engine = create_engine(settings.POSTGRES_URL)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        
        with SessionLocal() as db:
            # Test ORM query
            count = db.query(Symbol).count()
            print(f"✅ ORM access: symbols table has {count} rows")
            
            # Test ORM insert
            test_symbol = Symbol(
                symbol="TEST_ORM",
                dataset="TEST.DATASET",
                description="ORM test",
                sector="Tech",
                industry="Software", 
                currency="USD",
                exchange="TEST",
                is_active=True,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            
            db.add(test_symbol)
            db.commit()
            print("✅ ORM insert successful")
            
            # Verify insert
            inserted = db.query(Symbol).filter(Symbol.symbol == "TEST_ORM").first()
            if inserted:
                print(f"✅ ORM verification successful: {inserted.symbol}")
                
                # Clean up
                db.delete(inserted)
                db.commit()
                print("✅ ORM cleanup successful")
            
            return True
    except Exception as e:
        print(f"❌ ORM access failed: {e}")
        return False

def test_dependency_injection():
    """Test your actual dependency injection setup"""
    try:
        from dependency import get_db
        from services.data_storage import DataStorageService
        
        storage_service = DataStorageService()
        
        # Get database session using your dependency
        db_gen = get_db()
        db = next(db_gen)
        
        try:
            storage_service.db = db
            
            # Test count
            count = storage_service.db.query(Symbol).count()
            print(f"✅ Dependency injection: symbols table has {count} rows")
            
            # Test your actual create_symbol method
            test_symbol_data = SymbolCreate(
                symbol="TEST_DI",
                dataset="TEST.DATASET",
                description="Dependency injection test",
                sector="Tech",
                industry="Software",
                currency="USD",
                exchange="TEST"
            )
            
            created = storage_service.create_symbol(test_symbol_data)
            print(f"✅ Dependency injection create successful: {created.symbol}")
            
            # Clean up
            storage_service.delete_symbol(created.id)
            print("✅ Dependency injection cleanup successful")
            
            return True
        finally:
            next(db_gen, None)  # Close the generator
            
    except Exception as e:
        print(f"❌ Dependency injection failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def check_table_permissions():
    """Check if there are any permission issues"""
    try:
        engine = create_engine(settings.POSTGRES_URL)
        
        with engine.connect() as conn:
            # Check table permissions
            result = conn.execute(text("""
                SELECT 
                    table_name,
                    privilege_type
                FROM information_schema.table_privileges 
                WHERE table_name = 'symbols'
                AND grantee = current_user
            """))
            
            privileges = list(result)
            if privileges:
                print("✅ Table permissions:")
                for table, privilege in privileges:
                    print(f"   - {privilege} on {table}")
            else:
                print("⚠️  No specific privileges found (might be inherited)")
            
            return True
    except Exception as e:
        print(f"❌ Permission check failed: {e}")
        return False

def test_with_sample_symbols():
    """Test with actual sample symbols like your ingestion script"""
    try:
        from dependency import get_db
        from services.data_storage import DataStorageService
        
        # Sample symbols that were found in your log
        sample_symbols = ["AVGO", "KLAC", "INTU", "BIIB", "MSFT"]
        datasets = ["XNAS.ITCH", "XNYS.PILLAR", "XASE.PILLAR", "BATS.PITCH"]
        
        storage_service = DataStorageService()
        
        for dataset in datasets[:1]:  # Test with just one dataset first
            print(f"\n🧪 Testing with dataset: {dataset}")
            
            with next(get_db()) as db:
                storage_service.db = db
                
                for symbol in sample_symbols[:2]:  # Test with just 2 symbols
                    try:
                        # Check if symbol already exists
                        existing = storage_service.get_symbol(symbol, dataset)
                        if existing:
                            print(f"   ✅ Symbol {symbol} already exists")
                            continue
                        
                        # Create new symbol
                        symbol_data = SymbolCreate(
                            symbol=symbol,
                            dataset=dataset,
                            description=f"{symbol} stock",
                            sector="Technology",
                            industry="Software",
                            currency="USD",
                            exchange="NASDAQ"
                        )
                        
                        created = storage_service.create_symbol(symbol_data)
                        print(f"   ✅ Created symbol: {created.symbol}")
                        storage_service.delete_symbol(created.id) # Clean up
                        
                    except Exception as e:
                        print(f"   ❌ Error with symbol {symbol}: {e}")
                        import traceback
                        traceback.print_exc()
                        
        return True

    except Exception as e:
        print(f"❌ Sample symbol test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all diagnostic tests"""
    print("🔍 Diagnosing Data Ingestion Issues...")
    print("=" * 50)
    
    tests = [
        ("Direct Database Access", test_direct_database_access),
        ("SQLAlchemy ORM", test_sqlalchemy_orm),
        ("Table Permissions", check_table_permissions),
        ("Dependency Injection", test_dependency_injection),
        ("Sample Symbols Test", test_with_sample_symbols),
    ]
    
    results = {}
    for test_name, test_func in tests:
        print(f"\n📋 Running: {test_name}")
        print("-" * 30)
        results[test_name] = test_func()
    
    print("\n" + "=" * 50)
    print("📊 DIAGNOSIS SUMMARY")
    print("=" * 50)
    
    for test_name, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
    
    all_passed = all(results.values())
    if all_passed:
        print("\n🎉 All tests passed! Your ingestion should work now.")
    else:
        print("\n🚨 Some tests failed. Check the errors above.")
        
        # Provide specific recommendations
        if not results.get("Direct Database Access"):
            print("   → Database connection or table access issue")
        if not results.get("SQLAlchemy ORM"):
            print("   → SQLAlchemy configuration issue")
        if not results.get("Dependency Injection"):
            print("   → Application dependency injection issue")
    
    return all_passed

if __name__ == "__main__":
    success = main()
    
    if success:
        print("\n🚀 Ready to run data ingestion!")
        print("Try running: python market_data/scripts/ingest_daily_data.py")
    else:
        print("\n🔧 Fix the issues above before running data ingestion.")
    
    sys.exit(0 if success else 1)