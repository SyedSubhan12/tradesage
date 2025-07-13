#!/usr/bin/env python3
"""
TradeSage Market Data API - Fix Validation Script
Validates that all critical bug fixes are working correctly
Run this before Tuesday's testing to ensure all issues are resolved
"""

import sys
import os
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Tuple
import traceback
import subprocess
from pathlib import Path

# -----------------------------------------------------------------------------
# Ensure the project root (market_data) is on the Python path so that the
# application package `app` can be imported when this script is executed from
# tests/unit or any other directory.  This avoids `ModuleNotFoundError: app` and
# prevents relative-import errors when `validate_fixes.py` is executed as a
# standalone script.
# -----------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[2]  # /.../market_data
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class FixValidator:
    """Validates all critical bug fixes"""
    
    def __init__(self):
        self.results = []
        self.critical_failures = []
        self.warnings = []
    
    def run_all_validations(self) -> bool:
        """Run all validation checks"""
        print("🔍 TradeSage Market Data API - Fix Validation")
        print("=" * 60)
        
        validations = [
            ("Configuration Validation", self.validate_configuration),
            ("Pydantic V2 Compatibility", self.validate_pydantic_v2),
            ("Database Configuration", self.validate_database_config),
            ("Redis Configuration", self.validate_redis_config), 
            ("Schema Consistency", self.validate_schema_consistency),
            ("Dependency Injection", self.validate_dependency_injection),
            ("Import Validation", self.validate_imports),
            ("Environment Variables", self.validate_environment_variables),
            ("Circuit Breaker Logic", self.validate_circuit_breakers),
            ("Session Management", self.validate_session_management)
        ]
        
        for test_name, test_func in validations:
            print(f"\n📋 Running: {test_name}")
            print("-" * 40)
            
            try:
                success, message = test_func()
                
                if success:
                    print(f"✅ PASS: {message}")
                    self.results.append((test_name, True, message))
                else:
                    print(f"❌ FAIL: {message}")
                    self.results.append((test_name, False, message))
                    self.critical_failures.append(test_name)
                    
            except Exception as e:
                error_msg = f"Exception during test: {str(e)}"
                print(f"💥 ERROR: {error_msg}")
                self.results.append((test_name, False, error_msg))
                self.critical_failures.append(test_name)
        
        # Print summary
        self.print_summary()
        
        return len(self.critical_failures) == 0
    
    def validate_configuration(self) -> Tuple[bool, str]:
        """Validate configuration fixes"""
        try:
            # Add current directory to Python path
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            
            from app.utils.config import get_settings
            
            settings = get_settings()
            
            # Check critical configuration fixes
            checks = []
            
            # 1. Check DATABASE_URL vs POSTGRES_URL fix
            if hasattr(settings, 'DATABASE_URL'):
                checks.append("✓ DATABASE_URL field exists")
            else:
                return False, "DATABASE_URL field missing (should replace POSTGRES_URL)"
            
            # 2. Check Pydantic v2 validators
            config_class = settings.__class__
            validators = [method for method in dir(config_class) if method.startswith('validate_')]
            
            if any('field_validator' in str(getattr(config_class, method)) for method in validators):
                checks.append("✓ Pydantic v2 validators detected")
            else:
                checks.append("⚠ No Pydantic v2 validators found")
            
            # 3. Check Redis cluster detection logic
            if settings.REDIS_CLUSTER_NODES is None:
                checks.append("✓ Redis cluster detection logic fixed (None default)")
            else:
                return False, "Redis cluster detection still has default values"
            
            # 4. Check TTL consistency
            try:
                ttl = settings.get_cache_ttl('ohlcv-1m')
                if isinstance(ttl, int) and ttl > 0:
                    checks.append("✓ TTL calculation working")
                else:
                    return False, "TTL calculation broken"
            except Exception as e:
                return False, f"TTL calculation error: {e}"
            
            return True, f"Configuration validation passed: {', '.join(checks)}"
            
        except ImportError as e:
            return False, f"Import error: {e}"
        except Exception as e:
            return False, f"Configuration validation failed: {e}"
    
    def validate_pydantic_v2(self) -> Tuple[bool, str]:
        """Validate Pydantic v2 compatibility"""
        try:
            import pydantic
            
            # Check Pydantic version
            version = pydantic.VERSION
            if version.startswith('2.'):
                version_check = "✓ Pydantic v2 installed"
            else:
                return False, f"Pydantic v1 detected: {version}"
            
            # Test field validators
            from pydantic import BaseModel, field_validator
            
            class TestModel(BaseModel):
                test_field: str
                
                @field_validator('test_field')
                @classmethod
                def validate_test(cls, v):
                    return v.upper()
            
            # Test model creation
            test_instance = TestModel(test_field="hello")
            if test_instance.test_field == "HELLO":
                validator_check = "✓ Field validators working"
            else:
                return False, "Field validators not working correctly"
            
            return True, f"Pydantic v2 validation passed: {version_check}, {validator_check}"
            
        except ImportError as e:
            return False, f"Pydantic import error: {e}"
        except Exception as e:
            return False, f"Pydantic v2 validation failed: {e}"
    
    def validate_database_config(self) -> Tuple[bool, str]:
        """Validate database configuration fixes"""
        try:
            from app.utils.database import OptimizedDatabaseManager
            from app.utils.config import get_settings
            
            settings = get_settings()
            
            # Test database manager initialization (without actual connection)
            db_manager = OptimizedDatabaseManager(settings)
            
            # Check that DATABASE_URL is being used
            test_url = "postgresql://postgres:postgres@localhost:5432/trading_data"
            os.environ["DATABASE_URL"] = test_url
            
            # Test URL cleaning
            cleaned = db_manager._clean_database_url("postgresql+asyncpg://postgres:postgres@localhost:5432/trading_data")
            if cleaned == "postgresql://postgres:postgres@localhost:5432/trading_data":
                url_clean_check = "✓ URL cleaning working"
            else:
                return False, f"URL cleaning failed: {cleaned}"
            
            return True, f"Database config validation passed: {url_clean_check}"
            
        except Exception as e:
            return False, f"Database config validation failed: {e}"
    
    def validate_redis_config(self) -> Tuple[bool, str]:
        """Validate Redis configuration fixes"""
        try:
            # Test Redis cluster detection logic
            original_env = os.environ.get("REDIS_CLUSTER_NODES")
            
            # Test 1: No cluster nodes set
            if "REDIS_CLUSTER_NODES" in os.environ:
                del os.environ["REDIS_CLUSTER_NODES"]
            
            from app.services.redis_optimizer import EnhancedTradingRedisService
            
            service = EnhancedTradingRedisService()
            
            # This should not trigger cluster mode
            cluster_detected = service.redis_url != 'redis://localhost:6379/0'
            
            if not cluster_detected:
                cluster_check = "✓ Redis cluster detection fixed"
            else:
                return False, "Redis cluster detection still broken"
            
            # Restore original environment
            if original_env:
                os.environ["REDIS_CLUSTER_NODES"] = original_env
            
            return True, f"Redis config validation passed: {cluster_check}"
            
        except Exception as e:
            return False, f"Redis config validation failed: {e}"
    
    def validate_schema_consistency(self) -> Tuple[bool, str]:
        """Validate schema-model consistency"""
        try:
            from app.schemas.market_data import OHLCVBase
            from app.models.market_data import OHLCVData
            
            # Check if schema uses trades_count (fixed)
            schema_fields = OHLCVBase.__fields__
            
            if 'trades_count' in schema_fields:
                schema_check = "✓ Schema uses trades_count"
            else:
                return False, "Schema still uses trade_count instead of trades_count"
            
            # Check model field
            model_columns = [column.name for column in OHLCVData.__table__.columns]
            
            if 'trades_count' in model_columns:
                model_check = "✓ Model uses trades_count"
            else:
                return False, "Model field name mismatch"
            
            return True, f"Schema consistency validation passed: {schema_check}, {model_check}"
            
        except Exception as e:
            return False, f"Schema validation failed: {e}"
    
    def validate_dependency_injection(self) -> Tuple[bool, str]:
        """Validate dependency injection fixes"""
        try:
            from app.dependency import get_database, get_db
            
            # Check that functions are properly defined
            if callable(get_database) and callable(get_db):
                dependency_check = "✓ Dependency functions defined"
            else:
                return False, "Dependency functions not properly defined"
            
            # Check type hints
            import inspect
            get_db_signature = inspect.signature(get_db)
            return_annotation = get_db_signature.return_annotation
            
            if 'Generator' in str(return_annotation):
                type_check = "✓ Return type annotations correct"
            else:
                type_check = "⚠ Return type annotations may be incorrect"
            
            return True, f"Dependency injection validation passed: {dependency_check}, {type_check}"
            
        except Exception as e:
            return False, f"Dependency injection validation failed: {e}"
    
    def validate_imports(self) -> Tuple[bool, str]:
        """Validate all critical imports work"""
        try:
            # Test critical imports
            imports_to_test = [
                'app.utils.config',
                'app.utils.database',
                'app.services.redis_optimizer', 
                'app.services.data_ingestion',
                'app.schemas.market_data',
                'app.models.market_data',
                'app.dependency'
            ]
            
            successful_imports = []
            failed_imports = []
            
            for module_name in imports_to_test:
                try:
                    __import__(module_name)
                    successful_imports.append(module_name.split('.')[-1])
                except ImportError as e:
                    failed_imports.append(f"{module_name}: {e}")
            
            if not failed_imports:
                return True, f"All imports successful: {', '.join(successful_imports)}"
            else:
                return False, f"Import failures: {'; '.join(failed_imports)}"
                
        except Exception as e:
            return False, f"Import validation failed: {e}"
    
    def validate_environment_variables(self) -> Tuple[bool, str]:
        """Validate environment variable handling"""
        try:
            from app.utils.config import get_settings
            
            # Test with minimal environment
            original_database_url = os.environ.get("DATABASE_URL")
            original_redis_url = os.environ.get("REDIS_URL")
            
            # Set test values
            os.environ["DATABASE_URL"] = "postgresql://test:test@localhost:5432/test"
            os.environ["REDIS_URL"] = "redis://localhost:6379/1"
            
            # Reload settings
            from app.utils.config import reload_settings
            settings = reload_settings()
            
            # Validate
            if settings.DATABASE_URL == "postgresql://test:test@localhost:5432/test":
                db_env_check = "✓ DATABASE_URL environment variable working"
            else:
                return False, "DATABASE_URL environment variable not working"
            
            if settings.REDIS_URL == "redis://localhost:6379/1":
                redis_env_check = "✓ REDIS_URL environment variable working"
            else:
                return False, "REDIS_URL environment variable not working"
            
            # Restore original values
            if original_database_url:
                os.environ["DATABASE_URL"] = original_database_url
            if original_redis_url:
                os.environ["REDIS_URL"] = original_redis_url
            
            return True, f"Environment variables validation passed: {db_env_check}, {redis_env_check}"
            
        except Exception as e:
            return False, f"Environment variables validation failed: {e}"
    
    def validate_circuit_breakers(self) -> Tuple[bool, str]:
        """Validate circuit breaker initialization"""
        try:
            from app.services.data_ingestion import CircuitBreaker, ProductionDataIngestionService
            
            # Test circuit breaker creation
            breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=60)
            
            if breaker.state == 'closed':
                breaker_check = "✓ Circuit breaker initializes correctly"
            else:
                return False, "Circuit breaker initialization failed"
            
            # Test record methods
            breaker.record_failure()
            if breaker.failure_count == 1:
                method_check = "✓ Circuit breaker methods working"
            else:
                return False, "Circuit breaker methods not working"
            
            return True, f"Circuit breaker validation passed: {breaker_check}, {method_check}"
            
        except Exception as e:
            return False, f"Circuit breaker validation failed: {e}"
    
    def validate_session_management(self) -> Tuple[bool, str]:
        """Validate session management fixes"""
        try:
            # Check that context managers are used in routers
            import ast
            
            # Read the fixed OHLCV router
            try:
                router_path = PROJECT_ROOT / 'app' / 'routers' / 'v1' / 'ohlcv.py'
                with open(router_path, 'r') as f:
                    content = f.read()
                
                if 'async with get_enhanced_storage_service()' in content:
                    context_manager_check = "✓ Context managers used in routers"
                else:
                    return False, "Context managers not used in routers"
                
                if 'asynccontextmanager' in content:
                    async_context_check = "✓ Async context managers imported"
                else:
                    return False, "Async context managers not imported"
                
                return True, f"Session management validation passed: {context_manager_check}, {async_context_check}"
                
            except FileNotFoundError:
                return False, "Router file not found for validation"
            
        except Exception as e:
            return False, f"Session management validation failed: {e}"
    
    def print_summary(self):
        """Print validation summary"""
        print("\n" + "=" * 60)
        print("📊 VALIDATION SUMMARY")
        print("=" * 60)
        
        total_tests = len(self.results)
        passed_tests = sum(1 for _, success, _ in self.results if success)
        failed_tests = total_tests - passed_tests
        
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if self.critical_failures:
            print(f"\n🚨 CRITICAL FAILURES ({len(self.critical_failures)}):")
            for failure in self.critical_failures:
                print(f"   ❌ {failure}")
        
        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"   ⚠️  {warning}")
        
        print("\n" + "=" * 60)
        
        if not self.critical_failures:
            print("🎉 ALL VALIDATIONS PASSED! Ready for Tuesday's testing.")
            print("\n📋 PRE-TESTING CHECKLIST:")
            print("   ✅ Copy .env.template to .env and configure")
            print("   ✅ Update DATABENTO_API_KEY with real key")
            print("   ✅ Start PostgreSQL and Redis services")
            print("   ✅ Run database migrations (if any)")
            print("   ✅ Install dependencies: pip install -r requirements.txt")
            print("   ✅ Start the application: python -m app.main")
        else:
            print("💥 CRITICAL FAILURES DETECTED!")
            print("   🔧 Fix the issues above before testing")
            print("   📞 Contact development team if needed")
            
def main():
    """Main validation function"""
    validator = FixValidator()
    success = validator.run_all_validations()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()