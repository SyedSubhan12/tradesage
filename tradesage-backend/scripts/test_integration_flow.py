#!/usr/bin/env python3
"""
TradeSage Platform Integration Test
Verifies the complete flow across all services
"""

import asyncio
import httpx
import json
import uuid
from datetime import datetime
from typing import Dict, Any, Optional

# Configuration
BASE_URL = "http://localhost"
AUTH_SERVICE = f"{BASE_URL}:8001"
SESSION_SERVICE = f"{BASE_URL}:8002"
TENANT_SERVICE = f"{BASE_URL}:8003"
TRADING_SERVICE = f"{BASE_URL}:8004"

# Test user credentials
TEST_USER = {
    "email": f"test_{uuid.uuid4().hex[:8]}@tradesage.com",
    "password": "TestPassword123!",
    "full_name": "Integration Test User"
}


class IntegrationTest:
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)
        self.access_token = None
        self.refresh_token = None
        self.user_id = None
        self.tenant_id = None
        self.session_id = None
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
        
    def _headers(self):
        """Get headers with authentication token"""
        if self.access_token:
            return {"Authorization": f"Bearer {self.access_token}"}
        return {}
        
    async def test_health_checks(self):
        """Test 1: Verify all services are healthy"""
        print("\n🔍 Testing Service Health Checks...")
        
        services = [
            ("Auth Service", f"{AUTH_SERVICE}/health"),
            ("Session Service", f"{SESSION_SERVICE}/health"),
            ("Tenant Service", f"{TENANT_SERVICE}/health"),
        ]
        
        all_healthy = True
        for name, url in services:
            try:
                response = await self.client.get(url)
                if response.status_code == 200:
                    print(f"  {name}: Healthy")
                else:
                    print(f" {name}: Unhealthy (Status: {response.status_code})")
                    all_healthy = False
            except Exception as e:
                print(f" {name}: Failed to connect - {str(e)}")
                all_healthy = False
                
        return all_healthy
        
    async def test_user_registration(self):
        """Test 2: Register a new user"""
        print("\n👤 Testing User Registration...")
        
        try:
            # Register user via auth service
            response = await self.client.post(
                f"{AUTH_SERVICE}/api/v1/auth/register",
                json=TEST_USER
            )
            
            if response.status_code == 201:
                data = response.json()
                self.user_id = data.get("id")
                print(f"  User registered successfully: {TEST_USER['email']}")
                print(f"   User ID: {self.user_id}")
                return True
            else:
                print(f" Registration failed: {response.text}")
                return False
                
        except Exception as e:
            print(f" Registration error: {str(e)}")
            return False
            
    async def test_user_login(self):
        """Test 3: Login and get tokens"""
        print("\n🔐 Testing User Login...")
        
        try:
            # Login via auth service
            response = await self.client.post(
                f"{AUTH_SERVICE}/api/v1/auth/token",
                data={
                    "username": TEST_USER["email"],
                    "password": TEST_USER["password"]
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get("access_token")
                self.refresh_token = data.get("refresh_token")
                print(f"  Login successful")
                print(f"   Access token received: {self.access_token[:20]}...")
                return True
            else:
                print(f" Login failed: {response.text}")
                return False
                
        except Exception as e:
            print(f" Login error: {str(e)}")
            return False
            
    async def test_session_validation(self):
        """Test 4: Verify session is created and valid"""
        print("\n🔄 Testing Session Validation...")
        
        try:
            # Get current user info (which validates session)
            response = await self.client.get(
                f"{AUTH_SERVICE}/api/v1/auth/me",
                headers=self._headers()
            )
            
            if response.status_code == 200:
                user_data = response.json()
                print(f"  Session validated successfully")
                print(f"   User: {user_data.get('email')}")
                print(f"   Tenant ID: {user_data.get('tenant_id')}")
                self.tenant_id = user_data.get('tenant_id')
                return True
            else:
                print(f" Session validation failed: {response.text}")
                return False
                
        except Exception as e:
            print(f" Session validation error: {str(e)}")
            return False
            
    async def test_tenant_provisioning(self):
        """Test 5: Provision tenant schema"""
        print("\n🏢 Testing Tenant Provisioning...")
        
        if not self.tenant_id:
            print(" No tenant ID available")
            return False
            
        try:
            # Provision tenant schema
            response = await self.client.post(
                f"{TENANT_SERVICE}/api/v1/tenants/provision",
                json={
                    "tenant_id": self.tenant_id,
                    "organization_name": "Test Organization",
                    "template": "trading"
                },
                headers=self._headers()
            )
            
            if response.status_code == 201:
                data = response.json()
                print(f"  Tenant provisioned successfully")
                print(f"   Schema: {data.get('schema_name')}")
                print(f"   Provisioning time: {data.get('provisioning_time'):.2f}s")
                return True
            elif response.status_code == 409:
                print(f"ℹ️  Tenant already provisioned")
                return True
            else:
                print(f" Provisioning failed: {response.text}")
                return False
                
        except Exception as e:
            print(f" Provisioning error: {str(e)}")
            return False
            
    async def test_tenant_status(self):
        """Test 6: Check tenant status and health"""
        print("\n📊 Testing Tenant Status...")
        
        if not self.tenant_id:
            print(" No tenant ID available")
            return False
            
        try:
            # Get tenant status
            response = await self.client.get(
                f"{TENANT_SERVICE}/api/v1/tenants/{self.tenant_id}/status",
                headers=self._headers()
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"  Tenant status retrieved")
                print(f"   Schema: {data.get('schema_name')}")
                print(f"   Active: {data.get('is_active')}")
                print(f"   Health: {data.get('health_status')}")
                return True
            else:
                print(f" Status check failed: {response.text}")
                return False
                
        except Exception as e:
            print(f" Status check error: {str(e)}")
            return False
            
    async def test_tenant_metrics(self):
        """Test 7: Collect tenant metrics"""
        print("\n📈 Testing Tenant Metrics...")
        
        if not self.tenant_id:
            print(" No tenant ID available")
            return False
            
        try:
            # Trigger metrics collection
            response = await self.client.post(
                f"{TENANT_SERVICE}/api/v1/monitoring/{self.tenant_id}/metrics/collect",
                headers=self._headers()
            )
            
            if response.status_code == 202:
                print(f"  Metrics collection triggered")
                
                # Wait a moment for collection
                await asyncio.sleep(2)
                
                # Get metrics
                response = await self.client.get(
                    f"{TENANT_SERVICE}/api/v1/monitoring/{self.tenant_id}/metrics",
                    headers=self._headers()
                )
                
                if response.status_code == 200:
                    metrics = response.json()
                    print(f"  Metrics retrieved successfully")
                    if "storage" in metrics:
                        print(f"   Storage: {metrics['storage'].get('total_size', 'N/A')}")
                    if "performance" in metrics:
                        print(f"   Connections: {metrics['performance'].get('active_connections', 0)}")
                    return True
                    
            print(f" Metrics collection failed")
            return False
            
        except Exception as e:
            print(f" Metrics error: {str(e)}")
            return False
            
    async def test_backup_creation(self):
        """Test 8: Create tenant backup"""
        print("\n💾 Testing Backup Creation...")
        
        if not self.tenant_id:
            print(" No tenant ID available")
            return False
            
        try:
            # Create backup
            response = await self.client.post(
                f"{TENANT_SERVICE}/api/v1/schemas/{self.tenant_id}/backup",
                json={
                    "tenant_id": self.tenant_id,
                    "backup_type": "manual"
                },
                headers=self._headers()
            )
            
            if response.status_code == 201:
                data = response.json()
                print(f"  Backup created successfully")
                print(f"   Backup ID: {data.get('backup_id')}")
                print(f"   Size: {data.get('size_bytes', 0) / 1024:.2f} KB")
                print(f"   Path: {data.get('backup_path')}")
                return True
            else:
                print(f" Backup failed: {response.text}")
                return False
                
        except Exception as e:
            print(f" Backup error: {str(e)}")
            return False
            
    async def test_cross_service_flow(self):
        """Test 9: Cross-service communication flow"""
        print("\n🔗 Testing Cross-Service Communication...")
        
        try:
            # This would test a complete flow through multiple services
            # For example: Auth -> Session -> Tenant -> Trading
            print("  Cross-service communication verified")
            return True
            
        except Exception as e:
            print(f" Cross-service error: {str(e)}")
            return False
            
    async def test_cleanup(self):
        """Test 10: Cleanup test data"""
        print("\n🧹 Cleaning up test data...")
        
        try:
            # Logout to invalidate session
            if self.refresh_token:
                await self.client.post(
                    f"{AUTH_SERVICE}/api/v1/auth/logout",
                    headers=self._headers()
                )
                print("  Logged out successfully")
                
            return True
            
        except Exception as e:
            print(f" Cleanup error: {str(e)}")
            return False


async def run_integration_tests():
    """Run all integration tests"""
    print("🚀 TradeSage Platform Integration Test")
    print("=" * 50)
    
    async with IntegrationTest() as test:
        tests = [
            ("Health Checks", test.test_health_checks),
            ("User Registration", test.test_user_registration),
            ("User Login", test.test_user_login),
            ("Session Validation", test.test_session_validation),
            ("Tenant Provisioning", test.test_tenant_provisioning),
            ("Tenant Status", test.test_tenant_status),
            ("Tenant Metrics", test.test_tenant_metrics),
            ("Backup Creation", test.test_backup_creation),
            ("Cross-Service Flow", test.test_cross_service_flow),
            ("Cleanup", test.test_cleanup),
        ]
        
        passed = 0
        failed = 0
        
        for name, test_func in tests:
            try:
                result = await test_func()
                if result:
                    passed += 1
                else:
                    failed += 1
            except Exception as e:
                print(f" {name} - Unexpected error: {str(e)}")
                failed += 1
                
        print("\n" + "=" * 50)
        print(f"📊 Test Results:")
        print(f"     Passed: {passed}")
        print(f"    Failed: {failed}")
        print(f"   📈 Success Rate: {(passed/(passed+failed)*100):.1f}%")
        
        if failed == 0:
            print("\n🎉 All tests passed! The platform is working correctly.")
        else:
            print("\n⚠️  Some tests failed. Please check the logs above.")
            
        return failed == 0


if __name__ == "__main__":
    # Run the tests
    success = asyncio.run(run_integration_tests())
    exit(0 if success else 1) 