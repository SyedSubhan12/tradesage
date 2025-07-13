#!/usr/bin/env python3
"""
TradeSage Market Data API Health Check Script
Production-grade health checking for container environments
"""

import sys
import os
import time
import json
import socket
import psutil
import requests
from datetime import datetime, timezone
from typing import Dict, Any, Optional

# Add app directory to path
sys.path.append('/app')

# Health check configuration
HEALTH_CHECK_CONFIG = {
    'app_port': int(os.getenv('PORT', 8005)),
    'app_host': os.getenv('HOST', '0.0.0.0'),
    'timeout': int(os.getenv('HEALTH_CHECK_TIMEOUT', 10)),
    'max_memory_mb': int(os.getenv('MAX_MEMORY_MB', 2048)),
    'max_cpu_percent': float(os.getenv('MAX_CPU_PERCENT', 80.0)),
    'max_response_time_ms': int(os.getenv('MAX_RESPONSE_TIME_MS', 5000))
}

class HealthChecker:
    """Comprehensive health checker for production environments"""
    
    def __init__(self):
        self.config = HEALTH_CHECK_CONFIG
        self.checks = {
            'http_endpoint': self.check_http_endpoint,
            'memory_usage': self.check_memory_usage,
            'cpu_usage': self.check_cpu_usage,
            'disk_space': self.check_disk_space,
            'process_status': self.check_process_status
        }
        self.results = {}
    
    def run_all_checks(self) -> Dict[str, Any]:
        """Run all health checks"""
        start_time = time.time()
        
        health_status = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'status': 'healthy',
            'checks': {},
            'summary': {},
            'execution_time_ms': 0
        }
        
        failed_checks = []
        
        for check_name, check_func in self.checks.items():
            try:
                result = check_func()
                health_status['checks'][check_name] = result
                
                if not result.get('healthy', False):
                    failed_checks.append(check_name)
                    
            except Exception as e:
                health_status['checks'][check_name] = {
                    'healthy': False,
                    'error': str(e),
                    'check_failed': True
                }
                failed_checks.append(check_name)
        
        # Overall health status
        if failed_checks:
            health_status['status'] = 'unhealthy'
            health_status['failed_checks'] = failed_checks
        
        # Summary
        total_checks = len(self.checks)
        passed_checks = total_checks - len(failed_checks)
        
        health_status['summary'] = {
            'total_checks': total_checks,
            'passed_checks': passed_checks,
            'failed_checks': len(failed_checks),
            'health_score': (passed_checks / total_checks) * 100
        }
        
        health_status['execution_time_ms'] = round((time.time() - start_time) * 1000, 2)
        
        return health_status
    
    def check_http_endpoint(self) -> Dict[str, Any]:
        """Check if the HTTP endpoint is responding"""
        try:
            url = f"http://localhost:{self.config['app_port']}/health"
            
            start_time = time.time()
            response = requests.get(
                url, 
                timeout=self.config['timeout'],
                headers={'User-Agent': 'HealthCheck/1.0'}
            )
            response_time_ms = round((time.time() - start_time) * 1000, 2)
            
            is_healthy = (
                response.status_code == 200 and 
                response_time_ms < self.config['max_response_time_ms']
            )
            
            return {
                'healthy': is_healthy,
                'status_code': response.status_code,
                'response_time_ms': response_time_ms,
                'endpoint': url,
                'response_body_size': len(response.text) if response.text else 0
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'healthy': False,
                'error': f"HTTP request failed: {str(e)}",
                'endpoint': url
            }
        except Exception as e:
            return {
                'healthy': False,
                'error': f"Unexpected error: {str(e)}"
            }
    
    def check_memory_usage(self) -> Dict[str, Any]:
        """Check memory usage"""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            memory_percent = process.memory_percent()
            memory_mb = memory_info.rss / 1024 / 1024
            
            is_healthy = memory_mb < self.config['max_memory_mb']
            
            return {
                'healthy': is_healthy,
                'memory_mb': round(memory_mb, 2),
                'memory_percent': round(memory_percent, 2),
                'max_memory_mb': self.config['max_memory_mb'],
                'virtual_memory_mb': round(memory_info.vms / 1024 / 1024, 2)
            }
            
        except Exception as e:
            return {
                'healthy': False,
                'error': f"Memory check failed: {str(e)}"
            }
    
    def check_cpu_usage(self) -> Dict[str, Any]:
        """Check CPU usage"""
        try:
            process = psutil.Process()
            cpu_percent = process.cpu_percent(interval=1)
            
            is_healthy = cpu_percent < self.config['max_cpu_percent']
            
            return {
                'healthy': is_healthy,
                'cpu_percent': round(cpu_percent, 2),
                'max_cpu_percent': self.config['max_cpu_percent'],
                'num_threads': process.num_threads(),
                'cpu_times': process.cpu_times()._asdict()
            }
            
        except Exception as e:
            return {
                'healthy': False,
                'error': f"CPU check failed: {str(e)}"
            }
    
    def check_disk_space(self) -> Dict[str, Any]:
        """Check disk space"""
        try:
            disk_usage = psutil.disk_usage('/')
            disk_percent = (disk_usage.used / disk_usage.total) * 100
            
            # Consider unhealthy if disk usage > 90%
            is_healthy = disk_percent < 90.0
            
            return {
                'healthy': is_healthy,
                'disk_percent': round(disk_percent, 2),
                'total_gb': round(disk_usage.total / 1024 / 1024 / 1024, 2),
                'used_gb': round(disk_usage.used / 1024 / 1024 / 1024, 2),
                'free_gb': round(disk_usage.free / 1024 / 1024 / 1024, 2)
            }
            
        except Exception as e:
            return {
                'healthy': False,
                'error': f"Disk check failed: {str(e)}"
            }
    
    def check_process_status(self) -> Dict[str, Any]:
        """Check process status and file descriptors"""
        try:
            process = psutil.Process()
            
            # Check if process is running
            is_running = process.is_running()
            
            # Check file descriptors (if available on platform)
            try:
                num_fds = process.num_fds()
                fd_healthy = num_fds < 1000  # Arbitrary limit
            except (AttributeError, psutil.AccessDenied):
                num_fds = None
                fd_healthy = True
            
            # Check process connections
            try:
                connections = len(process.connections())
                conn_healthy = connections < 500  # Arbitrary limit
            except psutil.AccessDenied:
                connections = None
                conn_healthy = True
            
            is_healthy = is_running and fd_healthy and conn_healthy
            
            return {
                'healthy': is_healthy,
                'is_running': is_running,
                'pid': process.pid,
                'ppid': process.ppid(),
                'status': process.status(),
                'create_time': process.create_time(),
                'num_file_descriptors': num_fds,
                'num_connections': connections
            }
            
        except Exception as e:
            return {
                'healthy': False,
                'error': f"Process check failed: {str(e)}"
            }
    
    def check_port_connectivity(self) -> Dict[str, Any]:
        """Check if the application port is accessible"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            result = sock.connect_ex(('localhost', self.config['app_port']))
            sock.close()
            
            is_healthy = result == 0
            
            return {
                'healthy': is_healthy,
                'port': self.config['app_port'],
                'connection_result': result
            }
            
        except Exception as e:
            return {
                'healthy': False,
                'error': f"Port connectivity check failed: {str(e)}"
            }

def main():
    """Main health check function"""
    try:
        checker = HealthChecker()
        health_result = checker.run_all_checks()
        
        # Print health status for logging
        print(json.dumps(health_result, indent=2))
        
        # Exit with appropriate code
        if health_result['status'] == 'healthy':
            print("✅ Health check passed")
            sys.exit(0)
        else:
            print("❌ Health check failed")
            sys.exit(1)
            
    except Exception as e:
        error_result = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'status': 'unhealthy',
            'error': f"Health check script failed: {str(e)}",
            'critical': True
        }
        
        print(json.dumps(error_result, indent=2))
        print(f"💥 Critical health check error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()