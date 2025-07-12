# app/services/backup_service_ma130.py

import asyncio
import os
import tempfile
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import asyncpg
import asyncssh
import aiofiles
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

logger = structlog.get_logger(__name__)


class MA130BackupService:
    """Backup service using MA130 server for storage."""
    
    def __init__(self, db_config: Dict[str, Any], ma130_config: Dict[str, Any]):
        """Initialize the backup service with MA130 configuration.
        
        Args:
            db_config: Database configuration with DSN
            ma130_config: MA130 server configuration
                - host: MA130 server hostname/IP
                - port: SSH port (default 22)
                - username: SSH username
                - password: SSH password (or use key_path)
                - key_path: Path to SSH private key
                - backup_path: Remote path for backups
        """
        self.db_dsn = db_config['dsn']
        self.ma130_host = ma130_config['host']
        self.ma130_port = ma130_config.get('port', 22)
        self.ma130_username = ma130_config['username']
        self.ma130_password = ma130_config.get('password')
        self.ma130_key_path = ma130_config.get('key_path')
        self.ma130_backup_path = ma130_config.get('backup_path', '/backups/tradesage')
        self.backup_retention_days = 30
        
        # Connection pool for SSH
        self._ssh_conn = None
        
    async def _get_ssh_connection(self):
        """Get or create SSH connection to MA130."""
        if self._ssh_conn is None or self._ssh_conn.is_closed:
            connect_kwargs = {
                'host': self.ma130_host,
                'port': self.ma130_port,
                'username': self.ma130_username,
                'known_hosts': None  # You should use proper host verification in production
            }
            
            if self.ma130_password:
                connect_kwargs['password'] = self.ma130_password
            elif self.ma130_key_path:
                connect_kwargs['client_keys'] = [self.ma130_key_path]
            
            self._ssh_conn = await asyncssh.connect(**connect_kwargs)
            
        return self._ssh_conn
    
    async def create_tenant_backup(
        self, 
        tenant_id: str, 
        schema_name: str,
        backup_type: str = 'manual'
    ) -> Dict[str, Any]:
        """Create a backup of a tenant schema on MA130 server.
        
        Args:
            tenant_id: Tenant identifier
            schema_name: Schema to backup
            backup_type: Type of backup (manual, scheduled, pre_migration)
            
        Returns:
            Backup metadata
        """
        backup_id = f"backup_{tenant_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        try:
            # Create temporary file for backup
            with tempfile.NamedTemporaryFile(delete=False, suffix='.sql.gz') as tmp_file:
                backup_path = tmp_file.name
            
            # Perform the backup using pg_dump with compression
            await self._perform_pg_dump_compressed(schema_name, backup_path)
            
            # Get file size
            file_size = os.path.getsize(backup_path)
            
            # Upload to MA130
            remote_path = await self._upload_to_ma130(backup_id, backup_path)
            
            # Verify backup on MA130
            await self._verify_remote_backup(remote_path)
            
            # Clean up temp file
            os.unlink(backup_path)
            
            # Calculate expiration
            expires_at = datetime.utcnow() + timedelta(days=self.backup_retention_days)
            
            # Store backup metadata
            backup_metadata = {
                "backup_id": backup_id,
                "tenant_id": tenant_id,
                "schema_name": schema_name,
                "backup_path": remote_path,
                "size_bytes": file_size,
                "backup_type": backup_type,
                "created_at": datetime.utcnow(),
                "expires_at": expires_at,
                "status": "completed",
                "storage_type": "ma130"
            }
            
            # Save to database
            await self._save_backup_metadata(backup_metadata)
            
            logger.info(
                "Backup created on MA130",
                backup_id=backup_id,
                tenant_id=tenant_id,
                size_mb=file_size / (1024 * 1024),
                remote_path=remote_path
            )
            
            return backup_metadata
            
        except Exception as e:
            logger.error(
                "Backup failed",
                tenant_id=tenant_id,
                error=str(e),
                exc_info=True
            )
            
            # Log failed backup
            await self._log_backup_failure(tenant_id, schema_name, str(e))
            raise
    
    async def _perform_pg_dump_compressed(self, schema_name: str, output_path: str):
        """Perform PostgreSQL schema dump with compression."""
        import urllib.parse
        parsed = urllib.parse.urlparse(self.db_dsn)
        
        # Build pg_dump command with gzip compression
        cmd = [
            'pg_dump',
            '-h', parsed.hostname,
            '-p', str(parsed.port or 5432),
            '-U', parsed.username,
            '-d', parsed.path[1:],
            '-n', schema_name,
            '--no-owner',
            '--no-privileges',
            '--if-exists',
            '--clean',
            '--verbose',
            '-Z', '9',  # Maximum compression
            '-f', output_path
        ]
        
        # Set PGPASSWORD environment variable
        env = os.environ.copy()
        env['PGPASSWORD'] = parsed.password
        
        # Execute pg_dump
        process = await asyncio.create_subprocess_exec(
            *cmd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise Exception(f"pg_dump failed: {stderr.decode()}")
        
        logger.info("Compressed schema dump completed", schema_name=schema_name)
    
    async def _upload_to_ma130(self, backup_id: str, local_path: str) -> str:
        """Upload backup file to MA130 server via SSH/SFTP."""
        # Create directory structure
        date_path = datetime.utcnow().strftime('%Y/%m/%d')
        remote_dir = f"{self.ma130_backup_path}/{date_path}"
        remote_path = f"{remote_dir}/{backup_id}.sql.gz"
        
        # Get SSH connection
        ssh_conn = await self._get_ssh_connection()
        
        # Create remote directory if it doesn't exist
        await ssh_conn.run(f'mkdir -p {remote_dir}', check=True)
        
        # Upload file using SFTP
        async with ssh_conn.start_sftp_client() as sftp:
            await sftp.put(local_path, remote_path)
            
            # Set appropriate permissions
            await sftp.chmod(remote_path, 0o640)
        
        logger.info("Backup uploaded to MA130", remote_path=remote_path)
        return remote_path
    
    async def _verify_remote_backup(self, remote_path: str):
        """Verify backup integrity on MA130."""
        ssh_conn = await self._get_ssh_connection()
        
        # Check if file exists and get size
        result = await ssh_conn.run(f'ls -la {remote_path}', check=True)
        
        # Verify gzip integrity
        verify_result = await ssh_conn.run(f'gzip -t {remote_path}', check=True)
        
        if verify_result.returncode != 0:
            raise Exception(f"Backup verification failed: {verify_result.stderr}")
        
        logger.info("Remote backup verified", remote_path=remote_path)
    
    async def restore_tenant_backup(
        self, 
        tenant_id: str, 
        backup_id: str,
        target_schema: Optional[str] = None
    ) -> Dict[str, Any]:
        """Restore a tenant backup from MA130 server."""
        # Get backup metadata
        backup = await self._get_backup_metadata(backup_id)
        
        if not backup:
            raise ValueError(f"Backup {backup_id} not found")
        
        if backup['tenant_id'] != tenant_id:
            raise ValueError("Backup does not belong to this tenant")
        
        # Generate target schema if not provided
        if not target_schema:
            target_schema = f"restored_{backup['schema_name']}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            # Download backup from MA130
            with tempfile.NamedTemporaryFile(delete=False, suffix='.sql.gz') as tmp_file:
                restore_path = tmp_file.name
            
            await self._download_from_ma130(backup['backup_path'], restore_path)
            
            # Create target schema
            await self._create_restore_schema(target_schema)
            
            # Restore the backup
            await self._perform_pg_restore_compressed(target_schema, restore_path)
            
            # Clean up temp file
            os.unlink(restore_path)
            
            # Log restore operation
            await self._log_restore_operation(tenant_id, backup_id, target_schema)
            
            logger.info(
                "Backup restored successfully",
                backup_id=backup_id,
                target_schema=target_schema
            )
            
            return {
                "backup_id": backup_id,
                "target_schema": target_schema,
                "restored_at": datetime.utcnow(),
                "status": "completed"
            }
            
        except Exception as e:
            logger.error(
                "Restore failed",
                backup_id=backup_id,
                error=str(e),
                exc_info=True
            )
            raise
    
    async def _download_from_ma130(self, remote_path: str, local_path: str):
        """Download backup file from MA130 server."""
        ssh_conn = await self._get_ssh_connection()
        
        # Download file using SFTP
        async with ssh_conn.start_sftp_client() as sftp:
            await sftp.get(remote_path, local_path)
        
        logger.info("Backup downloaded from MA130", remote_path=remote_path)
    
    async def _perform_pg_restore_compressed(self, schema_name: str, restore_path: str):
        """Perform PostgreSQL restore from compressed backup."""
        import urllib.parse
        parsed = urllib.parse.urlparse(self.db_dsn)
        
        # First decompress the file
        decompress_cmd = ['gzip', '-d', '-c', restore_path]
        
        # Then pipe to psql
        psql_cmd = [
            'psql',
            '-h', parsed.hostname,
            '-p', str(parsed.port or 5432),
            '-U', parsed.username,
            '-d', parsed.path[1:],
        ]
        
        # Set PGPASSWORD environment variable
        env = os.environ.copy()
        env['PGPASSWORD'] = parsed.password
        
        # Create processes
        decompress_proc = await asyncio.create_subprocess_exec(
            *decompress_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        psql_proc = await asyncio.create_subprocess_exec(
            *psql_cmd,
            stdin=decompress_proc.stdout,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env
        )
        
        # Wait for completion
        psql_stdout, psql_stderr = await psql_proc.communicate()
        
        if psql_proc.returncode != 0:
            raise Exception(f"Restore failed: {psql_stderr.decode()}")
    
    async def setup_ma130_monitoring(self):
        """Setup monitoring for MA130 backup storage."""
        ssh_conn = await self._get_ssh_connection()
        
        # Check disk usage
        df_result = await ssh_conn.run(f'df -h {self.ma130_backup_path}', check=True)
        
        # Parse disk usage
        lines = df_result.stdout.strip().split('\n')
        if len(lines) >= 2:
            fields = lines[1].split()
            if len(fields) >= 5:
                usage_percent = fields[4].rstrip('%')
                
                logger.info(
                    "MA130 storage status",
                    backup_path=self.ma130_backup_path,
                    usage_percent=usage_percent
                )
                
                # Alert if usage is high
                if int(usage_percent) > 80:
                    logger.warning(
                        "MA130 storage usage high",
                        usage_percent=usage_percent
                    )
        
        return {
            "storage_path": self.ma130_backup_path,
            "usage_percent": usage_percent,
            "status": "healthy" if int(usage_percent) < 80 else "warning"
        }
    
    async def cleanup_expired_backups_ma130(self):
        """Clean up expired backups from MA130 server."""
        pool = await asyncpg.create_pool(self.db_dsn)
        
        try:
            async with pool.acquire() as conn:
                # Get expired backups
                expired = await conn.fetch("""
                    SELECT backup_id, backup_path
                    FROM tenant_backups
                    WHERE expires_at < NOW() 
                    AND is_deleted = false
                    AND backup_path LIKE '%ma130%'
                """)
                
                ssh_conn = await self._get_ssh_connection()
                
                for row in expired:
                    try:
                        # Delete from MA130
                        await ssh_conn.run(f'rm -f {row["backup_path"]}', check=True)
                        
                        # Mark as deleted in database
                        await conn.execute("""
                            UPDATE tenant_backups
                            SET is_deleted = true
                            WHERE backup_id = $1
                        """, row['backup_id'])
                        
                        logger.info("Expired backup cleaned up", backup_id=row['backup_id'])
                        
                    except Exception as e:
                        logger.error(
                            "Failed to cleanup backup",
                            backup_id=row['backup_id'],
                            error=str(e)
                        )
        finally:
            await pool.close()
            
    # ... (remaining helper methods same as original backup_service.py) 