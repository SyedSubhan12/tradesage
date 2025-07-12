# app/services/backup_service.py

import asyncio
import os
import tempfile
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import asyncpg
import aioboto3
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

logger = structlog.get_logger(__name__)


class TenantBackupService:
    """Service for managing tenant schema backups."""
    
    def __init__(self, db_config: Dict[str, Any], s3_config: Dict[str, Any]):
        """Initialize the backup service.
        
        Args:
            db_config: Database configuration with DSN
            s3_config: S3 configuration for backup storage
        """
        self.db_dsn = db_config['dsn']
        self.s3_bucket = s3_config['bucket']
        self.s3_region = s3_config.get('region_name', 'us-east-1')
        self.backup_retention_days = 30
        
    async def create_tenant_backup(
        self, 
        tenant_id: str, 
        schema_name: str,
        backup_type: str = 'manual'
    ) -> Dict[str, Any]:
        """Create a backup of a tenant schema.
        
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
            with tempfile.NamedTemporaryFile(delete=False, suffix='.sql') as tmp_file:
                backup_path = tmp_file.name
            
            # Perform the backup using pg_dump
            await self._perform_pg_dump(schema_name, backup_path)
            
            # Get file size
            file_size = os.path.getsize(backup_path)
            
            # Upload to S3
            s3_key = await self._upload_to_s3(backup_id, backup_path)
            
            # Clean up temp file
            os.unlink(backup_path)
            
            # Calculate expiration
            expires_at = datetime.utcnow() + timedelta(days=self.backup_retention_days)
            
            # Store backup metadata
            backup_metadata = {
                "backup_id": backup_id,
                "tenant_id": tenant_id,
                "schema_name": schema_name,
                "backup_path": s3_key,
                "size_bytes": file_size,
                "backup_type": backup_type,
                "created_at": datetime.utcnow(),
                "expires_at": expires_at,
                "status": "completed"
            }
            
            # Save to database
            await self._save_backup_metadata(backup_metadata)
            
            logger.info(
                "Backup created successfully",
                backup_id=backup_id,
                tenant_id=tenant_id,
                size_mb=file_size / (1024 * 1024)
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
    
    async def _perform_pg_dump(self, schema_name: str, output_path: str):
        """Perform PostgreSQL schema dump."""
        # Parse connection string
        import urllib.parse
        parsed = urllib.parse.urlparse(self.db_dsn)
        
        # Build pg_dump command
        cmd = [
            'pg_dump',
            '-h', parsed.hostname,
            '-p', str(parsed.port or 5432),
            '-U', parsed.username,
            '-d', parsed.path[1:],  # Remove leading /
            '-n', schema_name,      # Specific schema only
            '-f', output_path,
            '--no-owner',
            '--no-privileges',
            '--if-exists',
            '--clean',
            '--verbose'
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
        
        logger.info("Schema dump completed", schema_name=schema_name)
    
    async def _upload_to_s3(self, backup_id: str, file_path: str) -> str:
        """Upload backup file to S3."""
        s3_key = f"tenant-backups/{backup_id}/{os.path.basename(file_path)}"
        
        async with aioboto3.Session().client(
            's3',
            region_name=self.s3_region
        ) as s3_client:
            with open(file_path, 'rb') as f:
                await s3_client.put_object(
                    Bucket=self.s3_bucket,
                    Key=s3_key,
                    Body=f.read(),
                    ServerSideEncryption='AES256',
                    StorageClass='STANDARD_IA'  # Infrequent access for cost savings
                )
        
        logger.info("Backup uploaded to S3", s3_key=s3_key)
        return s3_key
    
    async def _save_backup_metadata(self, metadata: Dict[str, Any]):
        """Save backup metadata to database."""
        # Create connection pool
        pool = await asyncpg.create_pool(self.db_dsn)
        
        try:
            async with pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO tenant_backups (
                        tenant_id, backup_id, schema_name, backup_path,
                        size_bytes, backup_type, created_at, expires_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """,
                metadata["tenant_id"],
                metadata["backup_id"],
                metadata["schema_name"],
                metadata["backup_path"],
                metadata["size_bytes"],
                metadata["backup_type"],
                metadata["created_at"],
                metadata["expires_at"]
                )
        finally:
            await pool.close()
    
    async def restore_tenant_backup(
        self, 
        tenant_id: str, 
        backup_id: str,
        target_schema: Optional[str] = None
    ) -> Dict[str, Any]:
        """Restore a tenant backup.
        
        Args:
            tenant_id: Tenant identifier
            backup_id: Backup to restore
            target_schema: Target schema name (optional, creates new if not specified)
            
        Returns:
            Restore operation details
        """
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
            # Download backup from S3
            with tempfile.NamedTemporaryFile(delete=False, suffix='.sql') as tmp_file:
                restore_path = tmp_file.name
            
            await self._download_from_s3(backup['backup_path'], restore_path)
            
            # Create target schema
            await self._create_restore_schema(target_schema)
            
            # Restore the backup
            await self._perform_pg_restore(target_schema, restore_path)
            
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
    
    async def _download_from_s3(self, s3_key: str, local_path: str):
        """Download backup file from S3."""
        async with aioboto3.Session().client(
            's3',
            region_name=self.s3_region
        ) as s3_client:
            response = await s3_client.get_object(
                Bucket=self.s3_bucket,
                Key=s3_key
            )
            
            content = await response['Body'].read()
            
            with open(local_path, 'wb') as f:
                f.write(content)
        
        logger.info("Backup downloaded from S3", s3_key=s3_key)
    
    async def _create_restore_schema(self, schema_name: str):
        """Create schema for restore operation."""
        pool = await asyncpg.create_pool(self.db_dsn)
        
        try:
            async with pool.acquire() as conn:
                await conn.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema_name}"')
        finally:
            await pool.close()
    
    async def _perform_pg_restore(self, schema_name: str, restore_path: str):
        """Perform PostgreSQL restore."""
        # Parse connection string
        import urllib.parse
        parsed = urllib.parse.urlparse(self.db_dsn)
        
        # Build psql command (pg_restore doesn't work well with plain SQL dumps)
        cmd = [
            'psql',
            '-h', parsed.hostname,
            '-p', str(parsed.port or 5432),
            '-U', parsed.username,
            '-d', parsed.path[1:],
            '-f', restore_path
        ]
        
        # Set PGPASSWORD environment variable
        env = os.environ.copy()
        env['PGPASSWORD'] = parsed.password
        
        # Execute restore
        process = await asyncio.create_subprocess_exec(
            *cmd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise Exception(f"Restore failed: {stderr.decode()}")
    
    async def _get_backup_metadata(self, backup_id: str) -> Optional[Dict[str, Any]]:
        """Get backup metadata from database."""
        pool = await asyncpg.create_pool(self.db_dsn)
        
        try:
            async with pool.acquire() as conn:
                row = await conn.fetchrow("""
                    SELECT * FROM tenant_backups
                    WHERE backup_id = $1 AND is_deleted = false
                """, backup_id)
                
                if row:
                    return dict(row)
                return None
        finally:
            await pool.close()
    
    async def list_tenant_backups(
        self, 
        tenant_id: str,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """List backups for a tenant."""
        pool = await asyncpg.create_pool(self.db_dsn)
        
        try:
            async with pool.acquire() as conn:
                rows = await conn.fetch("""
                    SELECT * FROM tenant_backups
                    WHERE tenant_id = $1 AND is_deleted = false
                    ORDER BY created_at DESC
                    LIMIT $2
                """, tenant_id, limit)
                
                return [dict(row) for row in rows]
        finally:
            await pool.close()
    
    async def cleanup_expired_backups(self):
        """Clean up expired backups from S3 and database."""
        pool = await asyncpg.create_pool(self.db_dsn)
        
        try:
            async with pool.acquire() as conn:
                # Get expired backups
                expired = await conn.fetch("""
                    SELECT backup_id, backup_path
                    FROM tenant_backups
                    WHERE expires_at < NOW() AND is_deleted = false
                """)
                
                for row in expired:
                    try:
                        # Delete from S3
                        await self._delete_from_s3(row['backup_path'])
                        
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
    
    async def _delete_from_s3(self, s3_key: str):
        """Delete backup file from S3."""
        async with aioboto3.Session().client(
            's3',
            region_name=self.s3_region
        ) as s3_client:
            await s3_client.delete_object(
                Bucket=self.s3_bucket,
                Key=s3_key
            )
    
    async def _log_backup_failure(self, tenant_id: str, schema_name: str, error: str):
        """Log backup failure for monitoring."""
        logger.error(
            "Backup operation failed",
            tenant_id=tenant_id,
            schema_name=schema_name,
            error=error,
            timestamp=datetime.utcnow().isoformat()
        )
    
    async def _log_restore_operation(self, tenant_id: str, backup_id: str, target_schema: str):
        """Log restore operation for audit trail."""
        logger.info(
            "Restore operation completed",
            tenant_id=tenant_id,
            backup_id=backup_id,
            target_schema=target_schema,
            timestamp=datetime.utcnow().isoformat()
        ) 