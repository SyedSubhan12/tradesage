import os
import sys

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Print environment variables
print(f"DATABASE_URL environment variable: {os.environ.get('DATABASE_URL')}")

# Try to import settings from common.config
try:
    from common.config import settings
    print(f"settings.database_url: {settings.database_url}")
except Exception as e:
    print(f"Error importing settings: {e}")

# Check if .env file exists and print its contents
env_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'common', '.env')
if os.path.exists(env_file_path):
    print(f"\n.env file exists at {env_file_path}")
    try:
        with open(env_file_path, 'r') as f:
            print("Contents of .env file:")
            for line in f:
                if line.strip() and not line.strip().startswith('#'):
                    print(f"  {line.strip()}")
    except Exception as e:
        print(f"Error reading .env file: {e}")
else:
    print(f"\n.env file does not exist at {env_file_path}")

# Try to import db_manager from common.database
print("\nChecking common.database imports:")
try:
    import common.database
    print(f"common.database imported successfully")
    print(f"common.database.settings.database_url: {common.database.settings.database_url}")
except Exception as e:
    print(f"Error importing common.database: {e}")