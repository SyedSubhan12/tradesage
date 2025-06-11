import tomli
import sys

with open(sys.argv[1], "rb") as f:
    try:
        tomli.load(f)
        print("✅ Valid TOML")
    except tomli.TOMLDecodeError as e:
        print(f"❌ Invalid TOML: {e}")