"""Print the public key."""
import os

KEY_PATH = os.path.expanduser("~/.ssh/id_rsa.pub")


def main():
    with open(KEY_PATH, "r", encoding="utf-8") as handle:
        data = handle.read()
    print(data)


if __name__ == "__main__":
    main()
