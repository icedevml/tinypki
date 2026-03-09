import os
import re
import random
import string


def secure_random_str(length: int):
    return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(length))


def repl(m):
    key_prefix = m.group(1) + '='
    contents = m.group(2)

    print(f"Populating {m.group(1)} with a secret")

    if contents == 'HEX_16':
        return key_prefix + os.urandom(16).hex().upper()
    elif contents == 'ASCII_32':
        return key_prefix + secure_random_str(32)
    else:
        raise RuntimeError("Unsupported random type: " + contents)


if __name__ == "__main__":
    try:
        os.mkdir("env")
    except FileExistsError:
        pass

    for fn in os.listdir("example-env"):
        fp = os.path.join("example-env", fn)

        with open(fp, "r") as f:
            data = f.read()

        data = re.sub(r'(.*?)=\{\{ RAND_([A-Z0-9_]+) }}', repl, data)

        target_fp = os.path.join("env", fn)
        if fn == "root.env":
            target_fp = ".env"

        print(f"Write {target_fp}")
        with open(target_fp, "w") as f:
            f.write(data)

    print("Generating env/stepca_password")
    with open("env/stepca_password", "w") as f:
        f.write(secure_random_str(32))
