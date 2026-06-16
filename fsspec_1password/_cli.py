from argparse import ArgumentParser

from ._core import OnePasswordFileSystem, logger


def op_read_cli() -> None:
    parser = ArgumentParser()
    parser.add_argument("paths", nargs="+", help="OnePassword paths to read, e.g. op://vault/item/field")
    args = parser.parse_args()

    content = {}
    fs = OnePasswordFileSystem()
    for path in args.paths:
        try:
            content[path] = fs.cat_file(path)
        except Exception as ex:
            logger.error(f"Problem reading '{path}': {ex}")

    print("\n")
    for path, content in content.items():
        header = f"Content of '{path}'"
        bar = "=" * len(header)
        print(f"{header}\n{bar}\n{content.decode().strip()}\n{bar}\n")
