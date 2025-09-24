from pathlib import Path
import tempfile
import os
import logging
from typing import Union

logger = logging.getLogger(__name__)
if not logger.hasHandlers():
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)
class FileIOError(Exception):
    pass

class FileReadError(FileIOError):
    pass

class FileWriteError(FileIOError):
    pass

def read_file(path: Union[str, Path]) -> bytes:
    p = Path(path)
    logger.debug("read_file called with path=%s", p)

    if not p.exists():
        logger.error("Input file not found: %s", p)
        raise FileReadError(f"Input file not found: {p}")

    if not p.is_file():
        logger.error("Input path is not a regular file: %s", p)
        raise FileReadError(f"Input path is not a regular file: {p}")

    try:
        with p.open("rb") as f:
            data = f.read()
        logger.info("Successfully read %d bytes from %s", len(data), p)
        return data
    except PermissionError as e:
        logger.exception("Permission denied while reading %s", p)
        raise FileReadError(f"Permission denied: {p}") from e
    except OSError as e:
        logger.exception("OS error while reading %s", p)
        raise FileReadError(f"Error reading {p}: {e}") from e


def write_file(path: Union[str, Path], data: bytes, *,
               create_dirs: bool = False,
               overwrite: bool = True) -> None:
    p = Path(path)
    logger.debug("write_file called with path=%s, len(data)=%s, create_dirs=%s, overwrite=%s",
                 p, len(data) if isinstance(data, (bytes, bytearray)) else "N/A", create_dirs, overwrite)

    if not isinstance(data, (bytes, bytearray)):
        logger.error("Attempt to write non-bytes object: %s", type(data))
        raise FileWriteError("Data to write must be bytes or bytearray")

    parent = p.parent
    if parent and not parent.exists():
        if create_dirs:
            try:
                parent.mkdir(parents=True, exist_ok=True)
                logger.info("Created parent directories: %s", parent)
            except OSError as e:
                logger.exception("Failed to create parent directories: %s", parent)
                raise FileWriteError(f"Cannot create parent directory {parent}: {e}") from e
        else:
            logger.error("Parent directory does not exist: %s", parent)
            raise FileWriteError(f"Parent directory does not exist: {parent}")

    if p.exists() and not overwrite:
        logger.error("Output file exists and overwrite is False: %s", p)
        raise FileWriteError(f"Output file exists: {p}")

    temp_path = None
    try:
        dir_for_temp = str(parent) if parent else None
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=dir_for_temp, prefix=p.name + ".", suffix=".tmp") as tf:
            tf.write(data)
            temp_path = Path(tf.name)
            logger.debug("Wrote %d bytes to temp file %s", len(data), temp_path)
        os.replace(str(temp_path), str(p))
        logger.info("Successfully wrote %d bytes to %s (atomic replace)", len(data), p)
    except PermissionError as e:
        logger.exception("Permission denied while writing to %s", p)
        try:
            if temp_path and temp_path.exists():
                temp_path.unlink()
        except Exception:
            logger.debug("Failed to remove temp file %s", temp_path, exc_info=True)
        raise FileWriteError(f"Permission denied: {p}") from e
    except OSError as e:
        logger.exception("OS error while writing to %s", p)
        try:
            if temp_path and temp_path.exists():
                temp_path.unlink()
        except Exception:
            logger.debug("Failed to remove temp file %s", temp_path, exc_info=True)
        raise FileWriteError(f"Error writing {p}: {e}") from e