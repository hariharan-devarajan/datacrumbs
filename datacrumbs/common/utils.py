import logging
import hashlib
from datacrumbs.common.status import ProfilerStatus


def convert_or_fail(type, value):
    try:
        return ProfilerStatus.SUCCESS, type(value)
    except Exception as e:
        logging.error(f"Type conversion for type {type} failed for value {value}")
        return ProfilerStatus.CONVERT_ERROR, type()
    
def get_hash(string):
    result = hashlib.md5(string.encode())
    return int(result.hexdigest(), 16)