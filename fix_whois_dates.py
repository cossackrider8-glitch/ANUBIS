import re
import json
from datetime import datetime

def convert_dates(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, list):
        return [convert_dates(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: convert_dates(v) for k, v in obj.items()}
    else:
        return obj
