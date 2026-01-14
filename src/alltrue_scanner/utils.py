# Shared utility functions

from typing import List, Union


def parse_csv_string(value: Union[str, List, None]) -> List[str]:
    """
    Parse comma-separated string or list into list of strings.
    
    Args:
        value: Can be None, a string (comma-separated), or a list/tuple
        
    Returns:
        List of non-empty trimmed strings
        
    Examples:
        >>> parse_csv_string("a, b, c")
        ['a', 'b', 'c']
        >>> parse_csv_string(["x", "y", "z"])
        ['x', 'y', 'z']
        >>> parse_csv_string(None)
        []
        >>> parse_csv_string("")
        []
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [s.strip() for s in str(value).split(",") if s.strip()]