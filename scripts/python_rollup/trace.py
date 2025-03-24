def parse(filename):
    """
    Parse a trace list file into a list of dictionaries.
    A new record starts when a line with key 'NAME' is encountered.
    """
    trace_info = []
    rec = None
    with open(filename, "r") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            idx = line.find("=")
            if idx == -1:
                continue
            key = line[:idx].strip()
            value = line[idx+1:].strip()
            if key == "NAME":
                if rec is not None:
                    trace_info.append(rec)
                rec = {}
            if rec is None:
                rec = {}
            rec[key] = value
        if rec:
            trace_info.append(rec)
    return trace_info
