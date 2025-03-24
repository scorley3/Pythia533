def trim(s):
    return s.strip()

def parse(filename):
    """
    Parse a metric file.
    Each non-empty, non-comment line should be of the form:
         MetricName: MetricType
    Returns a list of dictionaries with keys "NAME" and "TYPE".
    """
    metric_info = []
    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":", 1)
            if len(parts) < 2:
                continue
            name = trim(parts[0])
            mtype = trim(parts[1])
            metric_info.append({"NAME": name, "TYPE": mtype})
    return metric_info