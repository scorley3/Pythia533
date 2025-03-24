#!/usr/bin/env python3
import os
import argparse
import statistics

from trace import parse as parse_trace
from exp import parse as parse_exp
from metric import parse as parse_metric

def trim(s):
    return s.strip()

def convert_tokens(value, mtype):
    """
    Convert a comma-separated string into a list of floats.
    For "mean", "sum", "min", "max", "standard_deviation", and "variance":
        - Split the string and strip each token.
        - Empty tokens are treated as 0.0 (mirroring Perl's behavior in numeric context).
    For "nzmean":
        - Only non-empty tokens are kept.
    """
    if mtype == "nzmean":
        # Filter out empty tokens
        tokens = [t.strip() for t in value.split(",") if t.strip()]
        try:
            numbers = [float(t) for t in tokens]
        except ValueError:
            numbers = []
    else:
        # For mean, sum, etc., treat empty tokens as 0.0.
        tokens = [t.strip() for t in value.split(",")]
        try:
            numbers = [float(t) if t != "" else 0.0 for t in tokens]
        except ValueError:
            numbers = []
    return numbers

def main():
    parser = argparse.ArgumentParser(description="Rollup script in Python")
    parser.add_argument("--tlist", required=True, help="Trace list file")
    parser.add_argument("--exp", required=True, help="Experiment file")
    parser.add_argument("--mfile", required=True, help="Metric file")
    parser.add_argument("--ext", default="out", help="File extension (default 'out')")
    args = parser.parse_args()

    if "PYTHIA_HOME" not in os.environ:
        raise EnvironmentError("PYTHIA_HOME env variable is not defined.\nHave you sourced setvars.sh?")

    tlist_file = args.tlist
    exp_file = args.exp
    mfile = args.mfile
    ext = args.ext

    trace_info = parse_trace(tlist_file)
    exp_info = parse_exp(exp_file)
    m_info = parse_metric(mfile)

    # Print CSV header: Trace,Exp,<metric names>,Filter
    header = ["Trace", "Exp"] + [metric["NAME"] for metric in m_info] + ["Filter"]
    print(",".join(header))

    # Process each trace and experiment
    for trace in trace_info:
        trace_name = trace.get("NAME", "")
        per_trace_result = {}
        all_exps_passed_dict = {}
        for exp in exp_info:
            exp_name = exp.get("NAME", "")
            log_file = f"{trace_name}_{exp_name}.{ext}"
            metric_values = []
            all_exps_passed = True
            records = {}
            if os.path.exists(log_file):
                with open(log_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        if ext == "stats":
                            if "=" in line:
                                key, value = line.split("=", 1)
                                records[trim(key)] = trim(value)
                        else:
                            # If line has exactly one space, split into key and value
                            if line.count(" ") == 1:
                                key, value = line.split(" ", 1)
                                records[trim(key)] = trim(value)
            else:
                all_exps_passed = False

            # Compute each metric's value based on its type
            for metric in m_info:
                mname = metric["NAME"]
                mtype = metric["TYPE"]
                if mname in records:
                    value = records[mname]
                    if mtype == "array":
                        computed_value = value
                    else:
                        numbers = convert_tokens(value, mtype)
                        if not numbers:
                            computed_value = 0
                        else:
                            if mtype == "sum":
                                computed_value = sum(numbers)
                            elif mtype == "mean":
                                computed_value = statistics.mean(numbers)
                            elif mtype == "nzmean":
                                computed_value = statistics.mean(numbers)
                            elif mtype == "min":
                                computed_value = min(numbers)
                            elif mtype == "max":
                                computed_value = max(numbers)
                            elif mtype == "standard_deviation":
                                computed_value = statistics.stdev(numbers) if len(numbers) > 1 else 0
                            elif mtype == "variance":
                                computed_value = statistics.variance(numbers) if len(numbers) > 1 else 0
                            else:
                                raise ValueError("invalid summary type")
                    metric_values.append(str(computed_value))
                else:
                    metric_values.append("0")
                    all_exps_passed = False

            per_trace_result[exp_name] = metric_values
            all_exps_passed_dict[exp_name] = 1 if all_exps_passed else 0

        # Print one CSV line per experiment for the trace
        for exp in exp_info:
            exp_name = exp.get("NAME", "")
            metrics_str = ",".join(per_trace_result.get(exp_name, ["0"] * len(m_info)))
            print(f"{trace_name},{exp_name},{metrics_str},{all_exps_passed_dict.get(exp_name, 0)}")

if __name__ == "__main__":
    main()
