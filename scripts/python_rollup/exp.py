def parse(filename):
    """
    Parse an experiment file.
    Lines that define a configuration variable have the format:
       VAR = value
    Other lines define experiments. For tokens starting with '$', the corresponding
    config value is substituted.
    Returns a list of experiments (dictionaries with keys "NAME" and "KNOBS").
    """
    exps = []
    exp_configs = {}
    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            tokens = line.split()
            if len(tokens) < 2:
                continue
            if tokens[1] == "=":
                # Configuration variable line
                exp_configs[tokens[0]] = " ".join(tokens[2:])
            else:
                exp = {}
                exp["NAME"] = tokens[0]
                args = []
                for token in tokens[1:]:
                    if token.startswith("$"):
                        # Remove $, '(', and ')' characters from the token
                        key = token.replace("$", "").replace("(", "").replace(")", "")
                        if key in exp_configs:
                            args.append(exp_configs[key])
                        else:
                            raise ValueError(f"{key} is not defined before exp {tokens[0]}")
                    else:
                        args.append(token)
                exp["KNOBS"] = " ".join(args)
                exps.append(exp)
    return exps
