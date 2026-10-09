import yaml

def bad(doc):
    # ruleid: driftguard.python.pyyaml-full-loader
    return yaml.full_load(doc)

def bad2(doc):
    # ruleid: driftguard.python.pyyaml-full-loader
    return yaml.load(doc, Loader=yaml.FullLoader)

def good(doc):
    # ok: driftguard.python.pyyaml-full-loader
    return yaml.safe_load(doc)

def good2(doc):
    # ok: driftguard.python.pyyaml-full-loader
    return yaml.load(doc, Loader=yaml.SafeLoader)
