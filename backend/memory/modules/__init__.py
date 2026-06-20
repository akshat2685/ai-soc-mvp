"""16 memory modules. Each module is a thin writer that fans writes out to the
appropriate store layers (Structured + Semantic + Graph) and registers the
record in unified memory metadata + temporal versioning.
"""
