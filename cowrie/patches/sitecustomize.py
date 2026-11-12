"""Loaded automatically by Python at start-up (the compose file puts /cowrie/patches first on
PYTHONPATH). Registers our extra shell commands and applies the realism patches before Cowrie's
modules are used. Failures are printed and swallowed so Cowrie still starts unpatched."""
import sys
import traceback

try:
    import cowrie.commands as _cc

    # Our command module lives outside the image; extend the package path so Cowrie's normal
    # import_module("cowrie.commands.nb_extra") finds it. Listed last, so it overrides built-ins.
    _cc.__path__.append("/cowrie/patches/nbcmds")
    if "nb_extra" not in _cc.command_modules:
        _cc.command_modules.append("nb_extra")
except Exception:
    print("nb-patches: could not register commands", file=sys.stderr)
    traceback.print_exc()

try:
    import nb_patches

    nb_patches.apply()
except Exception:
    print("nb-patches: could not apply patches", file=sys.stderr)
    traceback.print_exc()
