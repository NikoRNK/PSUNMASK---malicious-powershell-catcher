from .cli import main

try:
    raise SystemExit(main())
except BrokenPipeError:  # e.g. `psunmask ... | head`
    raise SystemExit(0)
