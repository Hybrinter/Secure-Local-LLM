import ast
import os
import pathlib
import stat
import sys

root = pathlib.Path("/workspace/repo")
fd = os.open(root / "calculator.py", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
with os.fdopen(fd, "rb") as source:
    if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
        sys.exit("calculator must be a regular file")
    data = source.read(65537)
if len(data) > 65536:
    sys.exit("calculator exceeds the demo source limit")
tree = ast.parse(data)
expected_tree = ast.parse("def add(left, right):\n    return left + right\n")
if ast.dump(tree) != ast.dump(expected_tree):
    sys.exit("calculator does not match the permitted addition implementation")
namespace = {"__builtins__": {}}
exec(compile(tree, "verified-calculator", "exec"), namespace)
cases = ((2, 3, 5), (-2, 3, 1), (0, 0, 0), (-8, -5, -13),
         (1.5, 2.25, 3.75), (999, 1, 1000))
for left, right, expected in cases:
    if namespace["add"](left, right) != expected:
        sys.exit("independent addition check failed")
print("independent addition checks passed")
