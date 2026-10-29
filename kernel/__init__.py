"""Warrant kernel: labels, plan language, interpreter, policy, approval, execution.

This package is the trusted computing base. It must not import from
``planners``, ``evals`` or ``quarantine`` (enforced by tests/test_import_boundary.py).
"""
