# SPDX-License-Identifier: Elastic-2.0

"""Parity-oracle release boundary (BOOT-004, GATE-ORACLE).

The clean side imports this package. It never imports anything that holds
legacy source: the only value that crosses the boundary is a `Verdict` rebuilt
from this package's own constants.
"""
