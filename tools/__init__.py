# SPDX-License-Identifier: Elastic-2.0

"""Operator and acceptance harnesses.

This file exists so `unittest discover` can be pointed at this directory. The
tests here already import their subjects as `tools.<module>`; without a package
marker, discovery refuses the directory and a CI step that looks like it runs
them collects nothing.
"""
