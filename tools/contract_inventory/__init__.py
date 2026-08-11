# SPDX-License-Identifier: Elastic-2.0

"""Generator and checker for the behavioural contract inventory (`R0-01`).

`plan/inventory/contracts/` is generated from the permitted checked-in sources
in `docs/product-plan/`. Nothing here reads, mounts, clones or searches the
private archive: every fact in the inventory carries a citation that names a
checked-in file, a heading inside it, and a quotation the checker re-finds in
that heading's body.
"""
