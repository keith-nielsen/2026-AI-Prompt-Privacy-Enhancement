"""Evaluation against public labelled datasets, with one scoring protocol for every system.

`datasets` pins each dataset (revision, file hashes, licence) and loads it; `scoring` compares a
system's spans with the gold spans; `systems` wraps the detectors under test. Reports hold labels and
counts only, never text from the dataset.
"""
