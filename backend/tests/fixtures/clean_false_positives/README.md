# Clean false-positive fixture (H11)

Previously used `requests==2.32.3`, which OSV now flags as affected.
This fixture tracks pinned versions intended to produce **zero**
`likely_affected` matches for the seeded offline catalog used in unit tests.
