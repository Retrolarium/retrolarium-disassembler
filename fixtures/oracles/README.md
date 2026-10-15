# Fixture oracles

Oracle files contain source-derived structural facts for open fixtures. They are
versioned test inputs for post-analysis scoring, not inputs to the blind
analyzer.

Every oracle must identify:

- the exact fixture and ROM SHA-256;
- the upstream commit and source/build evidence;
- the schemas for which its coverage is declared complete;
- physical ranges and expected decoded values.

Generated benchmark reports belong under an ignored `build/` directory. An
oracle must not be created for a holdout until its first blind result has been
recorded.
