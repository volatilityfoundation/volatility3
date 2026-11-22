Agent coding guidelines for Volatility 3
========================================

Follow the CODING_STYLE.md guidelines and ensure that ruff passes both linting and formatting.

When making additions or changes to the code, try to ensure they are minimal and easily readable & reviewable by a human.

Be particularly cautious when making changes with regards to layers, automagic or other core components that are applied across all plugins.

Ensure that classes which can describe their `requirements` accurately reflect any direct versioned components they use.

When parsing data, try hard to make use of the volatility parsing code, rather than resorting to direct struct reads of data.  Using specific offsets rather than structure definitions makes the implicit assumption that the structures will never change in the future, whereas if the objects are parsed through volatility definitions, they can be updated/changed based on changes in the version of the code in the memory image.

This is a forensic tool and as such guesswork or heuristics that are not necessarily accurate are to be avoided in favour of accurately parsing data.  This also applies to logging (even if only in debug, so that only developers will see it) situations where parsing failed for an unexpected reason.

Versioning is important to ensure that all components within the Volatility ecosystem interact with each other correctly, therefore ensure any changes to the external API of a versioned component are bumped according to semver (so additive changes require a MINOR version bump, while backwards imcompatible changes or removals require a MAJOR version bump).  If the change requires the main volatility code version to be bumped, document it in API_CHANGES.md.

Constants or other specific data values that are likely useful in more than that one specific place, should be put in the `volatility.constants` package so that others can make use of it.
