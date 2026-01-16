"""Configuration for integration tests."""

import pytest


def pytest_configure(config):
    """Add integration marker."""
    config.addinivalue_line(
        "markers", "integration: mark test as requiring integration with real services"
    )


def pytest_collection_modifyitems(config, items):
    """Skip integration tests unless explicitly requested.

    Tests marked with 'ci_safe' are always run (even inside the integration
    directory) because they stub all external calls and are safe for CI.
    """
    if not config.getoption("--integration", default=False):
        # Skip integration tests by default, but honor ci_safe override
        skip_integration = pytest.mark.skip(reason="Need --integration option to run")
        for item in items:
            if "integration" in item.keywords and "ci_safe" not in item.keywords:
                item.add_marker(skip_integration)


def pytest_addoption(parser):
    """Add integration option to pytest."""
    parser.addoption(
        "--integration",
        action="store_true",
        default=False,
        help="run integration tests",
    )
