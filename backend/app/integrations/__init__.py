"""Outbound integration layer (Phase 10).

Every outbound notification (webhook, syslog/CEF, STIX 2.1 export, ticketing or
SIEM connector) goes through this package. The package is deliberately isolated
from the rest of the application:

* connectors are plain objects behind a small protocol, so tests inject fake
  transports and no test ever touches the network;
* the framework is **disabled by default**: with no configuration every connector
  is absent and the dispatcher reports an empty, honest health report;
* nothing here raises into a caller: delivery failures are recorded as data
  (``ConnectorResult``) and persisted in ``integration_deliveries``.
"""

# Importing the ORM model here registers ``integration_deliveries`` on
# ``app.db.base.Base.metadata`` for **every** code path that imports this package
# (the API, the test suite, a script). That is what makes
# ``Base.metadata.create_all`` create the table without touching
# ``app/db/models.py`` (owned by another change). ``alembic autogenerate`` only
# sees it when ``app.db.models`` (or ``alembic/env.py``) imports this package,
# which is why ``docs/integrations.md`` asks the coordinator to add one explicit
# import line to ``app/db/models.py``.
from app.integrations import models as models  # noqa: F401  (registers the table)
