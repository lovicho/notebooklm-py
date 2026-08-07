# REST seam-matrix slice

The bounded REST composition check is
`tests/server/test_integration_real_client.py::TestRestSeamMatrix::test_url_add_crosses_rest_to_client_boundary`.

It drives `POST /v1/notebooks/{id}/sources/url` through the real FastAPI app,
the transport-neutral `_app.source_add` service, and a real
`NotebookLMClient`/RPC decoder before checking the REST `source_view`
projection. The test uses an existing VCR cassette so the composition path is
deterministic and offline. That replay proves the in-process adapter-to-client
contract; it is not a reality probe for the external NotebookLM service.

The other server tests continue to use `FakeClient` for fast route-level branch
coverage. This single real-client path is the bounded seam-matrix evidence for
the REST adapter and should be expanded only when a distinct boundary risk is
identified.
