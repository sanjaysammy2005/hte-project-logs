# TraceLock — Project Instructions

## Project Overview

Project name: TraceLock

Full title: Context-Enriched Tamper-Evident Audit Logging with Provenance Verification

Build a complete, working research prototype that implements and evaluates a secure audit logging pipeline based on the research paper in `docs/research-paper.pdf`.

The paper is the primary reference for the proposed methodology. Read it before designing or implementing the system.

## Working Rules

1. Work in small, testable phases.
2. Do not implement the entire application in one step.
3. Explain the purpose of each major file and component in simple language.
4. Before making major architectural decisions, explain the options and recommend one.
5. Do not silently change the research methodology.
6. Distinguish requirements derived from the paper from implementation recommendations.
7. Do not fabricate experiment results, citations, performance numbers, or security guarantees.
8. Do not delete existing files or run destructive commands without asking first.
9. Do not expose passwords, API keys, or secrets in code or logs.
10. Prefer readable, maintainable code over unnecessary complexity.
11. Write tests for each important security feature before moving to the next phase.
12. Keep a record of completed work, test results, known problems, and remaining tasks.

## Technology Stack

Backend: Python and FastAPI.

Database: PostgreSQL.

Database access: SQLAlchemy and Alembic.

Validation: Pydantic.

Hashing: Python hashlib with SHA-256.

Testing: pytest and HTTPX.

Frontend: React, Vite, and TypeScript.

Visualization: Plotly.

Environment: Docker and Docker Compose.

Version control: Git.

Use additional libraries only when needed and explain why they are necessary.

## Main Processing Pipeline

1. Capture a security audit event.
2. Validate and enrich the event with contextual information.
3. Canonically serialize the event and its context.
4. Compute its SHA-256 hash using the previous event hash.
5. Store the event, context, sequence number, timestamp, and hashes.
6. Group events into batches.
7. Compute a Merkle root for each batch.
8. Verify event integrity, ordering, provenance, and batch integrity.
9. Detect and report tampering.
10. Present verification results and evaluation metrics in the dashboard.

Follow the research paper's precise definitions wherever provided. Do not assume that all contextual fields or formulas can be chosen arbitrarily.

## Core Data Requirements

Represent the relevant information required by the paper, including:

* User or actor identity
* Session identity
* Current event
* Previous event or event relationship
* Sequence number
* Timestamp
* Context information
* Previous hash
* Current hash
* Batch identifier
* Merkle root and relevant verification metadata

Review the paper before finalizing the schema. Document any additional fields needed by the implementation.

## Hash Chain

Use SHA-256 and deterministic canonical serialization.

The conceptual recurrence is:

H_n = SHA-256(serialize(E_n, C_n, H_(n-1)))

where E_n is the event, C_n is its context, and H_(n-1) is the preceding hash.

Treat this as a conceptual formula until the exact serialization and concatenation rules have been verified against the paper.

Define a documented genesis value for the first record.

Create tests for valid chains, modified events, modified context, deleted records, inserted records, and reordered records.

## Provenance Verification

Implement the provenance checks described in the paper.

Check relevant relationships among users, sessions, event sequences, timestamps, and preceding events where supported by the methodology.

Return a clear verification report explaining which checks passed, which failed, and which records were affected.

Do not invent provenance rules without documenting them.

## Merkle Batch Integrity

Implement Merkle-tree batch integrity as described in the paper.

Document leaf construction, parent hashing, odd-sized batch handling, root storage, and membership-proof verification.

Test single-event batches, even-sized batches, odd-sized batches, and altered leaves.

## Tampering Demonstration

Build a controlled laboratory that demonstrates:

* Event modification
* Context modification
* Event deletion
* Event insertion
* Event reordering

Use isolated test data and explicit authorization. Do not modify unrelated user files or production systems.

Show the expected result and the actual verification result for every scenario.

## Dashboard

Provide a clear interface for:

* Viewing audit events
* Viewing event context and hash relationships
* Checking chain integrity
* Checking provenance
* Checking Merkle batch integrity
* Running controlled tampering scenarios
* Viewing detection results
* Viewing experiment metrics

Clearly distinguish genuine test results from sample or demonstration data.

## Experimental Evaluation

Measure relevant metrics such as:

* Tampering detection rate
* False-positive rate
* Correct identification of the first affected record
* Verification time
* Storage overhead

Define the formulas, dataset sizes, test conditions, and measurement procedures before reporting results.

Never invent or hardcode performance results to make the system appear successful.

## Security Limitations

Describe the system as tamper-evident, not absolutely tamper-proof.

Discuss the risk of an attacker rewriting local records and integrity metadata together, events altered before capture, compromised verification credentials, and other limitations identified in the paper.

Do not claim that hashing alone prevents modification.

Clearly document which protections are actually implemented and tested.

## Required Documentation

Maintain these files:

* docs/PROJECT_PLAN.md
* docs/ARCHITECTURE.md
* docs/DATABASE.md
* docs/API_SPEC.md
* docs/VERIFICATION.md
* docs/EXPERIMENTS.md
* docs/SECURITY_LIMITATIONS.md
* docs/TESTING.md

## Development Workflow

At the beginning of each phase:

1. Explain the objective.
2. Identify the files to create or modify.
3. Explain the implementation approach.
4. Identify the security and testing requirements.
5. Implement only the approved phase.
6. Run relevant tests.
7. Summarize changed files and test results.
8. List unresolved issues.
9. Wait for approval before starting the next major phase.

Keep the project understandable to a final-year computer science student who must demonstrate and defend the implementation during a research presentation.
