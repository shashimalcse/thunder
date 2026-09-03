# <FEATURE> Specification

<Summary, Architecture, Detailed design, Requirements and acceptance criteria, and Change log are
required. Open questions and the subsections under Detailed design are conditional. Omit conditional
sections that do not apply. Remove all template instructions before the specification is accepted.>

## Summary

<Explain the problem, the proposed solution, its scope, and the governing design decision. Keep this
section concise and do not repeat the detailed requirements.>

## Architecture

<Describe the components, ownership boundaries, and existing seams used by the feature. Include a
Mermaid diagram only when it makes the relationships materially easier to understand. Mark new and
existing components clearly.>

### Main flow

<Conditional. Describe the representative operation that exercises most of the design.>

1. <DESCRIBE THE FIRST STEP.>
2. <CONTINUE THROUGH THE RESULT. REFERENCE DETAILED-DESIGN SUBSECTIONS INSTEAD OF REPEATING THEM.>

## Detailed design

<Use one subsection for each independent mechanism or responsibility. Describe its behavior, ownership,
validation, failure behavior, lifecycle, and rationale where relevant. Keep cross-cutting security analysis
in the separate threat model, but state security constraints that directly affect the mechanism.>

### <MECHANISM OR RESPONSIBILITY>

<DESCRIBE THE MECHANISM AND HOW IT USES OR CHANGES EXISTING COMPONENTS.>

### Data model

<Conditional. Describe durable and ephemeral state, ownership, lifecycle, cleanup, schema changes, and
indexes. State explicitly when an existing table is reused. Omit this subsection when the feature has no
data-model considerations.>

### API

<Conditional. Describe endpoints, request and response models, authorization, validation, and error
responses. Omit this subsection when the feature has no API changes.>

### UI

<Conditional. Describe the affected application, navigation, states, user actions, and error presentation.
Omit this subsection when the feature has no user-facing changes.>

### Configuration

<Conditional. List configuration keys, defaults, validation, and whether each setting is deployment-level
or organization-level. Omit this subsection when the feature has no configuration changes.>

## Requirements and acceptance criteria

<Every requirement and acceptance criterion below must be covered by the preceding design. Do not keep a
requirement that is deferred or partially covered. Move unsupported requirements to a future
specification. Use stable requirement and acceptance-criterion IDs.>

### R1. <REQUIREMENT TITLE>

**Requirement:** <CAPABILITY STATEMENT OR USER STORY.>

**Acceptance criteria:**

- **AC1.1:** Given <INITIAL STATE>, when <EVENT>, then <OBSERVABLE RESULT>.
- **AC1.2:** Given <INITIAL STATE>, when <EVENT>, then <OBSERVABLE RESULT>.

### R2. <REQUIREMENT TITLE>

**Requirement:** <CAPABILITY STATEMENT OR USER STORY.>

**Acceptance criteria:**

- **AC2.1:** Given <INITIAL STATE>, when <EVENT>, then <OBSERVABLE RESULT>.

## Change log

| Version | Date       | Change                 |
| ------- | ---------- | ---------------------- |
| 0.1     | YYYY-MM-DD | Initial specification. |
