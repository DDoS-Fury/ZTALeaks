# Task Management

## [x] Plan First: Fix 500 error on POST /api/v1/personnel
1. [x] Update `types.go`: add `omitempty` to `bson` tags for slices (`Qualifications`, `AssignedZones`, `RiskFlags`).
2. [x] Update `types.go`: add `validate:"required,startswith=BDG-"` to `BadgeID` in `Personnel`.
3. [x] Update `types.go`: add `validate:"required,employee_id"` to `EmployeeID` in `Personnel`.
4. [x] Update `validation.go`: register a custom validation function `employee_id` to test against the regex `^NP-\d{4}-\d{4}$`.
5. [x] Verify Plan with User.
6. [x] Implement the changes.
7. [x] Implement Tests: add tests for `EmployeeID` and `BadgeID` validation to ensure payload is checked correctly.
8. [x] Document Results in Walkthrough.
9. [x] Capture Lessons in `tasks/lessons.md`.
