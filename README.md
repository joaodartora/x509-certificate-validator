# X509 Certificate Validator

## Project Description

This project is a re-implementation / update of the project https://github.com/nandosola/trantor-certificate-verifier

The main focus was on refactoring the code applying clean code best practices, better layer separation
and a custom PKIXCertPathChecker, where it was possible to apply spec rules for validation of some kind
of certificate.

### Building and testing

Just run ```./gradlew clean build``` and ```./gradlew clean test``` to build and test the project.

