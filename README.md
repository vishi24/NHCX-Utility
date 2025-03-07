# NHCX Encryption-Decryption Utility

## Overview

This repository provides a ready-to-use Java Spring Boot utility to help integrators fast-track their integration with NHCX. It enables secure encryption and decryption of request payloads for seamless data exchange between participants.

## Features

- Pre-built utility for encryption and decryption of NHCX request payloads.
- Configurable and ready to use with minimal setup.
- Exposes two REST endpoints:
  - **Encrypt API**: Encrypts request payloads before sending.
  - **Decrypt API**: Decrypts received encrypted data.
- Can be run locally or deployed as a microservice in production environments.

## Prerequisites

- Java 17 or later
- Maven
- Spring Boot Framework

## API Endpoints

### 1. Encrypt API

**Endpoint:** `POST /api/encrypt`

**Request Body:**

```json
{
    "resourceType": "CoverageEligibilityRequest",  
    "sender": "1000003548@hcx",  
    "receiver": "1000003538@hcx"  
}
```

### 2. Decrypt API

**Endpoint:** `POST /api/decrypt`

**Request Body:**

```json
{
    "encryptedText": "<Encrypted String>"
}
```

## Configuration

To run this utility, update the configuration files as follows:

1. \*\*Modify \*\***`application.properties`** to set required environment variables.
2. **Update FHIR bundle files** in the repository as per your integration needs.
3. **Add your private key** in the `resources` folder for decryption.

## Running the Application

1. Clone this repository:
   ```sh
   git clone <repository-url>
   ```
2. Navigate to the project directory:
   ```sh
   cd nhcx-encryption-utility
   ```
3. Build the project using Maven:
   ```sh
   mvn clean install
   ```
4. Run the application:
   ```sh
   mvn spring-boot:run
   ```

## Deployment

This utility can be deployed as a standalone service or integrated into an existing microservices architecture.

## Contribution

Feel free to contribute to this repository by raising issues or submitting pull requests.

## License

This project is licensed under the MIT License.

## Contact

For any queries or support, please raise an issue on the repository.

